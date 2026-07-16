/**
 * Passive scanner runner. Materializes body text once per exchange, runs every
 * registered check under a guard (a faulty check cannot crash the scan), and
 * returns fully-formed, evidence-redacted Findings.
 */

import * as zlib from 'node:zlib';
import * as crypto from 'node:crypto';
import { getHeader, mimeType, type HttpExchange, type MessageBody } from '../../shared/model.js';
import type { Finding } from '../../shared/findings.js';
import { Redactor } from '../redaction/redactor.js';
import type { RedactionConfig } from '../../shared/config.js';
import { BlobStore } from '../storage/blobStore.js';
import { readBodyBytes } from '../storage/bodyCollector.js';
import { Logger, rootLogger } from '../logging/logger.js';
import type { ScannerCheck, ScanContext } from './types.js';
import { BUILTIN_CHECKS } from './checks.js';

const MAX_SCAN_BODY_BYTES = 1024 * 1024; // decode at most 1 MiB of body for scanning

const TEXTUAL_HINT = /(text\/|json|xml|javascript|x-www-form-urlencoded|html)/i;

export class PassiveScanner {
  private readonly checks: ScannerCheck[];
  private readonly redactor: Redactor;
  private readonly log: Logger;

  /**
   * @param extensionRunner optional async runner (backed by the isolated
   *   extension worker). It receives the materialized bodies and returns extra
   *   findings, which are merged with the built-in results.
   */
  constructor(
    private readonly blobStore: BlobStore,
    redaction: RedactionConfig,
    extraChecks: ScannerCheck[] = [],
    logger: Logger = rootLogger,
    private readonly extensionRunner?: (payload: {
      exchange: HttpExchange;
      requestBodyText: string;
      responseBodyText: string;
    }) => Promise<Finding[]>,
  ) {
    this.checks = [...BUILTIN_CHECKS, ...extraChecks];
    this.redactor = new Redactor(redaction);
    this.log = logger.child('scanner');
  }

  /** Register an additional in-process check (built-in composition/tests only). */
  registerCheck(check: ScannerCheck): void {
    this.checks.push(check);
  }

  listModules(): { module: string; version: string }[] {
    return this.checks.map((c) => ({ module: c.module, version: c.version }));
  }

  async scan(exchange: HttpExchange): Promise<Finding[]> {
    const requestBodyText = await this.bodyText(exchange.request.body, undefined);
    const responseBodyText = exchange.response
      ? await this.bodyText(
          exchange.response.body,
          exchange.response ? mimeType(exchange.response.headers) : undefined,
        )
      : '';

    const ctx: ScanContext = {
      exchange,
      requestBodyText,
      responseBodyText,
      redactor: this.redactor,
    };

    const findings: Finding[] = [];
    for (const check of this.checks) {
      try {
        if (check.appliesTo && !check.appliesTo(exchange)) continue;
        for (const raw of check.run(ctx)) {
          findings.push({
            id: crypto.randomUUID(),
            exchangeId: exchange.id,
            dedupeKey: `${check.module}|${raw.dedupeKey}`,
            title: raw.title,
            severity: raw.severity,
            confidence: raw.confidence,
            module: check.module,
            moduleVersion: check.version,
            description: raw.description,
            remediation: raw.remediation,
            // Defense-in-depth: re-redact every evidence excerpt.
            evidence: raw.evidence.map((e) => ({
              ...e,
              excerpt: this.redactor.redactText(e.excerpt),
            })),
            createdAt: Date.now(),
            suppressed: false,
          });
        }
      } catch (err) {
        this.log.warn('check failed', { module: check.module, err: String(err) });
      }
    }

    if (this.extensionRunner) {
      try {
        findings.push(
          ...(await this.extensionRunner({ exchange, requestBodyText, responseBodyText })),
        );
      } catch (err) {
        this.log.warn('extension checks failed', { err: String(err) });
      }
    }
    return findings;
  }

  private async bodyText(body: MessageBody, mt: string | undefined): Promise<string> {
    if (body.size === 0) return '';
    if (body.size > MAX_SCAN_BODY_BYTES && body.contentEncoding !== 'gzip') {
      // For very large uncompressed bodies, scan only the head.
    }
    let bytes: Buffer;
    try {
      bytes = await readBodyBytes(body, this.blobStore);
    } catch {
      return '';
    }
    if (body.contentEncoding === 'gzip') {
      try {
        bytes = zlib.gunzipSync(bytes);
      } catch {
        return '';
      }
    }
    if (bytes.length > MAX_SCAN_BODY_BYTES) bytes = bytes.subarray(0, MAX_SCAN_BODY_BYTES);
    // Only treat as text when the MIME hints textual, or when there is no MIME.
    if (mt && !TEXTUAL_HINT.test(mt)) {
      // still allow small bodies to be scanned as text
      if (bytes.length > 4096) return '';
    }
    return bytes.toString('utf8');
  }
}

/** Convenience for callers that just have headers and want the response MIME. */
export function responseMime(exchange: HttpExchange): string | undefined {
  return exchange.response ? getHeader(exchange.response.headers, 'content-type') : undefined;
}
