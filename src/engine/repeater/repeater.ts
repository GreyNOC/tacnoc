/**
 * Repeater — manual request editor backend. Sends a single (optionally
 * redirect-following) request directly to the origin, measuring timing and
 * size and capturing TLS/connection info. Produces an HttpExchange tagged
 * source="repeater".
 *
 * This is a MANUAL, single-shot workflow (not automated generation), so it is
 * not scope-gated; the resulting exchange still records its in-scope status.
 */

import * as http from 'node:http';
import * as https from 'node:https';
import * as tls from 'node:tls';
import * as crypto from 'node:crypto';
import {
  fromRawHeaders,
  getHeaders,
  type CapturedResponse,
  type HttpExchange,
  type HttpHeader,
  type Scheme,
} from '../../shared/model.js';
import type { EngineLimits } from '../../shared/config.js';
import type { ScopeConfig } from '../../shared/scope.js';
import type {
  RepeaterOptions,
  RepeaterResult,
  RedirectHop,
  TlsInfo,
} from '../../shared/repeater.js';
import { evaluateScope } from '../scope/scope.js';
import { BlobStore } from '../storage/blobStore.js';
import { bytesToBody } from '../storage/bodyCollector.js';
import { buildOutboundHeaders, originForm } from '../proxy/proxyUtil.js';
import { parseRawRequest } from './rawHttp.js';
import { CookieJar } from './cookieJar.js';

export interface RepeaterDeps {
  blobStore: BlobStore;
  limits: EngineLimits;
  getScope: () => ScopeConfig;
}

interface SingleResponse {
  statusCode: number;
  statusMessage: string;
  httpVersion: string;
  headers: HttpHeader[];
  body: Buffer;
  ttfbMs: number;
  tls?: TlsInfo;
}

const REDIRECT_CODES = new Set([301, 302, 303, 307, 308]);

export class Repeater {
  constructor(private readonly deps: RepeaterDeps) {}

  async send(
    target: { scheme: Scheme; host: string; port: number; raw: string },
    options: RepeaterOptions,
    jar?: CookieJar,
  ): Promise<RepeaterResult> {
    const started = Date.now();
    const parsed = parseRawRequest(target.raw);
    const redirects: RedirectHop[] = [];

    let scheme = target.scheme;
    let host = target.host;
    let port = target.port;
    let method = parsed.method;
    let path = originForm(parsed.target);
    let headers = [...parsed.headers];
    let body = Buffer.from(parsed.body, 'utf8');
    const firstExchangeId = crypto.randomUUID();
    let tls: TlsInfo | undefined;
    let hops = 0;

    // eslint-disable-next-line no-constant-condition
    while (true) {
      if (options.useCookieJar && jar) {
        const cookie = jar.cookieHeader(host);
        if (cookie) headers = upsertHeader(headers, 'Cookie', cookie);
      }

      const single = await this.sendOnce(
        scheme,
        host,
        port,
        method,
        path,
        headers,
        body,
        options.timeoutMs,
      );
      if (single.tls) tls = single.tls;

      if (options.useCookieJar && jar) {
        jar.ingest(host, getHeaders(single.headers, 'set-cookie'));
      }

      const isRedirect = REDIRECT_CODES.has(single.statusCode);
      const location = single.headers.find((h) => h.name.toLowerCase() === 'location')?.value;

      if (options.followRedirects && isRedirect && location && hops < options.maxRedirects) {
        redirects.push({ url: `${scheme}://${host}:${port}${path}`, status: single.statusCode });
        const next = new URL(location, `${scheme}://${host}:${port}${path}`);
        scheme = next.protocol.replace(':', '') as Scheme;
        host = next.hostname;
        port = next.port ? Number(next.port) : scheme === 'https' ? 443 : 80;
        path = next.pathname + next.search;

        // Adjust method/body per redirect semantics.
        if (
          single.statusCode === 303 ||
          ((single.statusCode === 301 || single.statusCode === 302) &&
            method !== 'GET' &&
            method !== 'HEAD')
        ) {
          method = 'GET';
          body = Buffer.alloc(0);
          headers = dropHeaders(headers, ['content-length', 'content-type', 'transfer-encoding']);
        }
        headers = upsertHeader(
          headers,
          'Host',
          port === (scheme === 'https' ? 443 : 80) ? host : `${host}:${port}`,
        );
        hops += 1;
        continue;
      }

      const response: CapturedResponse = {
        statusCode: single.statusCode,
        statusMessage: single.statusMessage,
        httpVersion: single.httpVersion,
        headers: single.headers,
        body: await bytesToBody(single.body, this.deps.limits.body, this.deps.blobStore),
      };
      const inScope = evaluateScope(this.deps.getScope(), { scheme, host, port, path }).inScope;
      const exchange: HttpExchange = {
        id: firstExchangeId,
        createdAt: started,
        source: 'repeater',
        scheme,
        host,
        port,
        inScope,
        automated: false,
        request: {
          method,
          target: path,
          url: `${scheme}://${host}:${port}${path}`,
          httpVersion: parsed.httpVersion,
          headers,
          body: await bytesToBody(body, this.deps.limits.body, this.deps.blobStore),
        },
        response,
        tags: [],
        timing: { startedAt: started, ttfbMs: single.ttfbMs, durationMs: Date.now() - started },
      };

      return {
        exchange,
        redirects,
        ...(tls ? { tls } : {}),
        totalMs: Date.now() - started,
      };
    }
  }

  private sendOnce(
    scheme: Scheme,
    host: string,
    port: number,
    method: string,
    path: string,
    headers: HttpHeader[],
    body: Buffer,
    timeoutMs: number,
  ): Promise<SingleResponse> {
    const started = Date.now();
    const outHeaders = buildOutboundHeaders(headers);
    const options: http.RequestOptions = {
      host,
      port,
      method,
      path,
      headers: outHeaders,
      timeout: timeoutMs,
    };

    return new Promise<SingleResponse>((resolve, reject) => {
      const req =
        scheme === 'https'
          ? https.request({
              ...options,
              servername: host,
              rejectUnauthorized: false,
              ALPNProtocols: ['http/1.1'],
            } as https.RequestOptions & { ALPNProtocols?: string[] })
          : http.request(options);

      let tlsInfo: TlsInfo | undefined;
      req.on('socket', (socket) => {
        if (scheme === 'https') {
          const s = socket as tls.TLSSocket;
          s.on('secureConnect', () => {
            const cert = s.getPeerCertificate();
            const asStr = (v: string | string[] | undefined): string | undefined =>
              Array.isArray(v) ? v[0] : v;
            tlsInfo = {
              protocol: s.getProtocol(),
              cipherName: s.getCipher()?.name,
              authorized: s.authorized,
              ...(s.authorizationError ? { authorizationError: String(s.authorizationError) } : {}),
              ...(cert && cert.subject ? { subjectCN: asStr(cert.subject.CN) } : {}),
              ...(cert && cert.issuer ? { issuerCN: asStr(cert.issuer.CN) } : {}),
              ...(cert && cert.valid_from ? { validFrom: cert.valid_from } : {}),
              ...(cert && cert.valid_to ? { validTo: cert.valid_to } : {}),
              ...(cert && cert.fingerprint256 ? { fingerprint256: cert.fingerprint256 } : {}),
            };
          });
        }
      });

      req.on('timeout', () => req.destroy(new Error('request timeout')));
      req.on('error', reject);
      req.on('response', (res) => {
        const ttfbMs = Date.now() - started;
        const chunks: Buffer[] = [];
        res.on('data', (c) => chunks.push(c as Buffer));
        res.on('end', () =>
          resolve({
            statusCode: res.statusCode ?? 0,
            statusMessage: res.statusMessage ?? '',
            httpVersion: `HTTP/${res.httpVersion}`,
            headers: fromRawHeaders(res.rawHeaders),
            body: Buffer.concat(chunks),
            ttfbMs,
            ...(tlsInfo ? { tls: tlsInfo } : {}),
          }),
        );
      });

      if (body.length) req.write(body);
      req.end();
    });
  }
}

function upsertHeader(headers: HttpHeader[], name: string, value: string): HttpHeader[] {
  const lower = name.toLowerCase();
  const out = headers.filter((h) => h.name.toLowerCase() !== lower);
  out.push({ name, value });
  return out;
}

function dropHeaders(headers: HttpHeader[], names: string[]): HttpHeader[] {
  const set = new Set(names.map((n) => n.toLowerCase()));
  return headers.filter((h) => !set.has(h.name.toLowerCase()));
}
