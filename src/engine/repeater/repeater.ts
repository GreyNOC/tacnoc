/**
 * Repeater — manual request editor backend. Sends a (optionally
 * redirect-following) request directly to the origin, measuring timing and
 * size and capturing TLS/connection info. Produces an HttpExchange tagged
 * source="repeater".
 *
 * A send is operator-initiated, so it is not scope-gated; the resulting
 * exchange still records its in-scope status.
 *
 * It is NOT, however, single-shot, and the previous version of this comment
 * claiming otherwise was the reason this path went unthrottled. With
 * `followRedirects` on, one send emits up to `maxRedirects + 1` requests, and
 * every destination after the first is chosen by the REMOTE HOST. A redirect
 * chain is therefore attacker-influenced request generation originating from
 * this process, and it is rate-limited accordingly:
 *
 *   - Every hop, including the first, takes a token from a shared TokenBucket
 *     running at `limits.automation.requestsPerSecond`. The bucket lives on the
 *     Repeater, not on the call, so rapid successive sends are throttled too.
 *   - Every hop is abortable. `emergencyStopAll()` cancels queued hops AND
 *     destroys the in-flight socket, mirroring VariationEngine.emergencyStopAll().
 *
 * The abort path is not optional decoration: throttling without it would make
 * the emergency stop WORSE, because halted work would sit queued on tokens and
 * then fire after the operator believed everything had stopped.
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
import type { EngagementProfile } from '../../shared/engagement.js';
import { applyIdentity } from '../engagement/identity.js';
import { evaluateScope } from '../scope/scope.js';
import { BlobStore } from '../storage/blobStore.js';
import { bytesToBody } from '../storage/bodyCollector.js';
import { buildOutboundHeaders, originForm } from '../proxy/proxyUtil.js';
import { parseRawRequest } from './rawHttp.js';
import { CookieJar } from './cookieJar.js';
import { TokenBucket, AbortError } from '../util/rateLimit.js';

export interface RepeaterDeps {
  blobStore: BlobStore;
  limits: EngineLimits;
  getScope: () => ScopeConfig;
  /**
   * Engagement profile, read per request so a profile change takes effect
   * immediately. When it mandates identification, the required User-Agent and
   * identity headers are applied to what actually goes on the wire.
   */
  getEngagement?: () => EngagementProfile | undefined;
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

  /**
   * Shared across sends so N rapid sends are throttled as a group, not each
   * allowed its own burst. Rebuilt when the configured rate changes, because
   * `deps.limits` is a live reference to the open project's config and an
   * operator lowering the rate must take effect without reopening the project.
   */
  private bucket: TokenBucket | undefined;
  private bucketRate = 0;

  /** Re-armed after each stop so the Repeater stays usable afterwards. */
  private controller = new AbortController();

  private limiter(): TokenBucket {
    const rate = this.deps.limits.automation.requestsPerSecond;
    if (!this.bucket || this.bucketRate !== rate) {
      this.bucket = new TokenBucket(rate);
      this.bucketRate = rate;
    }
    return this.bucket;
  }

  /**
   * Abort every queued and in-flight hop. Mirrors
   * VariationEngine.emergencyStopAll() so the session can halt this path too.
   * An in-flight send rejects with AbortError; the operator sees a stopped
   * request rather than a silent completion after the stop.
   */
  emergencyStopAll(): void {
    this.controller.abort();
    this.controller = new AbortController();
  }

  async send(
    target: { scheme: Scheme; host: string; port: number; raw: string },
    options: RepeaterOptions,
    jar?: CookieJar,
  ): Promise<RepeaterResult> {
    const started = Date.now();
    const parsed = parseRawRequest(target.raw);
    const redirects: RedirectHop[] = [];
    // Captured once: emergencyStopAll() swaps in a fresh controller, and this
    // send must keep observing the signal it started under.
    const signal = this.controller.signal;

    let scheme = target.scheme;
    let host = target.host;
    let port = target.port;
    let method = parsed.method;
    let path = originForm(parsed.target);
    let headers = [...parsed.headers];
    let sentHeaders = headers;
    let body = Buffer.from(parsed.body, 'utf8');
    const firstExchangeId = crypto.randomUUID();
    let tls: TlsInfo | undefined;
    let hops = 0;

    // eslint-disable-next-line no-constant-condition
    while (true) {
      if (options.useCookieJar && jar) {
        // Reset the Cookie header from the jar for the CURRENT host each hop.
        // Stripping first ensures a redirect to a host with no jar cookies does
        // not carry the previous host's Cookie header (cross-host cookie leak).
        headers = dropHeaders(headers, ['cookie']);
        const cookie = jar.cookieHeader(host, scheme);
        if (cookie) headers = upsertHeader(headers, 'Cookie', cookie);
      }

      // Apply engagement identity to what actually goes on the wire, and record
      // exactly that in history — a compliance check against captured traffic is
      // only meaningful if history shows the bytes the target received.
      const outgoing = applyIdentity(headers, this.deps.getEngagement?.());
      sentHeaders = outgoing;

      // Throttle EVERY hop, first included. Placed before the send rather than
      // after it so the very first request of a burst is also paced, and inside
      // the redirect loop so a server-controlled chain cannot outrun the limit.
      await this.limiter().take(signal);

      const single = await this.sendOnce(
        scheme,
        host,
        port,
        method,
        path,
        outgoing,
        body,
        options.timeoutMs,
        signal,
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
        const crossHost = next.hostname.toLowerCase() !== host.toLowerCase();
        scheme = next.protocol.replace(':', '') as Scheme;
        host = next.hostname;
        port = next.port ? Number(next.port) : scheme === 'https' ? 443 : 80;
        path = next.pathname + next.search;

        // On a cross-host redirect, drop credential-bearing headers scoped to the
        // previous host so a manually-supplied Cookie/Authorization is not leaked
        // to an unrelated (possibly attacker-controlled) redirect target. The jar
        // path re-applies the correct per-host Cookie at the top of the loop.
        if (crossHost) {
          headers = dropHeaders(headers, ['cookie', 'authorization']);
        }

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
          headers: sentHeaders,
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
    signal?: AbortSignal,
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
      if (signal?.aborted) return reject(new AbortError());

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

      // Destroy the socket on abort so an emergency stop halts a request that
      // is already on the wire, not merely the ones still queued behind it.
      const onAbort = (): void => {
        req.destroy(new AbortError());
      };
      signal?.addEventListener('abort', onAbort, { once: true });
      const cleanup = (): void => signal?.removeEventListener('abort', onAbort);

      req.on('timeout', () => req.destroy(new Error('request timeout')));
      req.on('error', (err) => {
        cleanup();
        reject(err);
      });
      req.on('response', (res) => {
        const ttfbMs = Date.now() - started;
        const chunks: Buffer[] = [];
        res.on('data', (c) => chunks.push(c as Buffer));
        res.on('end', () => {
          cleanup();
          resolve({
            statusCode: res.statusCode ?? 0,
            statusMessage: res.statusMessage ?? '',
            httpVersion: `HTTP/${res.httpVersion}`,
            headers: fromRawHeaders(res.rawHeaders),
            body: Buffer.concat(chunks),
            ttfbMs,
            ...(tlsInfo ? { tls: tlsInfo } : {}),
          });
        });
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
