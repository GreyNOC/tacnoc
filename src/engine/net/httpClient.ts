/**
 * Low-level raw HTTP/1.1 sender used by automated tooling (variation engine).
 * Sends a fully-specified request and returns the response with timing.
 * Origin TLS validation is relaxed (research tool) but recorded via `authorized`.
 */

import * as http from 'node:http';
import * as https from 'node:https';
import * as tls from 'node:tls';
import { fromRawHeaders, type HttpHeader, type Scheme } from '../../shared/model.js';
import { buildOutboundHeaders } from '../proxy/proxyUtil.js';
import { AbortError } from '../util/rateLimit.js';

/** https.request options extended with ALPN (present at runtime, not in base types). */
type HttpsReqOptions = https.RequestOptions & { ALPNProtocols?: string[] };

export interface RawSendResult {
  statusCode: number;
  statusMessage: string;
  httpVersion: string;
  headers: HttpHeader[];
  body: Buffer;
  ttfbMs: number;
  durationMs: number;
  tlsAuthorized?: boolean;
}

export function sendRaw(
  scheme: Scheme,
  host: string,
  port: number,
  method: string,
  path: string,
  headers: HttpHeader[],
  body: Buffer,
  timeoutMs: number,
  signal?: AbortSignal,
): Promise<RawSendResult> {
  const started = Date.now();
  const options: http.RequestOptions = {
    host,
    port,
    method,
    path,
    headers: buildOutboundHeaders(headers),
    timeout: timeoutMs,
  };

  return new Promise<RawSendResult>((resolve, reject) => {
    const req =
      scheme === 'https'
        ? https.request({
            ...options,
            servername: host,
            rejectUnauthorized: false,
            ALPNProtocols: ['http/1.1'],
          } as HttpsReqOptions)
        : http.request(options);

    let tlsAuthorized: boolean | undefined;
    if (scheme === 'https') {
      req.on('socket', (socket) => {
        (socket as tls.TLSSocket).on('secureConnect', () => {
          tlsAuthorized = (socket as tls.TLSSocket).authorized;
        });
      });
    }

    const onAbort = (): void => {
      req.destroy(new AbortError());
    };
    if (signal) {
      if (signal.aborted) {
        req.destroy(new AbortError());
        return reject(new AbortError());
      }
      signal.addEventListener('abort', onAbort, { once: true });
    }

    req.on('timeout', () => req.destroy(new Error('request timeout')));
    req.on('error', (err) => {
      signal?.removeEventListener('abort', onAbort);
      reject(err);
    });
    req.on('response', (res) => {
      const ttfbMs = Date.now() - started;
      const chunks: Buffer[] = [];
      res.on('data', (c) => chunks.push(c as Buffer));
      res.on('end', () => {
        signal?.removeEventListener('abort', onAbort);
        resolve({
          statusCode: res.statusCode ?? 0,
          statusMessage: res.statusMessage ?? '',
          httpVersion: `HTTP/${res.httpVersion}`,
          headers: fromRawHeaders(res.rawHeaders),
          body: Buffer.concat(chunks),
          ttfbMs,
          durationMs: Date.now() - started,
          ...(tlsAuthorized !== undefined ? { tlsAuthorized } : {}),
        });
      });
    });

    if (body.length) req.write(body);
    req.end();
  });
}
