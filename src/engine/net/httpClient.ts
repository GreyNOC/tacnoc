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
  bodyTruncated: boolean;
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
  maxResponseBytes = 10 * 1024 * 1024,
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

    let settled = false;
    // Wall-clock deadline. Before the response starts, this fails the request;
    // once bytes are streaming it keeps the partial body and marks it truncated
    // (consistent with the response size cap) instead of discarding the capture.
    let onDeadline = (): void => {
      req.destroy(new Error('request deadline exceeded'));
    };
    const hardTimer = setTimeout(() => onDeadline(), timeoutMs);
    const cleanup = (): void => {
      clearTimeout(hardTimer);
      signal?.removeEventListener('abort', onAbort);
    };
    const fail = (err: Error): void => {
      if (settled) return;
      settled = true;
      cleanup();
      reject(err);
    };
    const onAbort = (): void => {
      req.destroy(new AbortError());
    };

    // Attach the request-level handlers BEFORE any code path that can destroy
    // the request. req.destroy(err) emits an 'error' event; if no 'error'
    // listener is attached yet — e.g. the already-aborted branch below, or a
    // synchronous connect failure — Node turns it into an uncaughtException,
    // which (there being no process-level handler) crashes the Electron main
    // process rather than rejecting this promise.
    req.on('timeout', () => req.destroy(new Error('request timeout')));
    req.on('error', fail);

    if (signal) {
      if (signal.aborted) {
        req.destroy(new AbortError());
        return fail(new AbortError());
      }
      signal.addEventListener('abort', onAbort, { once: true });
    }

    req.on('response', (res) => {
      const ttfbMs = Date.now() - started;
      const chunks: Buffer[] = [];
      let capturedBytes = 0;
      let bodyTruncated = false;
      const finish = (): void => {
        if (settled) return;
        settled = true;
        cleanup();
        resolve({
          statusCode: res.statusCode ?? 0,
          statusMessage: res.statusMessage ?? '',
          httpVersion: `HTTP/${res.httpVersion}`,
          headers: fromRawHeaders(res.rawHeaders),
          body: Buffer.concat(chunks, capturedBytes),
          bodyTruncated,
          ttfbMs,
          durationMs: Date.now() - started,
          ...(tlsAuthorized !== undefined ? { tlsAuthorized } : {}),
        });
      };
      // Once the response is streaming, the deadline keeps the partial capture.
      onDeadline = (): void => {
        if (settled) return;
        bodyTruncated = true;
        finish();
        res.destroy();
      };
      res.on('data', (value) => {
        const chunk = value as Buffer;
        const remaining = maxResponseBytes - capturedBytes;
        if (remaining > 0) {
          const kept = chunk.length > remaining ? chunk.subarray(0, remaining) : chunk;
          chunks.push(kept);
          capturedBytes += kept.length;
        }
        if (chunk.length > remaining) {
          bodyTruncated = true;
          finish();
          res.destroy();
        }
      });
      res.on('end', finish);
      res.on('aborted', () => {
        if (!bodyTruncated) fail(new Error('response aborted before completion'));
      });
      res.on('error', fail);
    });

    if (body.length) req.write(body);
    req.end();
  });
}
