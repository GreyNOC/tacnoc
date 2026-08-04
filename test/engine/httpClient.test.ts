/**
 * Regression tests for sendRaw's response bounds (added in the v0.3.0 QAQC pass):
 * the wall-clock deadline preserves the partial body (truncated) rather than
 * discarding it, and the response cap bounds the captured bytes.
 */
import { describe, it, expect, afterEach } from 'vitest';
import * as http from 'node:http';
import type { Server } from 'node:http';
import { sendRaw } from '../../src/engine/net/httpClient.js';

let server: Server | undefined;

afterEach(async () => {
  if (server) {
    const s = server;
    server = undefined;
    await new Promise<void>((resolve) => s.close(() => resolve()));
  }
});

async function listen(handler: http.RequestListener): Promise<number> {
  server = http.createServer(handler);
  await new Promise<void>((resolve) => server!.listen(0, '127.0.0.1', () => resolve()));
  const addr = server.address();
  if (!addr || typeof addr === 'string') throw new Error('no port');
  return addr.port;
}

const host = (port: number) => [{ name: 'Host', value: `127.0.0.1:${port}` }];

describe('sendRaw response bounds', () => {
  it('keeps the partial body (truncated) when the wall-clock deadline fires mid-stream', async () => {
    const port = await listen((_req, res) => {
      res.writeHead(200, { 'content-type': 'text/plain' });
      res.write('chunk-0;');
      // Stream steadily (< the timeout) so the inactivity timeout never fires;
      // only the wall-clock deadline should stop the capture.
      const timer = setInterval(() => {
        if (!res.writableEnded) res.write('chunk;');
      }, 40);
      const stop = (): void => clearInterval(timer);
      res.on('close', stop);
      res.on('error', stop);
    });

    const result = await sendRaw(
      'http',
      '127.0.0.1',
      port,
      'GET',
      '/',
      host(port),
      Buffer.alloc(0),
      300,
    );
    expect(result.bodyTruncated).toBe(true);
    expect(result.body.length).toBeGreaterThan(0);
    expect(result.body.toString('utf8').startsWith('chunk-0;')).toBe(true);
  });

  it('caps the captured response at maxResponseBytes and marks it truncated', async () => {
    const port = await listen((_req, res) => {
      res.writeHead(200);
      res.end(Buffer.alloc(5000, 0x61));
    });

    const result = await sendRaw(
      'http',
      '127.0.0.1',
      port,
      'GET',
      '/',
      host(port),
      Buffer.alloc(0),
      5000,
      undefined,
      1000,
    );
    expect(result.body.length).toBe(1000);
    expect(result.bodyTruncated).toBe(true);
  });

  it('rejects with AbortError and raises no uncaught exception when the signal is already aborted', async () => {
    // Regression: the aborted branch called req.destroy(err) before any 'error'
    // listener was attached, so Node re-emitted 'error' with no handler -> an
    // uncaughtException that crashes the Electron main process (reachable by
    // clicking Stop while a variation task is queued on a saturated semaphore).
    const port = await listen((_req, res) => res.end('ok'));
    const ac = new AbortController();
    ac.abort();
    const uncaught: unknown[] = [];
    const record = (err: unknown): void => {
      uncaught.push(err);
    };
    process.on('uncaughtException', record);
    process.on('unhandledRejection', record);
    try {
      await expect(
        sendRaw(
          'http',
          '127.0.0.1',
          port,
          'GET',
          '/',
          host(port),
          Buffer.alloc(0),
          2000,
          ac.signal,
        ),
      ).rejects.toThrow(/abort/i);
      // Let any asynchronously-emitted 'error' from req.destroy() surface.
      await new Promise((resolve) => setTimeout(resolve, 50));
    } finally {
      process.off('uncaughtException', record);
      process.off('unhandledRejection', record);
    }
    expect(uncaught).toEqual([]);
  });

  it('does not mark a fully-received response as truncated', async () => {
    const port = await listen((_req, res) => {
      res.writeHead(200);
      res.end('complete');
    });
    const result = await sendRaw(
      'http',
      '127.0.0.1',
      port,
      'GET',
      '/',
      host(port),
      Buffer.alloc(0),
      2000,
    );
    expect(result.bodyTruncated).toBe(false);
    expect(result.body.toString('utf8')).toBe('complete');
  });
});
