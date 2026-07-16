import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import * as os from 'node:os';
import * as path from 'node:path';
import { promises as fs } from 'node:fs';
import * as crypto from 'node:crypto';
import { Repeater } from '../../src/engine/repeater/repeater.js';
import { CookieJar } from '../../src/engine/repeater/cookieJar.js';
import {
  parseRawRequest,
  serializeRawRequest,
  toRawRequest,
} from '../../src/engine/repeater/rawHttp.js';
import { BlobStore } from '../../src/engine/storage/blobStore.js';
import { DEFAULT_LIMITS } from '../../src/engine/config.js';
import { emptyScope } from '../../src/shared/scope.js';
import { readBodyBytes } from '../../src/engine/storage/bodyCollector.js';
import { getHeader } from '../../src/shared/model.js';
import { startTestServer, type TestServerHandle } from '../server/testServer.js';
import type { RepeaterOptions } from '../../src/shared/repeater.js';

let server: TestServerHandle;
let repeater: Repeater;
let blobs: BlobStore;
let dir: string;

const OPTS: RepeaterOptions = {
  followRedirects: false,
  maxRedirects: 5,
  timeoutMs: 10000,
  useCookieJar: false,
};

beforeAll(async () => {
  server = await startTestServer();
  dir = path.join(os.tmpdir(), `belcher-rep-${crypto.randomBytes(6).toString('hex')}`);
  blobs = new BlobStore(path.join(dir, 'blobs'));
  repeater = new Repeater({
    blobStore: blobs,
    limits: DEFAULT_LIMITS,
    getScope: () => emptyScope(),
  });
});

afterAll(async () => {
  await server.close();
  await fs.rm(dir, { recursive: true, force: true });
});

describe('rawHttp parse/serialize', () => {
  it('round-trips a raw request preserving headers and body', () => {
    const raw = 'POST /x HTTP/1.1\r\nHost: h\r\nX-A: 1\r\nX-A: 2\r\n\r\nbody-data';
    const parsed = parseRawRequest(raw);
    expect(parsed.method).toBe('POST');
    expect(parsed.headers.filter((h) => h.name === 'X-A')).toHaveLength(2);
    expect(parsed.body).toBe('body-data');
    expect(serializeRawRequest(parsed)).toBe(raw);
  });

  it('rejects a malformed request line', () => {
    expect(() => parseRawRequest('not a request\r\n\r\n')).toThrow();
  });
});

describe('repeater fidelity', () => {
  it('sends a GET and captures response + timing', async () => {
    const raw = toRawRequest('GET', '/json', [
      { name: 'Host', value: `127.0.0.1:${server.httpPort}` },
    ]);
    const result = await repeater.send(
      { scheme: 'http', host: '127.0.0.1', port: server.httpPort, raw },
      OPTS,
    );
    expect(result.exchange.response?.statusCode).toBe(200);
    expect(result.exchange.source).toBe('repeater');
    expect(result.exchange.timing?.durationMs).toBeGreaterThanOrEqual(0);
    const body = await readBodyBytes(result.exchange.response!.body, blobs);
    expect(JSON.parse(body.toString()).ok).toBe(true);
  });

  it('resends a captured request faithfully (POST body preserved)', async () => {
    const raw = toRawRequest(
      'POST',
      '/echo-body',
      [
        { name: 'Host', value: `127.0.0.1:${server.httpPort}` },
        { name: 'Content-Type', value: 'text/plain' },
      ],
      'repeater-payload-123',
    );
    const result = await repeater.send(
      { scheme: 'http', host: '127.0.0.1', port: server.httpPort, raw },
      OPTS,
    );
    const body = await readBodyBytes(result.exchange.response!.body, blobs);
    expect(body.toString()).toBe('repeater-payload-123');
    expect(result.exchange.request.body.size).toBe('repeater-payload-123'.length);
  });

  it('follows redirects when enabled and records the hop', async () => {
    const raw = toRawRequest('GET', '/redirect', [
      { name: 'Host', value: `127.0.0.1:${server.httpPort}` },
    ]);
    const result = await repeater.send(
      { scheme: 'http', host: '127.0.0.1', port: server.httpPort, raw },
      { ...OPTS, followRedirects: true },
    );
    expect(result.redirects).toHaveLength(1);
    expect(result.redirects[0]?.status).toBe(302);
    expect(result.exchange.response?.statusCode).toBe(200);
  });

  it('applies and collects cookies through the jar', async () => {
    const jar = new CookieJar();
    const setRaw = toRawRequest('GET', '/set-cookie', [
      { name: 'Host', value: `127.0.0.1:${server.httpPort}` },
    ]);
    await repeater.send(
      { scheme: 'http', host: '127.0.0.1', port: server.httpPort, raw: setRaw },
      { ...OPTS, useCookieJar: true },
      jar,
    );
    expect(jar.cookieHeader('127.0.0.1')).toContain('sid=SECRETVALUE');

    const echoRaw = toRawRequest('GET', '/', [
      { name: 'Host', value: `127.0.0.1:${server.httpPort}` },
    ]);
    const result = await repeater.send(
      { scheme: 'http', host: '127.0.0.1', port: server.httpPort, raw: echoRaw },
      { ...OPTS, useCookieJar: true },
      jar,
    );
    // the outgoing request should now carry the Cookie header
    expect(getHeader(result.exchange.request.headers, 'cookie')).toContain('sid=SECRETVALUE');
  });

  it('captures TLS info for HTTPS repeater requests', async () => {
    const raw = toRawRequest('GET', '/json', [
      { name: 'Host', value: `localhost:${server.httpsPort}` },
    ]);
    const result = await repeater.send(
      { scheme: 'https', host: 'localhost', port: server.httpsPort, raw },
      OPTS,
    );
    expect(result.tls).toBeDefined();
    expect(result.tls?.protocol).toMatch(/TLS/);
    expect(result.exchange.scheme).toBe('https');
  });
});
