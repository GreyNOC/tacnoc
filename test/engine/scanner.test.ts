import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import * as os from 'node:os';
import * as path from 'node:path';
import { promises as fs } from 'node:fs';
import * as crypto from 'node:crypto';
import { PassiveScanner } from '../../src/engine/scanner/passiveScanner.js';
import { BlobStore } from '../../src/engine/storage/blobStore.js';
import type { HttpExchange, HttpHeader } from '../../src/shared/model.js';

let blobs: BlobStore;
let scanner: PassiveScanner;
let dir: string;

beforeAll(async () => {
  dir = path.join(os.tmpdir(), `belcher-scan-${crypto.randomBytes(6).toString('hex')}`);
  blobs = new BlobStore(path.join(dir, 'blobs'));
  scanner = new PassiveScanner(blobs, {
    maskCookies: true,
    maskAuthorization: true,
    maskSecretPatterns: true,
  });
});

afterAll(async () => {
  await fs.rm(dir, { recursive: true, force: true });
});

function exchange(opts: {
  scheme?: 'http' | 'https';
  url?: string;
  reqHeaders?: HttpHeader[];
  status?: number;
  resHeaders?: HttpHeader[];
  bodyText?: string;
}): HttpExchange {
  const bodyBuf = Buffer.from(opts.bodyText ?? '');
  return {
    id: crypto.randomUUID(),
    createdAt: Date.now(),
    source: 'proxy',
    scheme: opts.scheme ?? 'https',
    host: 'app.example.test',
    port: opts.scheme === 'http' ? 80 : 443,
    inScope: true,
    automated: false,
    request: {
      method: 'GET',
      target: '/',
      url: opts.url ?? 'https://app.example.test/',
      httpVersion: 'HTTP/1.1',
      headers: opts.reqHeaders ?? [{ name: 'Host', value: 'app.example.test' }],
      body: { size: 0, truncated: false },
    },
    response: {
      statusCode: opts.status ?? 200,
      statusMessage: 'OK',
      httpVersion: 'HTTP/1.1',
      headers: opts.resHeaders ?? [{ name: 'Content-Type', value: 'text/html' }],
      body: bodyBuf.length
        ? { size: bodyBuf.length, truncated: false, inline: bodyBuf }
        : { size: 0, truncated: false },
    },
    tags: [],
  };
}

describe('passive scanner', () => {
  it('flags missing security headers on HTML responses', async () => {
    const findings = await scanner.scan(exchange({ bodyText: '<p>hi</p>' }));
    const modules = findings.map((f) => f.module);
    expect(modules).toContain('security-headers');
    expect(findings.some((f) => /Content-Security-Policy/i.test(f.title))).toBe(true);
    expect(findings.some((f) => /Strict-Transport-Security/i.test(f.title))).toBe(true);
  });

  it('does not flag when security headers are present', async () => {
    const findings = await scanner.scan(
      exchange({
        bodyText: '<p>ok</p>',
        resHeaders: [
          { name: 'Content-Type', value: 'text/html' },
          { name: 'Content-Security-Policy', value: "default-src 'self'" },
          { name: 'X-Content-Type-Options', value: 'nosniff' },
          { name: 'X-Frame-Options', value: 'DENY' },
          { name: 'Referrer-Policy', value: 'no-referrer' },
          { name: 'Strict-Transport-Security', value: 'max-age=63072000' },
        ],
      }),
    );
    expect(findings.filter((f) => f.module === 'security-headers')).toHaveLength(0);
  });

  it('flags insecure cookies and redacts the value', async () => {
    const findings = await scanner.scan(
      exchange({
        resHeaders: [
          { name: 'Content-Type', value: 'text/html' },
          { name: 'Set-Cookie', value: 'sid=SUPERSECRET; Path=/' },
        ],
      }),
    );
    const cookie = findings.find((f) => f.module === 'insecure-cookies');
    expect(cookie).toBeDefined();
    expect(cookie!.title).toMatch(/Secure|HttpOnly|SameSite/);
    expect(JSON.stringify(cookie!.evidence)).not.toContain('SUPERSECRET');
  });

  it('flags dangerous CORS (wildcard + credentials)', async () => {
    const findings = await scanner.scan(
      exchange({
        resHeaders: [
          { name: 'Content-Type', value: 'application/json' },
          { name: 'Access-Control-Allow-Origin', value: '*' },
          { name: 'Access-Control-Allow-Credentials', value: 'true' },
        ],
      }),
    );
    const cors = findings.find((f) => f.module === 'cors');
    expect(cors?.severity).toBe('high');
  });

  it('flags sensitive data in URLs', async () => {
    const findings = await scanner.scan(
      exchange({ url: 'https://app.example.test/cb?access_token=abcd1234&x=1' }),
    );
    expect(findings.some((f) => f.module === 'sensitive-in-url')).toBe(true);
  });

  it('flags secrets, banners, verbose errors, and cleartext creds', async () => {
    const secretFindings = await scanner.scan(
      exchange({
        bodyText: 'here is AKIAIOSFODNN7EXAMPLE leaked',
        resHeaders: [{ name: 'Content-Type', value: 'text/plain' }],
      }),
    );
    expect(secretFindings.some((f) => f.module === 'secrets-in-response')).toBe(true);

    const banner = await scanner.scan(
      exchange({
        resHeaders: [
          { name: 'Server', value: 'nginx/1.2.3' },
          { name: 'Content-Type', value: 'text/plain' },
        ],
      }),
    );
    expect(banner.some((f) => f.module === 'banner-disclosure')).toBe(true);

    const err = await scanner.scan(
      exchange({
        status: 500,
        bodyText: 'Exception in thread main NullReferenceException at X.y (a.js:1:2)',
        resHeaders: [{ name: 'Content-Type', value: 'text/plain' }],
      }),
    );
    expect(err.some((f) => f.module === 'verbose-errors')).toBe(true);

    const cleartext = await scanner.scan(
      exchange({
        scheme: 'http',
        url: 'http://app.example.test/',
        reqHeaders: [{ name: 'Authorization', value: 'Bearer x' }],
      }),
    );
    expect(cleartext.some((f) => f.module === 'cleartext-credentials')).toBe(true);
  });

  it('reports reflected input only as a tentative observation', async () => {
    const findings = await scanner.scan(
      exchange({
        url: 'https://app.example.test/s?q=needle12345',
        bodyText: '<html>You searched for: needle12345</html>',
      }),
    );
    const reflected = findings.find((f) => f.module === 'reflected-input');
    expect(reflected).toBeDefined();
    expect(reflected!.confidence).toBe('tentative');
    expect(reflected!.severity).toBe('info');
  });

  it('has a stable dedupeKey and provides module version + remediation', async () => {
    const findings = await scanner.scan(exchange({ bodyText: '<p>x</p>' }));
    for (const f of findings) {
      expect(f.dedupeKey).toBeTruthy();
      expect(f.moduleVersion).toMatch(/\d+\.\d+\.\d+/);
      expect(f.remediation.length).toBeGreaterThan(0);
    }
  });
});
