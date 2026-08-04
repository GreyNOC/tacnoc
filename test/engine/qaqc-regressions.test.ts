/**
 * Regression tests for the QAQC pass (adversarial audit findings).
 * Each test pins a specific fix so the bug cannot silently return.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import * as os from 'node:os';
import * as path from 'node:path';
import * as net from 'node:net';
import * as zlib from 'node:zlib';
import { promises as fs } from 'node:fs';
import * as crypto from 'node:crypto';

import { Redactor, REDACTION_MASK } from '../../src/engine/redaction/redactor.js';
import { htmlEncode, htmlDecode } from '../../src/engine/transforms/codec.js';
import { isInScope } from '../../src/engine/scope/scope.js';
import { CookieJar } from '../../src/engine/repeater/cookieJar.js';
import { Database } from '../../src/engine/storage/database.js';
import { HistoryRepo } from '../../src/engine/storage/historyRepo.js';
import { FindingsRepo } from '../../src/engine/storage/findingsRepo.js';
import { PassiveScanner } from '../../src/engine/scanner/passiveScanner.js';
import { BlobStore } from '../../src/engine/storage/blobStore.js';
import { ProjectStore } from '../../src/engine/project/projectStore.js';
import { TacnocSession } from '../../src/engine/session.js';
import { CertificateAuthority } from '../../src/engine/ca/certificateAuthority.js';
import { InMemorySecretStore, type SecretStore } from '../../src/engine/ca/secretStore.js';
import type { Finding } from '../../src/shared/findings.js';
import type { HttpExchange, HttpHeader, MessageBody } from '../../src/shared/model.js';
import type { ScopeConfig } from '../../src/shared/scope.js';

let dir: string;
let blobs: BlobStore;

beforeAll(async () => {
  dir = path.join(os.tmpdir(), `tacnoc-qaqc-${crypto.randomBytes(6).toString('hex')}`);
  blobs = new BlobStore(path.join(dir, 'blobs'));
});

afterAll(async () => {
  await fs.rm(dir, { recursive: true, force: true });
});

function exchange(opts: {
  scheme?: 'http' | 'https';
  reqHeaders?: HttpHeader[];
  resHeaders?: HttpHeader[];
  resBody?: MessageBody;
  host?: string;
}): HttpExchange {
  return {
    id: crypto.randomUUID(),
    createdAt: Date.now(),
    source: 'proxy',
    scheme: opts.scheme ?? 'https',
    host: opts.host ?? 'app.example.test',
    port: opts.scheme === 'http' ? 80 : 443,
    inScope: true,
    automated: false,
    request: {
      method: 'GET',
      target: '/',
      url: `${opts.scheme ?? 'https'}://${opts.host ?? 'app.example.test'}/`,
      httpVersion: 'HTTP/1.1',
      headers: opts.reqHeaders ?? [{ name: 'Host', value: 'app.example.test' }],
      body: { size: 0, truncated: false },
    },
    response: {
      statusCode: 200,
      statusMessage: 'OK',
      httpVersion: 'HTTP/1.1',
      headers: opts.resHeaders ?? [{ name: 'Content-Type', value: 'application/json' }],
      body: opts.resBody ?? { size: 0, truncated: false },
    },
    tags: [],
  };
}

// ---- redaction (findings #4, #6) ----
describe('redaction regressions', () => {
  const redactor = new Redactor({
    maskCookies: true,
    maskAuthorization: true,
    maskSecretPatterns: true,
  });

  it('redacts a secret embedded in the URL PATH even when a query string is present', () => {
    const jwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJ';
    const out = redactor.redactUrl(`https://x.test/reset/${jwt}?ok=1`);
    expect(out).not.toContain(jwt);
    expect(out).toContain('ok=1');
  });

  it('masks whole-value credential headers when maskSecretPatterns is OFF', () => {
    const r = new Redactor({
      maskCookies: true,
      maskAuthorization: true,
      maskSecretPatterns: false,
    });
    expect(r.redactHeaderValue('X-Api-Key', 'a1b2c3d4e5f6g7h8')).toBe(REDACTION_MASK);
    expect(r.redactHeaderValue('X-Auth-Token', 'tok_abcdefghij')).toBe(REDACTION_MASK);
  });

  it('respects the cookie toggle: cookie is NOT masked when maskCookies is off', () => {
    const r = new Redactor({
      maskCookies: false,
      maskAuthorization: true,
      maskSecretPatterns: false,
    });
    // maskAuthorization is on, but cookie has its own (off) toggle and must not
    // be masked by the credential-header branch.
    expect(r.redactHeaderValue('Cookie', 'sid=keepme')).toContain('keepme');
  });
});

// ---- html decode (findings #22, #23) ----
describe('htmlDecode regressions', () => {
  it('is a correct inverse of htmlEncode (no &amp; double-unescape)', () => {
    for (const s of ['&lt;', '&amp;', '<a>&\'"', 'a & b < c']) {
      expect(htmlDecode(htmlEncode(s))).toBe(s);
    }
  });

  it('does not throw on out-of-range numeric character references', () => {
    expect(() => htmlDecode('&#9999999999;')).not.toThrow();
    expect(() => htmlDecode('&#xFFFFFFFF;')).not.toThrow();
    expect(htmlDecode('&#9999999999;')).toBe('�');
  });
});

// ---- scope normalization (finding #25) ----
describe('scope host normalization', () => {
  it('strips ALL trailing dots so multi-dot hosts still match', () => {
    const cfg: ScopeConfig = {
      include: [
        { id: 'i', enabled: true, hostMatch: 'exact', host: 'a.test', schemes: [], ports: [] },
      ],
      exclude: [],
    };
    expect(isInScope(cfg, { scheme: 'https', host: 'a.test..', port: 443, path: '/' })).toBe(true);
  });
});

// ---- cookie jar (findings #20, #21) ----
describe('cookie jar regressions', () => {
  it('does not replay a Secure cookie over cleartext http', () => {
    const jar = new CookieJar();
    jar.ingest('h.test', ['sid=abc; Secure; Path=/']);
    jar.ingest('h.test', ['theme=dark']);
    expect(jar.cookieHeader('h.test', 'https')).toContain('sid=abc');
    const overHttp = jar.cookieHeader('h.test', 'http') ?? '';
    expect(overHttp).not.toContain('sid=abc');
    expect(overHttp).toContain('theme=dark');
    expect(jar.list().find((c) => c.name === 'sid')?.secure).toBe(true);
  });

  it('detects deletion via the hyphenated epoch Expires form', () => {
    const jar = new CookieJar();
    jar.ingest('h.test', ['sid=live']);
    jar.ingest('h.test', ['sid=x; Expires=Thu, 01-Jan-1970 00:00:00 GMT; Path=/']);
    expect(jar.cookieHeader('h.test')).toBeUndefined();
  });
});

// ---- suppression rules (finding #3) ----
describe('findings suppression rules', () => {
  function finding(over: Partial<Finding>): Finding {
    return {
      id: crypto.randomUUID(),
      exchangeId: 'ex-a',
      dedupeKey: 'security-headers|x|csp',
      title: 't',
      severity: 'medium',
      confidence: 'firm',
      module: 'security-headers',
      moduleVersion: '1.0.0',
      description: 'd',
      remediation: 'r',
      evidence: [],
      createdAt: Date.now(),
      suppressed: false,
      ...over,
    };
  }

  it('a host-only rule does NOT mute findings on other hosts', () => {
    const db = Database.openInMemory();
    const history = new HistoryRepo(db);
    // Two parent exchanges (FK targets).
    history.insert(exchange({ host: 'a.example' }) as HttpExchange);
    const exB = exchange({ host: 'b.example' });
    exB.id = 'ex-b';
    history.insert(exB);
    const repo = new FindingsRepo(db);

    repo.addSuppression({
      id: 's1',
      host: 'a.example',
      reason: 'noisy host',
      createdAt: Date.now(),
    });

    // Finding on b.example must remain visible (the pre-fix bug hid ALL findings).
    const fb = finding({ id: 'fb', exchangeId: 'ex-b', dedupeKey: 'security-headers|x|hsts' });
    repo.upsert(fb, 'b.example');
    expect(repo.list().some((f) => f.id === 'fb')).toBe(true);

    db.close();
  });

  it('a host rule suppresses findings whose exchange host matches', () => {
    const db = Database.openInMemory();
    const history = new HistoryRepo(db);
    const exA = exchange({ host: 'a.example' });
    exA.id = 'ex-a';
    history.insert(exA);
    const repo = new FindingsRepo(db);
    repo.addSuppression({ id: 's1', host: 'a.example', reason: 'x', createdAt: Date.now() });
    repo.upsert(finding({ id: 'fa', exchangeId: 'ex-a' }), 'a.example');
    expect(repo.list().some((f) => f.id === 'fa')).toBe(false); // suppressed
    expect(repo.list({ includeSuppressed: true }).some((f) => f.id === 'fa')).toBe(true);
    db.close();
  });

  it('a rule with no matchable criteria never matches everything', () => {
    const db = Database.openInMemory();
    const history = new HistoryRepo(db);
    const exA = exchange({ host: 'a.example' });
    exA.id = 'ex-a';
    history.insert(exA);
    const repo = new FindingsRepo(db);
    repo.addSuppression({ id: 's1', reason: 'blank rule', createdAt: Date.now() });
    repo.upsert(finding({ id: 'fa', exchangeId: 'ex-a' }), 'a.example');
    expect(repo.list().some((f) => f.id === 'fa')).toBe(true);
    db.close();
  });
});

// ---- scanner: CORS + gzip bomb (findings #11, #12) ----
describe('scanner regressions', () => {
  let scanner: PassiveScanner;
  beforeAll(() => {
    scanner = new PassiveScanner(blobs, {
      maskCookies: true,
      maskAuthorization: true,
      maskSecretPatterns: true,
    });
  });

  it('flags reflected-origin + credentials as a high CORS finding', async () => {
    const findings = await scanner.scan(
      exchange({
        reqHeaders: [
          { name: 'Host', value: 'app.example.test' },
          { name: 'Origin', value: 'https://evil.example' },
        ],
        resHeaders: [
          { name: 'Content-Type', value: 'application/json' },
          { name: 'Access-Control-Allow-Origin', value: 'https://evil.example' },
          { name: 'Access-Control-Allow-Credentials', value: 'true' },
        ],
      }),
    );
    const cors = findings.find((f) => f.module === 'cors');
    expect(cors?.severity).toBe('high');
    expect(cors?.title).toMatch(/reflect/i);
  });

  it('flags the null origin + credentials CORS case', async () => {
    const findings = await scanner.scan(
      exchange({
        resHeaders: [
          { name: 'Content-Type', value: 'application/json' },
          { name: 'Access-Control-Allow-Origin', value: 'null' },
          { name: 'Access-Control-Allow-Credentials', value: 'true' },
        ],
      }),
    );
    expect(findings.find((f) => f.module === 'cors')?.severity).toBe('high');
  });

  it('does not hang or throw on a gzip decompression bomb', async () => {
    // 4 MiB of a single byte compresses to a few KB but would inflate past the
    // 1 MiB scan cap; the bounded gunzip must reject it fast, not exhaust memory.
    const compressed = zlib.gzipSync(Buffer.alloc(4 * 1024 * 1024, 0x41));
    const t0 = Date.now();
    const findings = await scanner.scan(
      exchange({
        resHeaders: [
          { name: 'Content-Type', value: 'application/json' },
          { name: 'Content-Encoding', value: 'gzip' },
        ],
        resBody: {
          size: compressed.length,
          truncated: false,
          inline: compressed,
          contentEncoding: 'gzip',
        },
      }),
    );
    expect(Date.now() - t0).toBeLessThan(3000);
    expect(Array.isArray(findings)).toBe(true);
  });
});

// ---- project ws export/import (finding #9) ----
describe('websocket export/import round-trip', () => {
  it('preserves captured WebSocket frames through export→import', async () => {
    const s1 = await ProjectStore.create(path.join(dir, 'ws-a.tacnocproj'), {
      name: 'WS',
      secretStore: new InMemorySecretStore(),
    });
    const ex = exchange({ host: 'ws.example' });
    ex.id = 'ws-ex';
    ex.tags = ['websocket'];
    s1.history.insert(ex);
    s1.wsMessages.insert({
      id: 'm1',
      exchangeId: 'ws-ex',
      seq: 0,
      direction: 'c2s',
      kind: 'text',
      size: 5,
      truncated: false,
      payload: Buffer.from('hello'),
      createdAt: Date.now(),
    });
    const exported = await s1.export();
    s1.close();
    expect(exported.websockets).toHaveLength(1);

    const s2 = await ProjectStore.import(exported, path.join(dir, 'ws-b.tacnocproj'), {
      secretStore: new InMemorySecretStore(),
    });
    const restored = s2.wsMessages.listByExchange('ws-ex');
    expect(restored).toHaveLength(1);
    expect(Buffer.from(restored[0]!.payloadBase64, 'base64').toString()).toBe('hello');
    s2.close();
  });
});

// ---- secret store fail-closed (finding #2) ----
describe('secret store fail-closed', () => {
  it('loadOrCreate propagates a decrypt error instead of regenerating over the key', async () => {
    // A store that HAS the secret but cannot decrypt it (cross-user DPAPI, etc.).
    const undecryptable: SecretStore = {
      get: () => Promise.reject(new Error('present but undecryptable')),
      set: () => Promise.resolve(),
      delete: () => Promise.resolve(),
      isSecure: () => true,
      backendName: () => 'mock',
    };
    const certPath = path.join(dir, 'fail-closed-ca.pem');
    await expect(CertificateAuthority.loadOrCreate(certPath, undecryptable)).rejects.toThrow(
      /undecryptable/,
    );
    // It must NOT have written a fresh CA cert to disk (no silent regeneration).
    await expect(fs.access(certPath)).rejects.toBeTruthy();
  });
});

// ---- session: proxy not wedged after a failed start (finding #5) ----
describe('session proxy start resilience', () => {
  it('remains startable after a failed bind (EADDRINUSE)', async () => {
    const sdir = path.join(dir, 'sess.tacnocproj');
    const session = new TacnocSession({ secretStoreFactory: () => new InMemorySecretStore() });
    await session.createProject(sdir, 'sess');

    // Occupy a port so the first startProxy fails to bind.
    const blocker = net.createServer();
    const occupiedPort = await new Promise<number>((resolve) => {
      blocker.listen(0, '127.0.0.1', () => resolve((blocker.address() as net.AddressInfo).port));
    });

    await expect(session.startProxy('127.0.0.1', occupiedPort)).rejects.toBeTruthy();
    // The failed start must not leave a dangling proxy; a retry on a free port works.
    const status = await session.startProxy('127.0.0.1', 0);
    expect(status.running).toBe(true);

    await session.dispose();
    await new Promise<void>((resolve) => blocker.close(() => resolve()));
  });
});
