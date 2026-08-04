import { describe, it, expect, afterEach } from 'vitest';
import * as os from 'node:os';
import * as path from 'node:path';
import { promises as fs } from 'node:fs';
import * as crypto from 'node:crypto';
import { Database } from '../../src/engine/storage/database.js';
import { HistoryRepo } from '../../src/engine/storage/historyRepo.js';
import { CURRENT_SCHEMA_VERSION } from '../../src/engine/storage/migrations.js';
import { BlobStore } from '../../src/engine/storage/blobStore.js';
import { BodyCollector, readBodyBytes } from '../../src/engine/storage/bodyCollector.js';
import { ProjectStore } from '../../src/engine/project/projectStore.js';
import { InMemorySecretStore } from '../../src/engine/ca/secretStore.js';
import type { HttpExchange, HttpHeader } from '../../src/shared/model.js';
import type { BodyLimits } from '../../src/shared/config.js';

const tmpRoots: string[] = [];
async function tmp(): Promise<string> {
  const dir = path.join(os.tmpdir(), `tacnoc-store-${crypto.randomBytes(6).toString('hex')}`);
  await fs.mkdir(dir, { recursive: true });
  tmpRoots.push(dir);
  return dir;
}

afterEach(async () => {
  for (const d of tmpRoots.splice(0)) await fs.rm(d, { recursive: true, force: true });
});

function sampleExchange(overrides: Partial<HttpExchange> = {}): HttpExchange {
  const headers: HttpHeader[] = [
    { name: 'Host', value: 'example.test' },
    { name: 'X-Dup', value: 'a' },
    { name: 'x-dup', value: 'b' }, // different casing + duplicate must be preserved
  ];
  return {
    id: crypto.randomUUID(),
    createdAt: Date.now(),
    source: 'proxy',
    scheme: 'https',
    host: 'example.test',
    port: 443,
    inScope: true,
    automated: false,
    request: {
      method: 'GET',
      target: '/a',
      url: 'https://example.test/a',
      httpVersion: 'HTTP/1.1',
      headers,
      body: { size: 0, truncated: false },
    },
    response: {
      statusCode: 200,
      statusMessage: 'OK',
      httpVersion: 'HTTP/1.1',
      headers: [{ name: 'Content-Type', value: 'application/json' }],
      body: { size: 5, truncated: false, inline: new Uint8Array([104, 101, 108, 108, 111]) },
    },
    tags: [],
    ...overrides,
  };
}

describe('database + migrations', () => {
  it('migrates a fresh in-memory db to the current version', () => {
    const db = Database.openInMemory();
    expect(db.getUserVersion()).toBe(CURRENT_SCHEMA_VERSION);
    db.close();
  });

  it('is idempotent when reopened (no data loss on reopen)', async () => {
    const dir = await tmp();
    const dbPath = path.join(dir, 'x.db');
    const db1 = Database.open(dbPath);
    db1.run("INSERT INTO project_meta (key, value) VALUES ('k','v')");
    db1.close();
    const db2 = Database.open(dbPath);
    expect(db2.getUserVersion()).toBe(CURRENT_SCHEMA_VERSION);
    expect(db2.get<{ value: string }>("SELECT value FROM project_meta WHERE key='k'")?.value).toBe(
      'v',
    );
    db2.close();
  });
});

describe('history repo', () => {
  it('round-trips an exchange preserving header order/casing/duplicates', () => {
    const db = Database.openInMemory();
    const repo = new HistoryRepo(db);
    const ex = sampleExchange();
    repo.insert(ex);
    const back = repo.get(ex.id)!;
    expect(back.request.headers).toEqual(ex.request.headers);
    expect(back.response?.statusCode).toBe(200);
    expect(Buffer.from(back.response!.body.inline!).toString()).toBe('hello');
    db.close();
  });

  it('filters by method, status class, host, and scope', async () => {
    const { HistoryRepo } = await import('../../src/engine/storage/historyRepo.js');
    const db = Database.openInMemory();
    const repo = new HistoryRepo(db);
    repo.insert(
      sampleExchange({ id: '1', request: { ...sampleExchange().request, method: 'GET' } }),
    );
    repo.insert(
      sampleExchange({
        id: '2',
        host: 'api.example.test',
        inScope: false,
        request: { ...sampleExchange().request, method: 'POST', url: 'https://api.example.test/x' },
        response: { ...sampleExchange().response!, statusCode: 404, statusMessage: 'Not Found' },
      }),
    );
    expect(repo.query({ method: 'post' }).total).toBe(1);
    expect(repo.query({ statusClass: 4 }).total).toBe(1);
    expect(repo.query({ host: 'api' }).total).toBe(1);
    expect(repo.query({ inScopeOnly: true }).total).toBe(1);
    expect(repo.query({ text: 'example' }).total).toBe(2);
    db.close();
  });
});

describe('blob store', () => {
  it('stores and dedupes by content hash', async () => {
    const dir = await tmp();
    const store = new BlobStore(path.join(dir, 'blobs'));
    const a = await store.putBytes(Buffer.from('same'));
    const b = await store.putBytes(Buffer.from('same'));
    expect(a.id).toBe(b.id);
    expect(await store.has(a.id)).toBe(true);
    expect((await store.readBytes(a.id)).toString()).toBe('same');
  });
});

describe('body collector', () => {
  const limits: BodyLimits = { spillToDiskAfterBytes: 10, maxCapturedBytes: 20 };

  it('keeps small bodies inline', async () => {
    const dir = await tmp();
    const bs = new BlobStore(path.join(dir, 'b'));
    const c = new BodyCollector(limits, bs);
    await c.write(Buffer.from('12345'));
    const body = await c.finish();
    expect(body.size).toBe(5);
    expect(body.inline).toBeInstanceOf(Uint8Array);
    expect(body.blobId).toBeUndefined();
  });

  it('spills large bodies to the blob store', async () => {
    const dir = await tmp();
    const bs = new BlobStore(path.join(dir, 'b'));
    const c = new BodyCollector(limits, bs);
    await c.write(Buffer.from('12345'));
    await c.write(Buffer.from('67890AB')); // pushes past spill threshold (10)
    const body = await c.finish();
    expect(body.size).toBe(12);
    expect(body.blobId).toBeDefined();
    expect(body.inline).toBeUndefined();
    expect((await readBodyBytes(body, bs)).toString()).toBe('1234567890AB');
  });

  it('truncates at the hard cap but reports total bytes seen', async () => {
    const dir = await tmp();
    const bs = new BlobStore(path.join(dir, 'b'));
    const c = new BodyCollector(limits, bs);
    await c.write(Buffer.alloc(30, 0x41)); // 30 bytes, cap is 20
    const body = await c.finish();
    expect(body.size).toBe(20);
    expect(body.truncated).toBe(true);
    expect(c.seenBytes).toBe(30);
  });
});

describe('project reopen + export/import', () => {
  it('persists exchanges across close/reopen', async () => {
    const dir = await tmp();
    const projDir = path.join(dir, 'proj.tacnocproj');
    // The secret store (holding the data-encryption key) persists like the app's
    // on-disk store, so reopen uses the SAME instance across close/open.
    const secretStore = new InMemorySecretStore();
    const s1 = await ProjectStore.create(projDir, { name: 'T', secretStore });
    expect(s1.encryptedAtRest).toBe(true);
    const ex = sampleExchange();
    s1.history.insert(ex);
    s1.close();

    const s2 = await ProjectStore.open(projDir, { secretStore });
    expect(s2.history.count()).toBe(1);
    expect(s2.history.get(ex.id)?.request.url).toBe('https://example.test/a');
    expect(Buffer.from(s2.history.get(ex.id)!.response!.body.inline!).toString()).toBe('hello');
    expect(s2.info?.name).toBe('T');
    s2.close();
  });

  it('round-trips through versioned export/import including body bytes', async () => {
    const dir = await tmp();
    const s1 = await ProjectStore.create(path.join(dir, 'a.tacnocproj'), {
      name: 'Export',
      secretStore: new InMemorySecretStore(),
    });
    s1.history.insert(sampleExchange({ id: 'ex1' }));
    const exported = await s1.export();
    s1.close();
    expect(exported.exchanges).toHaveLength(1);

    const s2 = await ProjectStore.import(exported, path.join(dir, 'b.tacnocproj'), {
      secretStore: new InMemorySecretStore(),
    });
    const back = s2.history.get('ex1')!;
    expect(Buffer.from(back.response!.body.inline!).toString()).toBe('hello');
    expect(back.request.headers).toEqual(sampleExchange().request.headers);
    s2.close();
  });
});

async function readAllUnder(dir: string): Promise<Buffer> {
  const out: Buffer[] = [];
  const walk = async (d: string): Promise<void> => {
    for (const entry of await fs.readdir(d, { withFileTypes: true })) {
      const p = path.join(d, entry.name);
      if (entry.isDirectory()) await walk(p);
      else out.push(await fs.readFile(p));
    }
  };
  await walk(dir);
  return Buffer.concat(out);
}

describe('at-rest encryption', () => {
  it('encrypts bodies and headers on disk but round-trips through the key', async () => {
    const dir = await tmp();
    const projDir = path.join(dir, 'enc.tacnocproj');
    const secretStore = new InMemorySecretStore();
    const store = await ProjectStore.create(projDir, { name: 'Enc', secretStore });
    expect(store.encryptedAtRest).toBe(true);

    const MARKER = 'SUPERSECRETMARKER-98765';
    const BLOBSECRET = 'BLOBSECRETPAYLOAD';
    const ref = await store.blobs.putBytes(Buffer.from(BLOBSECRET.repeat(200)));
    store.history.insert(
      sampleExchange({
        id: 'enc1',
        request: {
          ...sampleExchange().request,
          headers: [{ name: 'X-Marker', value: MARKER }],
        },
        response: {
          statusCode: 200,
          statusMessage: 'OK',
          httpVersion: 'HTTP/1.1',
          headers: [{ name: 'Content-Type', value: 'application/json' }],
          body: { size: BLOBSECRET.length * 200, truncated: false, blobId: ref.id },
        },
      }),
    );
    store.close();

    // Raw on-disk bytes must NOT contain the plaintext markers.
    const onDisk = await readAllUnder(projDir);
    expect(onDisk.includes(Buffer.from(MARKER))).toBe(false);
    expect(onDisk.includes(Buffer.from(BLOBSECRET))).toBe(false);

    // The blob id (filename) is a keyed HMAC, NOT the plaintext SHA-256, so a
    // keyless attacker cannot confirm known content by hashing it.
    const plainHash = crypto.createHash('sha256').update(BLOBSECRET.repeat(200)).digest('hex');
    expect(ref.id).not.toBe(plainHash);
    expect(onDisk.includes(Buffer.from(plainHash))).toBe(false);

    // With the key, everything decrypts.
    const reopened = await ProjectStore.open(projDir, { secretStore });
    const ex = reopened.history.get('enc1')!;
    expect(ex.request.headers[0]?.value).toBe(MARKER);
    const body = await reopened.blobs.readBytes(ref.id);
    expect(body.toString().startsWith(BLOBSECRET)).toBe(true);
    reopened.close();
  });

  it('exports ALL exchanges, paging beyond the 2000-row page size', async () => {
    const dir = await tmp();
    const secretStore = new InMemorySecretStore();
    const store = await ProjectStore.create(path.join(dir, 'big.tacnocproj'), {
      name: 'Big',
      secretStore,
    });
    const N = 2050;
    for (let i = 0; i < N; i++) {
      store.history.insert(
        sampleExchange({
          id: `ex-${i}`,
          request: { ...sampleExchange().request, body: { size: 0, truncated: false } },
        }),
      );
    }
    expect(store.history.count()).toBe(N);
    const exported = await store.export();
    expect(exported.exchanges).toHaveLength(N);
    store.close();
  });

  it('cannot read encrypted content without the data-encryption key', async () => {
    const dir = await tmp();
    const projDir = path.join(dir, 'nokey.tacnocproj');
    const store = await ProjectStore.create(projDir, {
      name: 'N',
      secretStore: new InMemorySecretStore(),
    });
    store.history.insert(sampleExchange({ id: 'x' }));
    store.close();

    // Reopen with a fresh (empty) secret store → no DEK available.
    const reopened = await ProjectStore.open(projDir, { secretStore: new InMemorySecretStore() });
    expect(reopened.encryptedAtRest).toBe(false);
    expect(() => reopened.history.get('x')).toThrow();
    reopened.close();
  });
});
