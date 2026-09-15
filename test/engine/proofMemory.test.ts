/**
 * Tests for the proof gate, cross-hunt memory, and attack-surface ranking.
 *
 * The proof tests are the important ones. The whole point of the gate is that a
 * caller cannot assert a finding into existence, so the tests that matter are
 * the ones where a confident claim meets identical bytes and loses.
 */

import { describe, expect, it, beforeEach, afterEach } from 'vitest';
import { promises as fs } from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { proveDifferential } from '../../src/engine/analysis/proof.js';
import { HuntMemory, pathShape } from '../../src/engine/analysis/huntMemory.js';
import { rankAttackSurface } from '../../src/engine/analysis/surface.js';
import type { ExchangeDetail } from '../../src/shared/detail.js';
import type { TargetMap } from '../../src/shared/target.js';

function exchange(
  id: string,
  opts: {
    status?: number;
    body?: string;
    method?: string;
    host?: string;
    headers?: [string, string][];
    noResponse?: boolean;
    path?: string;
  } = {},
): ExchangeDetail {
  const body = opts.body ?? '';
  const target = opts.path ?? '/x';
  const detail: ExchangeDetail = {
    id,
    createdAt: 1,
    source: 'repeater',
    scheme: 'https',
    host: opts.host ?? 'api.test',
    port: 443,
    inScope: true,
    automated: false,
    tags: [],
    request: {
      method: opts.method ?? 'GET',
      target,
      url: `https://${opts.host ?? 'api.test'}${target}`,
      httpVersion: 'HTTP/1.1',
      headers: [],
      bodyBase64: '',
      bodySize: 0,
      bodyTruncated: false,
      truncatedForView: false,
      sensitive: { hasCookies: false, hasAuthorization: false, hasTokens: false, fields: [] },
    },
  };
  if (!opts.noResponse) {
    detail.response = {
      statusCode: opts.status ?? 200,
      statusMessage: 'OK',
      httpVersion: 'HTTP/1.1',
      headers: (opts.headers ?? []).map(([name, value]) => ({ name, value })),
      bodyBase64: Buffer.from(body, 'utf8').toString('base64'),
      bodySize: Buffer.byteLength(body),
      bodyTruncated: false,
      truncatedForView: false,
      sensitive: { hasCookies: false, hasAuthorization: false, hasTokens: false, fields: [] },
    };
  }
  return detail;
}

describe('proof gate', () => {
  it('confirms a real body differential', () => {
    const result = proveDifferential(
      exchange('c', { path: '/orders/1', body: '{"order":1,"owner":"me"}' }),
      exchange('t', { path: '/orders/2', body: '{"order":2,"owner":"someone-else"}' }),
      'the order endpoint returns another user’s object',
    );
    expect(result.outcome).toBe('confirmed');
    expect(result.differential.changedLines).toBeGreaterThan(0);
    expect(result.differential.excerpt.length).toBeGreaterThan(0);
  });

  it('confirms a status-only differential', () => {
    const result = proveDifferential(
      exchange('c', { path: '/admin/1', status: 403, body: 'denied' }),
      exchange('t', { path: '/admin/2', status: 200, body: 'denied' }),
      'authorization is not enforced for this role',
    );
    expect(result.outcome).toBe('confirmed');
    expect(result.differential.statusChanged).toBe(true);
    expect(result.reason).toContain('403');
  });

  it('REFUTES identical responses however confident the claim is', () => {
    const result = proveDifferential(
      exchange('c', { path: '/orders/1', status: 200, body: 'same' }),
      exchange('t', { path: '/orders/2', status: 200, body: 'same' }),
      'this definitely proves a critical account takeover',
    );
    expect(result.outcome).toBe('refuted');
    expect(result.differential.bodiesIdentical).toBe(true);
  });

  it('refuses to grade an exchange against itself', () => {
    const same = exchange('same', { body: 'x' });
    const result = proveDifferential(same, same, 'anything');
    expect(result.outcome).toBe('inconclusive');
    expect(result.reason).toMatch(/same exchange/i);
  });

  it('is inconclusive when one side never got a response', () => {
    const result = proveDifferential(
      exchange('c', { path: '/a/1', body: 'x' }),
      exchange('t', { path: '/a/2', noResponse: true }),
      'the server crashed',
    );
    expect(result.outcome).toBe('inconclusive');
    expect(result.reason).toMatch(/no response/i);
  });

  it('ignores incidental headers rather than calling them a difference', () => {
    const result = proveDifferential(
      exchange('c', { path: '/a/1', body: 'same', headers: [['Date', 'a']] }),
      exchange('t', {
        path: '/a/2',
        body: 'same',
        headers: [
          ['Date', 'b'],
          ['X-Request-Id', 'c'],
        ],
      }),
      'header leak',
    );
    // A Date and a request id differ on almost every pair of responses. Counting
    // them would manufacture findings AND block real refutations.
    expect(result.outcome).toBe('refuted');
    expect(result.differential.headerDifferences).toHaveLength(0);
  });

  it('treats a header VALUE change as a real difference (open redirect, cookie flags)', () => {
    const redirect = proveDifferential(
      exchange('c', {
        path: '/go/1',
        status: 302,
        headers: [['Location', 'https://target.example/home']],
      }),
      exchange('t', {
        path: '/go/2',
        status: 302,
        headers: [['Location', 'https://evil.example/']],
      }),
      'the redirect destination is caller-controlled',
    );
    // Both responses carry a Location header and an empty body. Comparing only
    // header NAMES called this "byte-identical" and refuted an open redirect.
    expect(redirect.outcome).toBe('confirmed');
    expect(redirect.differential.headerDifferences.join(' ')).toMatch(/evil\.example/);

    const cookie = proveDifferential(
      exchange('c', {
        path: '/login/1',
        headers: [['Set-Cookie', 'session=AAAA; HttpOnly; Secure']],
      }),
      exchange('t', { path: '/login/2', headers: [['Set-Cookie', 'session=BBBB']] }),
      'the session cookie loses its flags on this path',
    );
    expect(cookie.outcome).toBe('confirmed');
  });

  it('is inconclusive when the two requests are identical — that measures nondeterminism', () => {
    const result = proveDifferential(
      exchange('c', { path: '/search', body: '<input name="csrf" value="aaaa">' }),
      exchange('t', { path: '/search', body: '<input name="csrf" value="bbbb">' }),
      'this definitely proves a critical issue',
    );
    // Nothing was varied, so the difference measures how noisy the endpoint is,
    // not how it behaves. This is the assert-a-finding-into-existence path.
    expect(result.outcome).toBe('inconclusive');
    expect(result.reason).toMatch(/identical/i);
  });

  it('compares body BYTES, so binary bodies are not collapsed into one another', () => {
    const bin = (id: string, path: string, bytes: number[]): ExchangeDetail => {
      const detail = exchange(id, { path });
      detail.response!.bodyBase64 = Buffer.from(bytes).toString('base64');
      return detail;
    };
    // Every byte here is invalid UTF-8. Decoded, both bodies become identical
    // replacement characters and the hypothesis would be falsely refuted.
    const result = proveDifferential(
      bin('c', '/f/1', [0xff, 0xfe, 0xfd]),
      bin('t', '/f/2', [0xc0, 0xc1, 0xf5]),
      'the two objects return different content',
    );
    expect(result.differential.bodiesIdentical).toBe(false);
    expect(result.outcome).toBe('confirmed');
    expect(result.differential.controlLength).toBe(3);
  });

  it('flags a second changed variable as a caveat rather than silently confirming', () => {
    const result = proveDifferential(
      exchange('c', { path: '/a/1', method: 'GET', body: 'a' }),
      exchange('t', { path: '/a/2', method: 'POST', body: 'b' }),
      'the id is not checked',
    );
    expect(result.outcome).toBe('confirmed');
    expect(result.caveats.join(' ')).toMatch(/method differs/i);
  });

  it('flags rate limiting and server errors as caveats', () => {
    const limited = proveDifferential(
      exchange('c', { path: '/a/1', status: 200, body: 'a' }),
      exchange('t', { path: '/a/2', status: 429, body: 'b' }),
      'auth bypass',
    );
    expect(limited.caveats.join(' ')).toMatch(/rate limiting/i);

    const errored = proveDifferential(
      exchange('c', { path: '/a/1', status: 200, body: 'a' }),
      exchange('t', { path: '/a/2', status: 500, body: 'b' }),
      'injection',
    );
    expect(errored.caveats.join(' ')).toMatch(/5xx/i);
  });
});

describe('hunt memory', () => {
  let dir = '';

  beforeEach(async () => {
    // Resolved for the same reason as in huntFolderLayout.test.ts: macOS tmpdir is a symlink.
    dir = await fs.realpath(await fs.mkdtemp(path.join(os.tmpdir(), 'tacnoc-hunt-')));
  });
  afterEach(async () => {
    await fs.rm(dir, { recursive: true, force: true }).catch(() => undefined);
  });

  it('generalizes a concrete path so lessons transfer between objects and targets', () => {
    expect(pathShape('/api/orders/10432')).toBe('/api/orders/{id}');
    expect(pathShape('/api/orders/10432')).toBe(pathShape('/api/orders/99887'));
    expect(pathShape('/api/users/2f1c9b7e-4a6d-4c3e-9f11-8a7b6c5d4e3f/profile')).toBe(
      '/api/users/{id}/profile',
    );
    expect(pathShape('/api/Orders/5?expand=all')).toBe('/api/orders/{id}');
    expect(pathShape('/login')).toBe('/login');
  });

  it('records outcomes and merges them into a verdict per shape and class', async () => {
    const memory = new HuntMemory({ directory: dir });
    await memory.record({
      program: 'acme',
      host: 'api.acme.test',
      pathShape: '/api/orders/1',
      klass: 'access-control',
      claim: 'order id not ownership-checked',
      outcome: 'confirmed',
      note: 'returned another tenant order',
    });
    await memory.record({
      program: 'other-client',
      host: 'api.other.test',
      pathShape: '/api/orders/77',
      klass: 'access-control',
      claim: 'same idea on another target',
      outcome: 'refuted',
    });

    const recall = await memory.recall({ klass: 'access-control', program: 'acme' });
    // Scoped to one program: only that program's record is considered, and only
    // its hosts are returned — another client's asset names are not context here.
    expect(recall.recordsConsidered).toBe(1);
    expect(recall.entries).toHaveLength(1);
    const entry = recall.entries[0]!;
    expect(entry.pathShape).toBe('/api/orders/{id}');
    expect(entry.confirmed).toBe(1);
    expect(entry.refuted).toBe(0);
    expect(entry.hosts).toContain('api.acme.test');

    // Across programs, both records collapse onto the same shape, and no host
    // from either engagement is disclosed.
    const all = await memory.recall({ klass: 'access-control' });
    expect(all.recordsConsidered).toBe(2);
    expect(all.entries[0]?.hosts).toHaveLength(0);
    expect(all.entries[0]?.suggestion).toMatch(/mixed history/i);
  });

  it('tells the planner to deprioritise a shape refuted repeatedly', async () => {
    const memory = new HuntMemory({ directory: dir });
    for (let i = 0; i < 3; i += 1) {
      await memory.record({
        program: 'p',
        host: 'h.test',
        pathShape: '/search',
        klass: 'reflection',
        claim: 'reflected input',
        outcome: 'refuted',
      });
    }
    const recall = await memory.recall({ pathShape: '/search', klass: 'reflection' });
    expect(recall.entries[0]?.suggestion).toMatch(/deprioritise/i);
  });

  it('redacts secrets before they reach the durable store', async () => {
    const memory = new HuntMemory({ directory: dir });
    await memory.record({
      program: 'p',
      host: 'h.test',
      pathShape: '/login',
      klass: 'auth',
      claim: 'session token is predictable',
      outcome: 'confirmed',
      note: 'captured Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.abcdefghijklmno.signaturepart',
    });
    const raw = await fs.readFile(path.join(dir, 'hunt-outcomes.jsonl'), 'utf8');
    expect(raw).not.toContain('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.abcdefghijklmno.signaturepart');
  });

  it('redacts LLM provider keys — the credential this app itself prompts for', async () => {
    const memory = new HuntMemory({ directory: dir });
    await memory.record({
      program: 'p',
      host: 'h.test',
      pathShape: '/config',
      klass: 'disclosure',
      claim: 'key in response',
      outcome: 'confirmed',
      note: 'response body contained sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA and sk-proj-BBBBBBBBBBBBBBBBBBBBBBBB',
    });
    const raw = await fs.readFile(path.join(dir, 'hunt-outcomes.jsonl'), 'utf8');
    expect(raw).not.toContain('sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA');
    expect(raw).not.toContain('sk-proj-BBBBBBBBBBBBBBBBBBBBBBBB');
  });

  it('reports honestly when nothing matches instead of inventing history', async () => {
    const memory = new HuntMemory({ directory: dir });
    const recall = await memory.recall({ host: 'never-seen.test' });
    expect(recall.entries).toHaveLength(0);
    expect(recall.notes.join(' ')).toMatch(/new ground/i);
  });

  it('survives a corrupt line rather than losing the whole store', async () => {
    const memory = new HuntMemory({ directory: dir });
    await memory.record({
      program: 'p',
      host: 'h.test',
      pathShape: '/a',
      klass: 'auth',
      claim: 'c',
      outcome: 'confirmed',
    });
    await fs.appendFile(path.join(dir, 'hunt-outcomes.jsonl'), 'not json at all\n', 'utf8');
    const recall = await memory.recall({});
    expect(recall.recordsConsidered).toBe(1);
  });
});

describe('attack-surface ranking', () => {
  const map = (): TargetMap => ({
    generatedAt: 1,
    totalExchanges: 10,
    analyzedExchanges: 10,
    truncated: false,
    sites: [
      {
        id: 's1',
        scheme: 'https',
        host: 'api.test',
        port: 443,
        requestCount: 10,
        firstSeen: 1,
        lastSeen: 2,
        inScopeEndpoints: 3,
        endpoints: [
          {
            id: 'e1',
            path: '/api/orders/10432',
            methods: ['GET', 'DELETE'],
            statusCodes: [200],
            mimeTypes: ['application/json'],
            parameterNames: [],
            requestCount: 5,
            firstSeen: 1,
            lastSeen: 2,
            latestExchangeId: 'x-orders',
            inScope: true,
          },
          {
            id: 'e2',
            path: '/fetch',
            methods: ['GET'],
            statusCodes: [200],
            mimeTypes: ['text/html'],
            parameterNames: ['imageUrl'],
            requestCount: 2,
            firstSeen: 1,
            lastSeen: 2,
            latestExchangeId: 'x-fetch',
            inScope: true,
          },
          {
            id: 'e3',
            path: '/private',
            methods: ['GET'],
            statusCodes: [200],
            mimeTypes: [],
            parameterNames: ['id'],
            requestCount: 9,
            firstSeen: 1,
            lastSeen: 2,
            latestExchangeId: 'x-private',
            inScope: false,
          },
        ],
      },
    ],
  });

  it('flags a path identifier plus a destructive method as access control', () => {
    const ranking = rankAttackSurface(map());
    const orders = ranking.leads.find((l) => l.path === '/api/orders/10432');
    expect(orders?.classes[0]?.kind).toBe('access-control');
    expect(orders?.classes[0]?.because.join(' ')).toMatch(/identifier/i);
  });

  it('flags a URL-shaped parameter as SSRF', () => {
    const ranking = rankAttackSurface(map());
    const fetchLead = ranking.leads.find((l) => l.path === '/fetch');
    expect(fetchLead?.classes.map((c) => c.kind)).toContain('ssrf');
    expect(fetchLead?.classes[0]?.because.join(' ')).toMatch(/imageUrl/);
  });

  it('never surfaces an out-of-scope endpoint, and says how many it dropped', () => {
    const ranking = rankAttackSurface(map());
    expect(ranking.leads.some((l) => l.path === '/private')).toBe(false);
    expect(ranking.outOfScopeSkipped).toBe(1);
    expect(ranking.leads.every((l) => l.inScope)).toBe(true);
  });

  it('says plainly that ranking only reorders work', () => {
    expect(rankAttackSurface(map()).notes.join(' ')).toMatch(/reorders/i);
  });
});
