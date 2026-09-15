/**
 * Evidence bundles: what goes in, what must never go in, and whether the file
 * a recipient gets actually opens.
 *
 * The load-bearing test here is the host one. `HistoryRepo`'s host filter is a
 * `LIKE '%host%'` substring match, so a bundle built naively on it would ship
 * `notacme-corp.test.evil.example`'s traffic to whoever triages `acme-corp.test`
 * — one target's data disclosed to another program. That is the failure this
 * feature could plausibly cause, so it is tested first and directly.
 *
 * It was tested blind. The fixture returned a one-line briefing and a one-line
 * log tail, neither of which could ever mention the impostor, so the two
 * sections that actually did — the engine briefing, rendered verbatim into
 * `HANDOFF.md`, and the unfiltered session log — passed the assertion by being
 * incapable of failing it. Both fixtures now carry the impostor, which is the
 * only way the assertion means anything.
 */

import { describe, expect, it } from 'vitest';
import * as os from 'node:os';
import * as path from 'node:path';
import * as zlib from 'node:zlib';
import { createHash } from 'node:crypto';
import { promises as fs } from 'node:fs';
import { buildEvidenceBundle, type BundleSource } from '../../src/engine/evidence/bundle.js';
import { readZip } from '../../src/engine/evidence/zip.js';
import { Redactor } from '../../src/engine/redaction/redactor.js';
import { defaultEngagementProfile } from '../../src/shared/engagement.js';
import type { ExchangeDetail } from '../../src/shared/detail.js';
import type { ExchangeSummary } from '../../src/shared/query.js';
import type { Finding } from '../../src/shared/findings.js';
import type { ScopeConfig } from '../../src/shared/scope.js';
import type { TargetSite } from '../../src/shared/target.js';

const HOST = 'acme-corp.test';
const IMPOSTOR = 'notacme-corp.test.evil.example';
const SESSION_COOKIE = 'sid=THIS_IS_A_LIVE_SESSION_TOKEN_9f3a';
const BEARER = 'Bearer eyJhbGciOiJIUzI1NiJ9.SECRETPAYLOAD.c2ln';
const NOW = Date.UTC(2026, 8, 15, 12, 0, 0);

const summary = (
  id: string,
  host: string,
  over: Partial<ExchangeSummary> = {},
): ExchangeSummary => ({
  id,
  createdAt: NOW - 1000,
  source: 'proxy',
  scheme: 'https',
  host,
  port: 443,
  method: 'GET',
  url: `https://${host}/account?access_token=tok_live_SHOULD_NOT_LEAK`,
  path: '/account',
  inScope: true,
  automated: false,
  statusCode: 200,
  mime: 'application/json',
  responseLength: 12,
  durationMs: 10,
  hasResponse: true,
  tags: [],
  ...over,
});

const detail = (s: ExchangeSummary): ExchangeDetail => ({
  id: s.id,
  createdAt: s.createdAt,
  source: s.source,
  scheme: 'https',
  host: s.host,
  port: s.port,
  inScope: s.inScope,
  automated: s.automated,
  tags: [],
  request: {
    method: s.method,
    // Origin-form, so it carries the query string — which is how a credential
    // lands on the request line itself. The fixture used a bare path, which is
    // why the leak survived the first version of these tests.
    target: `${s.path}?access_token=tok_live_SHOULD_NOT_LEAK`,
    url: s.url,
    httpVersion: 'HTTP/1.1',
    headers: [
      { name: 'Host', value: s.host },
      { name: 'Cookie', value: SESSION_COOKIE },
      { name: 'Authorization', value: BEARER },
    ],
    bodyBase64: Buffer.from(`{"password":"hunter2-DO-NOT-LEAK"}`).toString('base64'),
    bodySize: 34,
    bodyTruncated: false,
    truncatedForView: false,
    sensitive: { hasCookies: true, hasAuthorization: true, hasTokens: true, fields: ['cookie'] },
  },
  response: {
    statusCode: 200,
    statusMessage: 'OK',
    httpVersion: 'HTTP/1.1',
    headers: [{ name: 'Content-Type', value: 'application/json' }],
    bodyBase64: Buffer.from('{"ok":true}').toString('base64'),
    bodySize: 11,
    bodyTruncated: false,
    truncatedForView: false,
    sensitive: { hasCookies: false, hasAuthorization: false, hasTokens: false, fields: [] },
  },
});

const site = (host: string): TargetSite => ({
  id: `https://${host}:443`,
  scheme: 'https',
  host,
  port: 443,
  requestCount: 1,
  firstSeen: NOW - 2000,
  lastSeen: NOW - 1000,
  inScopeEndpoints: 1,
  endpoints: [
    {
      id: `https://${host}:443/account`,
      path: '/account',
      methods: ['GET'],
      statusCodes: [200, 403],
      mimeTypes: ['application/json'],
      parameterNames: ['access_token', 'user_id'],
      requestCount: 1,
      firstSeen: NOW - 2000,
      lastSeen: NOW - 1000,
      latestExchangeId: 'ex-1',
      inScope: true,
    },
  ],
});

const finding = (over: Partial<Finding> = {}): Finding => ({
  id: 'f-1',
  exchangeId: 'ex-1',
  dedupeKey: 'missing-hsts',
  title: 'Missing Strict-Transport-Security',
  severity: 'medium',
  confidence: 'firm',
  module: 'headers',
  moduleVersion: '1.0.0',
  description: 'The response did not set HSTS.',
  remediation: 'Set Strict-Transport-Security.',
  evidence: [
    { location: 'response-headers', excerpt: 'no HSTS header', field: 'strict-transport-security' },
  ],
  createdAt: NOW - 500,
  suppressed: false,
  ...over,
});

const scopeWith = (host: string): ScopeConfig => ({
  include: [{ id: 'r1', enabled: true, hostMatch: 'exact', host, schemes: [], ports: [] }],
  exclude: [],
});

function source(over: Partial<BundleSource> = {}): BundleSource {
  const rows = [summary('ex-1', HOST), summary('ex-2', IMPOSTOR, { id: 'ex-2' })];
  const byId = new Map(rows.map((r) => [r.id, detail(r)]));
  return {
    appVersion: '0.5.6',
    host: HOST,
    profile: { ...defaultEngagementProfile(), program: 'Acme BBP', authorizationRef: 'H1-12345' },
    scope: scopeWith(HOST),
    sites: [site(HOST)],
    exchanges: rows,
    exchangesAvailable: rows.length,
    detail: (id) => Promise.resolve(byId.get(id)),
    findings: [finding()],
    audit: [
      { ts: NOW - 400, actor: 'operator', action: 'job.create', target: `https://${HOST}/account` },
    ],
    // Models `session.engineBriefing({ host })`: unnarrowed it ranks every site
    // the project has captured, which is exactly how another target's endpoints
    // reached a bundle addressed to this one.
    engineBriefing: (scopedHost?: string) =>
      Promise.resolve(
        [
          'ENGINE BRIEFING — scope is set.',
          '## Ranked attack surface (in-scope endpoints, best first)',
          ...[HOST, IMPOSTOR]
            .filter((h) => scopedHost === undefined || h === scopedHost)
            .map((h, i) => `${i + 1}. GET https://${h}/account — access-control`),
        ].join('\n'),
      ),
    // The proxy logs `{ url }` and `{ host, port }` for every host it sees, so
    // the tail names targets this bundle is not addressed to.
    logs: {
      jsonl:
        '{"level":"info","msg":"proxy started"}\n' +
        `{"level":"info","msg":"connect","host":"${IMPOSTOR}","port":443}\n`,
      count: 2,
      dropped: 0,
    },
    redactor: new Redactor({
      maskCookies: true,
      maskAuthorization: true,
      maskSecretPatterns: true,
    }),
    targetInScope: true,
    now: NOW,
    ...over,
  };
}

const text = (files: Map<string, Buffer>, name: string): string => {
  const b = files.get(name);
  if (!b) throw new Error(`bundle has no ${name} — has ${[...files.keys()].join(', ')}`);
  return b.toString('utf8');
};
const whole = (files: Map<string, Buffer>): string =>
  [...files.values()].map((b) => b.toString('utf8')).join('\n');

describe('evidence bundle', () => {
  it('carries only the requested host, never a name that merely contains it', async () => {
    const built = await buildEvidenceBundle(source());
    const files = readZip(built.zip);
    const all = whole(files);

    expect(built.summary.exchangeCount).toBe(1);
    expect(all).toContain(HOST);
    // The impostor host shares `acme-corp.test` as a substring. A LIKE-based
    // filter would have put its traffic in a bundle addressed to someone else.
    expect(all).not.toContain(IMPOSTOR);
    expect([...files.keys()].filter((k) => k.startsWith('exchanges/'))).toHaveLength(1);
  });

  it('redacts credentials by default, in headers, bodies and URLs alike', async () => {
    const built = await buildEvidenceBundle(source());
    const all = whole(readZip(built.zip));

    expect(all).not.toContain('THIS_IS_A_LIVE_SESSION_TOKEN_9f3a');
    expect(all).not.toContain('SECRETPAYLOAD');
    expect(all).not.toContain('tok_live_SHOULD_NOT_LEAK');
    expect(all).not.toContain('hunter2-DO-NOT-LEAK');
    expect(all).toContain('[REDACTED]');
    expect(built.summary.redacted).toBe(true);

    // Specifically the request line, not just the `# url:` comment above it.
    // The target is origin-form and carries the query, so this is where a
    // credential lands in a bundle that claims to be redacted.
    const files = readZip(built.zip);
    const name = [...files.keys()].find((k) => k.startsWith('exchanges/'));
    const exchange = text(files, name as string);
    expect(exchange).toContain('GET /account?access_token=[REDACTED] HTTP/1.1');
  });

  it('includes raw captures only when asked, and says so everywhere it matters', async () => {
    const built = await buildEvidenceBundle(source(), { includeRawCaptures: true });
    const files = readZip(built.zip);
    const all = whole(files);

    expect(all).toContain('THIS_IS_A_LIVE_SESSION_TOKEN_9f3a');
    expect(built.summary.redacted).toBe(false);
    expect(built.handoff.redacted).toBe(false);
    // A bundle full of live credentials must announce itself in the three
    // places a recipient actually looks.
    expect(text(files, 'README.md')).toContain('RAW CAPTURES');
    expect(text(files, 'HANDOFF.md')).toContain('RAW captures');
    expect(JSON.parse(text(files, 'manifest.json')).redacted).toBe(false);
  });

  it('never carries a secret store, a private key, or a database', async () => {
    const files = readZip((await buildEvidenceBundle(source())).zip);
    for (const name of files.keys()) {
      expect(name).not.toMatch(/secrets|\.key$|\.pem$|\.db(-wal|-shm)?$|\.sqlite3?$/i);
    }
  });

  it('manifests every file with a hash that matches the bytes shipped', async () => {
    const files = readZip((await buildEvidenceBundle(source())).zip);
    const manifest = JSON.parse(text(files, 'manifest.json')) as {
      files: { path: string; sha256: string; bytes: number }[];
    };
    expect(manifest.files.length).toBeGreaterThan(4);
    for (const entry of manifest.files) {
      const actual = files.get(entry.path);
      expect(actual, entry.path).toBeDefined();
      if (!actual) continue;
      expect(createHash('sha256').update(actual).digest('hex'), entry.path).toBe(entry.sha256);
      expect(actual.length, entry.path).toBe(entry.bytes);
    }
    // The manifest cannot hash itself; the bundle hash covers it.
    expect(manifest.files.some((f) => f.path === 'manifest.json')).toBe(false);
  });

  it('reports a bundle hash that matches the file actually written', async () => {
    const built = await buildEvidenceBundle(source());
    const dir = await fs.realpath(await fs.mkdtemp(path.join(os.tmpdir(), 'tacnoc-ev-')));
    try {
      const file = path.join(dir, 'bundle.zip');
      await fs.writeFile(file, built.zip);
      const onDisk = await fs.readFile(file);
      expect(createHash('sha256').update(onDisk).digest('hex')).toBe(built.summary.sha256);
      expect(onDisk.length).toBe(built.summary.sizeBytes);
    } finally {
      await fs.rm(dir, { recursive: true, force: true });
    }
  });

  it('asks for the engine briefing by host, never for the whole project', async () => {
    const asked: (string | undefined)[] = [];
    const built = await buildEvidenceBundle(
      source({
        engineBriefing: (h?: string) => {
          asked.push(h);
          return Promise.resolve(`briefing for ${h}`);
        },
      }),
    );
    // The briefing is free text the bundle cannot police after the fact, so the
    // narrowing has to happen where it is produced. All this module can do —
    // and must do — is say which host it wants.
    expect(asked).toEqual([HOST]);
    expect(built.handoff.engineBriefing).toBe(`briefing for ${HOST}`);
  });

  it('leaves the session log tail out unless the operator asks for it', async () => {
    const off = readZip((await buildEvidenceBundle(source())).zip);
    expect([...off.keys()]).not.toContain('logs/tacnoc.log.jsonl');

    const on = await buildEvidenceBundle(source(), { includeLogs: true });
    expect([...readZip(on.zip).keys()]).toContain('logs/tacnoc.log.jsonl');
    expect(on.summary.logCount).toBe(2);
  });

  it('omits logs and the handoff when they are turned off', async () => {
    const built = await buildEvidenceBundle(source(), {
      includeLogs: false,
      includeHandoff: false,
    });
    const names = [...readZip(built.zip).keys()];
    expect(names).not.toContain('logs/tacnoc.log.jsonl');
    expect(names).not.toContain('HANDOFF.md');
    expect(names).not.toContain('handoff.json');
    expect(built.summary.logCount).toBe(0);
    // The handoff is still computed — a live mesh hand-off needs it without a file.
    expect(built.handoff.target.host).toBe(HOST);
  });
});

/** A single exchange whose response body is exactly these bytes. */
function withResponseBody(body: Buffer, contentEncoding?: string): Partial<BundleSource> {
  const row = summary('ex-1', HOST);
  const response: NonNullable<ExchangeDetail['response']> = {
    statusCode: 200,
    statusMessage: 'OK',
    httpVersion: 'HTTP/1.1',
    headers: [{ name: 'Content-Type', value: 'application/json' }],
    bodyBase64: body.toString('base64'),
    bodySize: body.length,
    bodyTruncated: false,
    truncatedForView: false,
    sensitive: { hasCookies: false, hasAuthorization: false, hasTokens: false, fields: [] },
    ...(contentEncoding ? { contentEncoding } : {}),
  };
  return {
    exchanges: [row],
    exchangesAvailable: 1,
    findings: [],
    detail: () => Promise.resolve({ ...detail(row), response }),
  };
}

const exchangeFile = (files: Map<string, Buffer>): Buffer => {
  const name = [...files.keys()].find((k) => k.startsWith('exchanges/'));
  if (!name) throw new Error(`bundle has no exchange file — has ${[...files.keys()].join(', ')}`);
  return files.get(name) as Buffer;
};

/**
 * What the bundle does with a body it was handed.
 *
 * Captured bodies are stored `Content-Encoding`-compressed, which for real
 * HTTPS traffic means nearly every response. Rendering them as UTF-8 text
 * destroyed them and left the file claiming `REDACTED` over bytes no redactor
 * had been able to read.
 */
describe('evidence bundle bodies', () => {
  it('decompresses a gzip body, so the redaction it claims can actually happen', async () => {
    const payload = '{"session_token":"tok_live_SHOULD_NOT_LEAK","plan":"enterprise"}';
    const built = await buildEvidenceBundle(
      source(withResponseBody(zlib.gzipSync(Buffer.from(payload, 'utf8')), 'gzip')),
    );
    const exchange = exchangeFile(readZip(built.zip)).toString('utf8');

    // The masked value is the proof: the redactor cannot match a pattern in
    // bytes it cannot decode, so a `[REDACTED]` here means the body was read.
    expect(exchange).toContain('"session_token":"[REDACTED]"');
    expect(exchange).toContain('"plan":"enterprise"');
    expect(exchange).not.toContain('tok_live_SHOULD_NOT_LEAK');
    expect(exchange).toContain('response body decompressed from gzip');
  });

  it('says a body could not be decompressed rather than shipping it unread', async () => {
    const built = await buildEvidenceBundle(
      source(withResponseBody(Buffer.from('this is not brotli at all', 'utf8'), 'br')),
    );
    const exchange = exchangeFile(readZip(built.zip)).toString('utf8');

    expect(exchange).toContain('could not be decompressed');
    // Unreadable is unredactable: a bundle labelled REDACTED must not carry
    // bytes nothing inspected, however plausible they look as text.
    expect(exchange).not.toContain('this is not brotli at all');
  });

  it('writes a raw body byte for byte instead of through a lossy UTF-8 decode', async () => {
    const bytes = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0xff, 0xfe, 0x80]);
    const built = await buildEvidenceBundle(source(withResponseBody(bytes)), {
      includeRawCaptures: true,
    });
    // `toString('utf8')` replaces every one of these with U+FFFD, which is a
    // body a triager cannot do anything with — and cannot get back.
    expect(exchangeFile(readZip(built.zip)).includes(bytes)).toBe(true);
  });

  it('caps a raw body at the same size the redacted one is capped at', async () => {
    const built = await buildEvidenceBundle(
      source(withResponseBody(Buffer.alloc(600 * 1024, 0x41))),
      { includeRawCaptures: true },
    );
    const file = exchangeFile(readZip(built.zip));

    // The redacted path has always been capped at 256 KiB; the raw path was
    // bounded only by what `session.ts` reads for viewing, which is 4 MiB.
    expect(file.length).toBeLessThan(300 * 1024);
    expect(file.toString('utf8')).toContain('capped at 262144 byte(s) for this bundle');
  });
});

describe('agent handoff', () => {
  it('states the authorization it was given and does not invent one', async () => {
    const h = (await buildEvidenceBundle(source())).handoff;
    expect(h.authorization.program).toBe('Acme BBP');
    expect(h.authorization.authorizationRef).toBe('H1-12345');
    expect(h.authorization.inScope).toEqual(['exact: acme-corp.test']);
    expect(h.authorization.failClosed).toBe(false);
    expect(h.authorization.targetInScope).toBe(true);
    expect(h.schemaVersion).toBe(1);
    expect(h.engineBriefing).toContain('ENGINE BRIEFING');
  });

  it('leads with a stop condition when the gate would refuse everything', async () => {
    const h = (
      await buildEvidenceBundle(
        source({ scope: { include: [], exclude: [] }, targetInScope: false }),
      )
    ).handoff;
    expect(h.authorization.failClosed).toBe(true);
    expect(h.constraints[0]).toContain('STOP CONDITION');
    expect(h.suggestedObjective).toContain('Do not test');
  });

  it('leads with a stop condition when the target itself is out of scope', async () => {
    const h = (
      await buildEvidenceBundle(source({ scope: scopeWith('other.test'), targetInScope: false }))
    ).handoff;
    expect(h.authorization.failClosed).toBe(false);
    expect(h.constraints[0]).toContain('STOP CONDITION');
    expect(h.constraints[0]).toContain('NOT currently in scope');
  });

  it('always carries the rules of engagement', async () => {
    const h = (await buildEvidenceBundle(source())).handoff;
    const joined = h.constraints.join(' ');
    expect(joined).toContain('fails closed');
    expect(joined).toContain('No fabrication');
    expect(joined).toContain('Minimal proof');
    expect(joined).toContain('Coordinated disclosure');
  });

  it('points each finding at the evidence file that proves it', async () => {
    // Logs are opted into here because they are no longer in a bundle by
    // default; the assertion that the handoff indexes them is unchanged.
    const h = (await buildEvidenceBundle(source(), { includeLogs: true })).handoff;
    expect(h.findings).toHaveLength(1);
    const f = h.findings[0];
    expect(f?.evidenceFile).toMatch(/^exchanges\/0001-/);
    expect(h.evidence.some((e) => e.kind === 'exchange')).toBe(true);
    expect(h.evidence.some((e) => e.kind === 'log')).toBe(true);
  });

  it('derives open questions from the evidence rather than guessing', async () => {
    const h = (await buildEvidenceBundle(source())).handoff;
    const q = h.openQuestions.join(' ');
    // The fixture has an endpoint with `access_token`/`user_id` and a 403.
    expect(q).toContain('identity-');
    const none = (await buildEvidenceBundle(source({ exchanges: [], sites: [], findings: [] })))
      .handoff;
    expect(none.openQuestions.join(' ')).not.toContain('identity-');
  });

  it('reports what was already done, from the audit log', async () => {
    const h = (await buildEvidenceBundle(source())).handoff;
    expect(h.alreadyTried).toContain('job.create ×1');
  });

  it('renders markdown that a reader can act on without the JSON', async () => {
    const md = text(readZip((await buildEvidenceBundle(source())).zip), 'HANDOFF.md');
    expect(md).toContain('# Handoff — acme-corp.test');
    expect(md).toContain('rules of engagement');
    expect(md).toContain('Acme BBP');
    expect(md).toContain('/account');
    expect(md).toContain('Missing Strict-Transport-Security');
    expect(md).toContain('nothing here grants permission');
  });
});
