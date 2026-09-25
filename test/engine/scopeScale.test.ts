/**
 * Scale regressions for the scope pipeline.
 *
 * A real hunt folder is mostly recon output, and pointing TACNOC at one used to
 * make the app non-responsive and then die: the proposal extracted a candidate
 * for every hostname in every subdomain dump, the Engagement view drew a table
 * row for each, and the gate re-read and re-parsed the whole scope from SQLite
 * on every proxied request while recompiling a RegExp per wildcard rule.
 *
 * These tests pin the bounds and â€” more importantly â€” pin that the bounds never
 * cost the operator a rule in the UNSAFE direction. A dropped exclusion or a
 * stale cached scope silently widens the gate, which is worse than the hang.
 */

import { describe, expect, it } from 'vitest';
import * as os from 'node:os';
import * as path from 'node:path';
import { promises as fs } from 'node:fs';
import * as crypto from 'node:crypto';
import {
  countProposedHosts,
  proposeScope,
  MAX_PROPOSED_CANDIDATES,
  type ProposalSource,
} from '../../src/engine/engagement/scopeProposal.js';
import { evaluateScope } from '../../src/engine/scope/scope.js';
import { buildTargetMap } from '../../src/engine/target/siteMap.js';
import { Database } from '../../src/engine/storage/database.js';
import { MetaRepo } from '../../src/engine/storage/metaRepo.js';
import type { SiteMapHistoryRow } from '../../src/engine/storage/historyRepo.js';
import type { ScopeConfig, ScopeRule } from '../../src/shared/scope.js';

/**
 * A recon dump: one bare hostname per line, no scope wording anywhere.
 *
 * Deliberately under `acme.test`. `target` is one of the classifier's in-scope
 * marker words, so a host under `target.test` makes every line naming it read
 * as in-scope wording â€” which is a real quirk, but not the one under test here.
 */
function reconDump(count: number, prefix = 'h'): ProposalSource {
  const lines = Array.from({ length: count }, (_, i) => `${prefix}${i}.acme.test`);
  return { path: 'recon/subs.txt', content: lines.join('\n') };
}

function rule(partial: Partial<ScopeRule>): ScopeRule {
  return {
    id: partial.id ?? crypto.randomUUID(),
    enabled: partial.enabled ?? true,
    hostMatch: partial.hostMatch ?? 'exact',
    host: partial.host ?? 'example.test',
    schemes: partial.schemes ?? [],
    ports: partial.ports ?? [],
    ...(partial.path ? { path: partial.path } : {}),
  };
}

describe('proposal volume', () => {
  it('caps the candidate list and says how many it left out', () => {
    const proposal = proposeScope([reconDump(MAX_PROPOSED_CANDIDATES + 3000)]);
    const total = proposal.include.length + proposal.exclude.length + proposal.unclear.length;

    expect(total).toBe(MAX_PROPOSED_CANDIDATES);
    expect(proposal.omitted).toBe(3000);
    expect(proposal.truncated).toBe(true);
    // Silently showing a short list is indistinguishable from a small folder.
    expect(proposal.notes.join(' ')).toMatch(/3,000 further host/);
  });

  it('never omits an out-of-scope host, however late in the folder it appears', () => {
    // The cap is long gone by the time this document is reached.
    const proposal = proposeScope([
      reconDump(MAX_PROPOSED_CANDIDATES + 500),
      {
        path: 'policy.md',
        content: '# Out of scope\nprod-payments.acme.test must not be touched.\n',
      },
    ]);

    const excluded = proposal.exclude.map((c) => c.host);
    expect(excluded).toContain('prod-payments.acme.test');
    // And the exclusion is not counted as omitted, because it was not dropped.
    expect(proposal.omitted).toBe(500);
  });

  it('counts hosts exactly without building the candidate list', () => {
    const { count, sample } = countProposedHosts([reconDump(5000)], 8);
    // Exact: a readiness message that understates the folder sends the operator
    // looking in the wrong place.
    expect(count).toBe(5000);
    expect(sample).toHaveLength(8);
    expect(sample[0]).toBe('h0.acme.test');
  });

  it('stops counting a host as omitted once an exclusion admits it', () => {
    // Capped out first as unclear, then admitted later as an exclusion. It IS
    // in the result, so reporting it as omitted would be a false truncation.
    const proposal = proposeScope([
      { path: 'recon/subs.txt', content: 'late.acme.test' },
      reconDump(MAX_PROPOSED_CANDIDATES + 1, 'filler'),
      { path: 'policy.md', content: '# Out of scope\nlate.acme.test\n' },
    ]);

    expect(proposal.exclude.map((c) => c.host)).toContain('late.acme.test');
    expect(proposal.omitted).toBe(MAX_PROPOSED_CANDIDATES + 1 - (MAX_PROPOSED_CANDIDATES - 1));
    expect(proposal.notes.join(' ')).not.toMatch(/late\.acme\.test/);
  });

  it('does not report an out-of-scope host as one the documents call in scope', () => {
    // The callers word this as "your documents name N host(s) as in scope", so
    // folding an excluded host into that number would present a host the
    // operator was told not to touch as an authorized target.
    const policy: ProposalSource = {
      path: 'policy.md',
      content: ['# Out of scope', 'blocked.acme.test', '', '# In scope', 'api.acme.test'].join(
        '\n',
      ),
    };
    const { count, sample, excluded } = countProposedHosts([policy]);

    expect(sample).toContain('api.acme.test');
    expect(sample).not.toContain('blocked.acme.test');
    expect(count).toBe(1);
    expect(excluded).toBe(1);
  });

  it('agrees with the full proposal about how many hosts are offered', () => {
    // The cheap counter and the real extractor must not disagree about what the
    // folder says, or the readiness message contradicts the screen it points at.
    const sources: ProposalSource[] = [
      {
        path: 'policy.md',
        content: [
          '# In scope',
          'api.acme.test',
          'app.acme.test',
          '',
          '# Out of scope',
          'billing.acme.test',
        ].join('\n'),
      },
      { path: 'notes.md', content: 'saw stray.acme.test while poking around' },
    ];
    const proposal = proposeScope(sources);
    const counted = countProposedHosts(sources);

    expect(counted.count).toBe(proposal.include.length + proposal.unclear.length);
    expect(counted.excluded).toBe(proposal.exclude.length);
  });

  it('does not double-count a host repeated across thousands of lines', () => {
    const repeated: ProposalSource = {
      path: 'recon/resolved.txt',
      content: Array.from({ length: 5000 }, () => 'api.acme.test').join('\n'),
    };
    expect(countProposedHosts([repeated]).count).toBe(1);
    expect(proposeScope([repeated]).omitted).toBe(0);
  });
});

describe('scope evaluation caching', () => {
  it('gives the same decisions for wildcard rules as an uncached evaluation', () => {
    const config: ScopeConfig = {
      include: [rule({ hostMatch: 'wildcard', host: '**.acme.test' })],
      exclude: [rule({ hostMatch: 'wildcard', host: '**.internal.acme.test' })],
    };
    const check = (host: string): boolean =>
      evaluateScope(config, { scheme: 'https', host, port: 443 }).inScope;

    // Repeated calls exercise the compiled cache rather than a fresh compile.
    for (let i = 0; i < 3; i += 1) {
      expect(check('api.acme.test')).toBe(true);
      expect(check('a.b.acme.test')).toBe(true);
      expect(check('vpn.internal.acme.test')).toBe(false);
      expect(check('acme.test')).toBe(false);
      expect(check('notacme.test')).toBe(false);
    }
  });

  it('still honours a rule that is toggled off after it was first evaluated', () => {
    // `enabled` is read live off the rule, never captured into the compiled
    // form â€” otherwise disabling a rule would not take effect until a reload.
    const toggled = rule({ host: 'app.acme.test' });
    const config: ScopeConfig = { include: [toggled], exclude: [] };
    const target = { scheme: 'https' as const, host: 'app.acme.test', port: 443 };

    expect(evaluateScope(config, target).inScope).toBe(true);
    toggled.enabled = false;
    expect(evaluateScope(config, target).inScope).toBe(false);
  });

  it('notices a rule appended to a config it has already compiled', () => {
    const config: ScopeConfig = { include: [rule({ host: 'a.acme.test' })], exclude: [] };
    const target = { scheme: 'https' as const, host: 'b.acme.test', port: 443 };

    expect(evaluateScope(config, target).inScope).toBe(false);
    config.include.push(rule({ host: 'b.acme.test' }));
    expect(evaluateScope(config, target).inScope).toBe(true);
  });

  it('treats an uncompilable path regex as never matching, not always matching', () => {
    const config: ScopeConfig = {
      include: [rule({ host: 'app.acme.test', path: { kind: 'regex', value: '([' } })],
      exclude: [],
    };
    expect(
      evaluateScope(config, { scheme: 'https', host: 'app.acme.test', port: 443, path: '/x' })
        .inScope,
    ).toBe(false);
  });
});

describe('scope persistence caching', () => {
  const openDb = async (): Promise<{ meta: MetaRepo; close: () => void; dir: string }> => {
    const dir = path.join(os.tmpdir(), `tacnoc-scope-${crypto.randomBytes(6).toString('hex')}`);
    await fs.mkdir(dir, { recursive: true });
    const db = Database.open(path.join(dir, 'belcher.db'));
    return { meta: new MetaRepo(db), close: () => db.close(), dir };
  };

  it('serves a cached scope but re-reads it after a write', async () => {
    const { meta, close, dir } = await openDb();
    try {
      const first: ScopeConfig = { include: [rule({ host: 'a.acme.test' })], exclude: [] };
      meta.setScope(first);
      expect(meta.getScope().include[0]?.host).toBe('a.acme.test');
      // Same object back while nothing has been written.
      expect(meta.getScope()).toBe(meta.getScope());

      meta.setScope({ include: [rule({ host: 'b.acme.test' })], exclude: [] });
      // A stale read here would leave the gate enforcing the OLD scope â€” in the
      // narrowing direction that is an unauthorized request.
      expect(meta.getScope().include[0]?.host).toBe('b.acme.test');
    } finally {
      close();
      await fs.rm(dir, { recursive: true, force: true });
    }
  });

  it('freezes what it hands out, so no consumer can widen the gate in place', async () => {
    const { meta, close, dir } = await openDb();
    try {
      meta.setScope({ include: [rule({ host: 'a.acme.test', enabled: false })], exclude: [] });
      const scope = meta.getScope();
      const first = scope.include[0]!;

      expect(Object.isFrozen(scope)).toBe(true);
      expect(Object.isFrozen(first)).toBe(true);
      // Every consumer shares this object; an in-place edit would rewrite the
      // gate for all of them without touching the database.
      expect(() => {
        (first as { enabled: boolean }).enabled = true;
      }).toThrow();
      expect(() => scope.include.push(rule({}))).toThrow();
    } finally {
      close();
      await fs.rm(dir, { recursive: true, force: true });
    }
  });
});

describe('target map scope evaluation', () => {
  const row = (id: string, url: string): SiteMapHistoryRow => {
    const parsed = new URL(url);
    return {
      id,
      createdAt: Number(id),
      scheme: parsed.protocol.slice(0, -1) as 'http' | 'https',
      host: parsed.hostname,
      port: Number(parsed.port || 443),
      method: 'GET',
      url,
      statusCode: 200,
      mime: 'application/json',
    };
  };

  it('still decides per endpoint when a rule constrains the path', () => {
    // The per-site hoist must NOT engage here, or /health would be reported as
    // in scope alongside /api.
    const map = buildTargetMap(
      [row('1', 'https://app.acme.test/api/users'), row('2', 'https://app.acme.test/health')],
      {
        include: [rule({ host: 'app.acme.test' })],
        exclude: [rule({ host: 'app.acme.test', path: { kind: 'prefix', value: '/health' } })],
      },
      2,
    );

    const endpoints = map.sites[0]!.endpoints;
    expect(endpoints.find((e) => e.path === '/api/users')?.inScope).toBe(true);
    expect(endpoints.find((e) => e.path === '/health')?.inScope).toBe(false);
  });

  it('agrees with a per-endpoint evaluation when no rule constrains a path', () => {
    const scope: ScopeConfig = {
      include: [rule({ hostMatch: 'wildcard', host: '**.acme.test' })],
      exclude: [rule({ host: 'cdn.acme.test' })],
    };
    const rows = [
      row('1', 'https://app.acme.test/a'),
      row('2', 'https://app.acme.test/b'),
      row('3', 'https://cdn.acme.test/c'),
    ];
    const map = buildTargetMap(rows, scope, rows.length);

    for (const site of map.sites) {
      for (const endpoint of site.endpoints) {
        const direct = evaluateScope(scope, {
          scheme: site.scheme,
          host: site.host,
          port: site.port,
          path: endpoint.path,
        }).inScope;
        expect(endpoint.inScope).toBe(direct);
      }
    }
    expect(map.sites.find((s) => s.host === 'cdn.acme.test')?.endpoints[0]?.inScope).toBe(false);
  });
});
