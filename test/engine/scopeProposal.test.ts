/**
 * Tests for reading scope out of the engagement folder.
 *
 * The direction of error is what matters here. Missing a host costs the
 * operator a moment of typing; proposing an out-of-scope host as in-scope
 * invites an unauthorized request, so those cases carry the weight.
 */

import { describe, expect, it } from 'vitest';
import { proposeScope } from '../../src/engine/engagement/scopeProposal.js';

const doc = (content: string, path = 'program-policy.md') => [{ path, content }];

describe('scope proposal', () => {
  it('reads in-scope hosts under an in-scope heading', () => {
    const p = proposeScope(
      doc(`# Acme Bounty

## In scope
- api.acme-corp.test
- www.acme-corp.test
- *.dev.acme-corp.test
`),
    );
    expect(p.include.map((c) => c.host).sort()).toEqual(
      ['*.dev.acme-corp.test', 'api.acme-corp.test', 'www.acme-corp.test'].sort(),
    );
    expect(p.include.every((c) => c.evidence[0]?.file === 'program-policy.md')).toBe(true);
    expect(p.include.find((c) => c.host.startsWith('*.'))?.wildcard).toBe(true);
  });

  it('never proposes an out-of-scope host as an include', () => {
    const p = proposeScope(
      doc(`## In scope
- api.acme-corp.test

## Out of scope
- corp.acme-corp.test
- legacy.acme-corp.test
`),
    );
    expect(p.include.map((c) => c.host)).toEqual(['api.acme-corp.test']);
    expect(p.exclude.map((c) => c.host).sort()).toEqual([
      'corp.acme-corp.test',
      'legacy.acme-corp.test',
    ]);
  });

  it('lets a line marked out-of-scope override an in-scope section', () => {
    const p = proposeScope(
      doc(`## In scope
- api.acme-corp.test
- billing.acme-corp.test (NOT in scope — do not test)
`),
    );
    expect(p.include.map((c) => c.host)).toEqual(['api.acme-corp.test']);
    expect(p.exclude.map((c) => c.host)).toContain('billing.acme-corp.test');
  });

  it('resolves a host seen as both in and out of scope to EXCLUDE', () => {
    const p = proposeScope([
      { path: 'a.md', content: '## In scope\nshop.acme-corp.test\n' },
      { path: 'b.md', content: '## Out of scope\nshop.acme-corp.test\n' },
    ]);
    expect(p.include).toHaveLength(0);
    expect(p.exclude.map((c) => c.host)).toEqual(['shop.acme-corp.test']);
    expect(p.exclude[0]?.reason).toMatch(/excluded wins/i);
  });

  it('marks hosts with no scope wording nearby as unclear rather than guessing', () => {
    const p = proposeScope(doc('Contact security@acme-corp.test or see status.acme-corp.test\n'));
    expect(p.include).toHaveLength(0);
    expect(p.unclear.map((c) => c.host)).toContain('status.acme-corp.test');
  });

  it('never proposes the bounty platform or common linked domains', () => {
    const p = proposeScope(
      doc(`## In scope
- api.acme-corp.test
- see https://hackerone.com/acme for the policy
- code at github.com/acme
`),
    );
    expect(p.include.map((c) => c.host)).toEqual(['api.acme-corp.test']);
    const all = [...p.include, ...p.exclude, ...p.unclear].map((c) => c.host);
    expect(all).not.toContain('hackerone.com');
    expect(all).not.toContain('github.com');
  });

  it('does not mistake filenames or versions for hosts', () => {
    const p = proposeScope(
      doc(`## In scope
- api.acme-corp.test
See notes.md and report.pdf, built with lib 1.2.3, logo.png
`),
    );
    const all = [...p.include, ...p.unclear].map((c) => c.host);
    expect(all).toEqual(['api.acme-corp.test']);
  });

  it('records the file and line so the operator can verify each candidate', () => {
    const p = proposeScope(doc('## In scope\napi.acme-corp.test\n'));
    const evidence = p.include[0]?.evidence[0];
    expect(evidence?.file).toBe('program-policy.md');
    expect(evidence?.line).toBe(2);
    expect(evidence?.text).toContain('api.acme-corp.test');
  });

  it('says plainly that a proposal is not authorization', () => {
    expect(proposeScope(doc('## In scope\napi.acme-corp.test\n')).notes.join(' ')).toMatch(
      /not authorization/i,
    );
  });

  it('reports honestly when there is nothing to read', () => {
    expect(proposeScope([]).notes.join(' ')).toMatch(/no readable documents/i);
    expect(proposeScope(doc('nothing host-shaped in here at all')).notes.join(' ')).toMatch(
      /no host-shaped text/i,
    );
  });
});
