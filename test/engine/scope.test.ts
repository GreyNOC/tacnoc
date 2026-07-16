import { describe, it, expect } from 'vitest';
import { evaluateScope, isInScope, targetFromUrl } from '../../src/engine/scope/scope.js';
import { emptyScope, type ScopeConfig, type ScopeRule } from '../../src/shared/scope.js';

function rule(partial: Partial<ScopeRule>): ScopeRule {
  return {
    id: partial.id ?? 'r1',
    enabled: partial.enabled ?? true,
    hostMatch: partial.hostMatch ?? 'exact',
    host: partial.host ?? 'example.test',
    schemes: partial.schemes ?? [],
    ports: partial.ports ?? [],
    ...(partial.path ? { path: partial.path } : {}),
    ...(partial.label ? { label: partial.label } : {}),
  };
}

describe('scope evaluation', () => {
  it('fails closed with no include rules', () => {
    const decision = evaluateScope(emptyScope(), {
      scheme: 'https',
      host: 'example.test',
      port: 443,
    });
    expect(decision.inScope).toBe(false);
    expect(decision.reason).toMatch(/fail-closed/i);
  });

  it('matches exact host', () => {
    const cfg: ScopeConfig = { include: [rule({ host: 'app.example.test' })], exclude: [] };
    expect(isInScope(cfg, { scheme: 'https', host: 'app.example.test', port: 443 })).toBe(true);
    expect(isInScope(cfg, { scheme: 'https', host: 'other.example.test', port: 443 })).toBe(false);
  });

  it('matches subdomains but not the wrong parent', () => {
    const cfg: ScopeConfig = {
      include: [rule({ hostMatch: 'subdomain', host: 'example.test' })],
      exclude: [],
    };
    expect(isInScope(cfg, { scheme: 'https', host: 'example.test', port: 443 })).toBe(true);
    expect(isInScope(cfg, { scheme: 'https', host: 'api.example.test', port: 443 })).toBe(true);
    expect(isInScope(cfg, { scheme: 'https', host: 'notexample.test', port: 443 })).toBe(false);
    // guard against suffix-confusion: evil-example.test must NOT match example.test
    expect(isInScope(cfg, { scheme: 'https', host: 'evilexample.test', port: 443 })).toBe(false);
  });

  it('honors wildcard single-label vs multi-label', () => {
    const single: ScopeConfig = {
      include: [rule({ hostMatch: 'wildcard', host: '*.example.test' })],
      exclude: [],
    };
    expect(isInScope(single, { scheme: 'https', host: 'a.example.test', port: 443 })).toBe(true);
    expect(isInScope(single, { scheme: 'https', host: 'a.b.example.test', port: 443 })).toBe(false);

    const multi: ScopeConfig = {
      include: [rule({ hostMatch: 'wildcard', host: '**.example.test' })],
      exclude: [],
    };
    expect(isInScope(multi, { scheme: 'https', host: 'a.b.example.test', port: 443 })).toBe(true);
  });

  it('enforces scheme, port, and path constraints', () => {
    const cfg: ScopeConfig = {
      include: [
        rule({ schemes: ['https'], ports: [443], path: { kind: 'prefix', value: '/api/' } }),
      ],
      exclude: [],
    };
    expect(
      isInScope(cfg, { scheme: 'https', host: 'example.test', port: 443, path: '/api/v1' }),
    ).toBe(true);
    expect(
      isInScope(cfg, { scheme: 'http', host: 'example.test', port: 443, path: '/api/v1' }),
    ).toBe(false);
    expect(
      isInScope(cfg, { scheme: 'https', host: 'example.test', port: 8443, path: '/api/v1' }),
    ).toBe(false);
    expect(
      isInScope(cfg, { scheme: 'https', host: 'example.test', port: 443, path: '/public' }),
    ).toBe(false);
  });

  it('exclude rules veto includes (scope-bypass attempt)', () => {
    const cfg: ScopeConfig = {
      include: [rule({ id: 'inc', hostMatch: 'subdomain', host: 'example.test' })],
      exclude: [rule({ id: 'exc', host: 'admin.example.test' })],
    };
    expect(isInScope(cfg, { scheme: 'https', host: 'api.example.test', port: 443 })).toBe(true);
    const admin = evaluateScope(cfg, { scheme: 'https', host: 'admin.example.test', port: 443 });
    expect(admin.inScope).toBe(false);
    expect(admin.matchedExclude).toBe('exc');
  });

  it('disabled rules do not match', () => {
    const cfg: ScopeConfig = { include: [rule({ enabled: false })], exclude: [] };
    expect(isInScope(cfg, { scheme: 'https', host: 'example.test', port: 443 })).toBe(false);
  });

  it('parses URLs into targets with default ports', () => {
    expect(targetFromUrl('http://h.test/x')).toEqual({
      scheme: 'http',
      host: 'h.test',
      port: 80,
      path: '/x',
    });
    expect(targetFromUrl('https://h.test:8443/x?y=1')?.port).toBe(8443);
    expect(targetFromUrl('ftp://h.test')).toBeNull();
    expect(targetFromUrl('not a url')).toBeNull();
  });
});
