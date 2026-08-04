/**
 * Scope evaluation — the core safety gate.
 *
 * A destination is IN SCOPE iff it matches at least one enabled `include` rule
 * AND no enabled `exclude` rule. With zero include rules, nothing is in scope
 * (fail-closed). Automated request generation MUST consult this before acting.
 */

import type { ScopeConfig, ScopeDecision, ScopeRule, ScopeTarget } from '../../shared/scope.js';
import type { Scheme } from '../../shared/model.js';

export function normalizeHost(host: string): string {
  // Strip ALL trailing dots (not just one) so the safety gate's canonicalization
  // is exhaustive — a residual dot would let an exclude rule under-match.
  return host.trim().toLowerCase().replace(/\.+$/, '');
}

/** Translate a wildcard host glob into an anchored RegExp. */
function globToRegExp(pattern: string): RegExp {
  const normalized = normalizeHost(pattern);
  let re = '^';
  let i = 0;
  while (i < normalized.length) {
    const c = normalized[i] as string;
    if (c === '*') {
      if (normalized[i + 1] === '*') {
        re += '.+'; // ** = one or more labels (may include dots)
        i += 2;
      } else {
        re += '[^.]+'; // * = exactly one label
        i += 1;
      }
    } else if ('\\^$.|?+()[]{}'.includes(c)) {
      re += '\\' + c;
      i += 1;
    } else {
      re += c;
      i += 1;
    }
  }
  re += '$';
  return new RegExp(re);
}

function hostMatches(rule: ScopeRule, host: string): boolean {
  const ruleHost = normalizeHost(rule.host);
  switch (rule.hostMatch) {
    case 'exact':
      return host === ruleHost;
    case 'subdomain':
      return host === ruleHost || host.endsWith('.' + ruleHost);
    case 'wildcard':
      try {
        return globToRegExp(rule.host).test(host);
      } catch {
        return false;
      }
    default:
      return false;
  }
}

function schemeMatches(rule: ScopeRule, scheme: Scheme): boolean {
  return rule.schemes.length === 0 || rule.schemes.includes(scheme);
}

function portMatches(rule: ScopeRule, port: number): boolean {
  return rule.ports.length === 0 || rule.ports.includes(port);
}

function pathMatches(rule: ScopeRule, path: string | undefined): boolean {
  if (!rule.path) return true;
  const value = path ?? '/';
  if (rule.path.kind === 'prefix') return value.startsWith(rule.path.value);
  try {
    return new RegExp(rule.path.value).test(value);
  } catch {
    return false; // an invalid regex must not silently match everything
  }
}

function ruleMatches(rule: ScopeRule, target: ScopeTarget, host: string): boolean {
  return (
    rule.enabled &&
    hostMatches(rule, host) &&
    schemeMatches(rule, target.scheme) &&
    portMatches(rule, target.port) &&
    pathMatches(rule, target.path)
  );
}

export function evaluateScope(config: ScopeConfig, target: ScopeTarget): ScopeDecision {
  const host = normalizeHost(target.host);

  const matchedExclude = config.exclude.find((r) => ruleMatches(r, target, host));
  if (matchedExclude) {
    return {
      inScope: false,
      matchedExclude: matchedExclude.id,
      reason: `Excluded by rule "${matchedExclude.label ?? matchedExclude.id}"`,
    };
  }

  const matchedInclude = config.include.find((r) => ruleMatches(r, target, host));
  if (matchedInclude) {
    return {
      inScope: true,
      matchedInclude: matchedInclude.id,
      reason: `Included by rule "${matchedInclude.label ?? matchedInclude.id}"`,
    };
  }

  return {
    inScope: false,
    reason:
      config.include.length === 0
        ? 'No include rules defined — scope is empty (fail-closed).'
        : 'No include rule matched this destination.',
  };
}

export function isInScope(config: ScopeConfig, target: ScopeTarget): boolean {
  return evaluateScope(config, target).inScope;
}

/** Parse a URL into a ScopeTarget. Returns null for unparseable/unsupported URLs. */
export function targetFromUrl(url: string): ScopeTarget | null {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return null;
  }
  const scheme = parsed.protocol.replace(':', '');
  if (scheme !== 'http' && scheme !== 'https') return null;
  const port = parsed.port ? Number(parsed.port) : scheme === 'https' ? 443 : 80;
  return { scheme, host: parsed.hostname, port, path: parsed.pathname + parsed.search };
}
