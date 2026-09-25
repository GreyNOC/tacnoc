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

/**
 * A rule with everything derivable from it computed ONCE.
 *
 * The per-rule work used to happen inside the matcher, so it ran again for every
 * rule on every evaluation: `normalizeHost(rule.host)` re-canonicalized a
 * constant string, and — far worse — a wildcard rule compiled a brand-new
 * `RegExp` per evaluation. Measured on 10,000 worst-case lookups (a target that
 * matches nothing, so every rule is scanned): 1,000 exact rules cost 601ms,
 * while 1,000 wildcard rules cost 16,074ms. A hunt folder's policy is written in
 * wildcards and `scopeRulesFromProposal` maps every `*.` entry to `wildcard`, so
 * a real engagement landed entirely on that 27x-slower path — on the proxy's
 * per-request code path.
 *
 * `enabled` is deliberately NOT captured here: it is read live off the rule, so
 * toggling a rule takes effect without recompiling.
 */
interface CompiledRule {
  rule: ScopeRule;
  /** `normalizeHost(rule.host)`. */
  normHost: string;
  /** `'.' + normHost`, for the subdomain suffix test. */
  dotHost: string;
  /** Wildcard rules only. Undefined when the pattern failed to compile. */
  glob?: RegExp;
  /** Regex-path rules only. Undefined when the pattern failed to compile. */
  pathRe?: RegExp;
}

interface CompiledScope {
  include: CompiledRule[];
  exclude: CompiledRule[];
  /** Lengths at compile time, so a push/splice on the live arrays is detected. */
  includeLength: number;
  excludeLength: number;
}

function compileRule(rule: ScopeRule): CompiledRule {
  const normHost = normalizeHost(rule.host);
  const compiled: CompiledRule = { rule, normHost, dotHost: '.' + normHost };
  if (rule.hostMatch === 'wildcard') {
    // A pattern that will not compile must NEVER match — the same failure
    // direction the inline `catch` had. Leaving `glob` undefined encodes that.
    try {
      compiled.glob = globToRegExp(rule.host);
    } catch {
      /* leave undefined: never matches */
    }
  }
  if (rule.path && rule.path.kind !== 'prefix') {
    try {
      compiled.pathRe = new RegExp(rule.path.value);
    } catch {
      /* leave undefined: never matches */
    }
  }
  return compiled;
}

/**
 * Compiled forms, keyed by the identity of the config they came from.
 *
 * A `WeakMap` because the cache must not keep a closed project's scope alive,
 * and identity-keyed because a new scope is always a NEW object: `MetaRepo`
 * parses fresh JSON on each write and hands out one frozen object, so the
 * proxy's per-request `getScope()` hits this cache every time.
 *
 * The contract this relies on: a `ScopeConfig` is not edited in place after it
 * has been evaluated. `MetaRepo.getScope()` deep-freezes what it caches, which
 * makes that structurally true for the only config the gate actually consults.
 * The length check below additionally catches a push/splice on an unfrozen
 * config, which is the mutation a caller is most likely to attempt.
 */
const compiledCache = new WeakMap<ScopeConfig, CompiledScope>();

function compile(config: ScopeConfig): CompiledScope {
  const cached = compiledCache.get(config);
  if (
    cached &&
    cached.includeLength === config.include.length &&
    cached.excludeLength === config.exclude.length
  ) {
    return cached;
  }
  const fresh: CompiledScope = {
    include: config.include.map(compileRule),
    exclude: config.exclude.map(compileRule),
    includeLength: config.include.length,
    excludeLength: config.exclude.length,
  };
  compiledCache.set(config, fresh);
  return fresh;
}

function hostMatches(compiled: CompiledRule, host: string): boolean {
  switch (compiled.rule.hostMatch) {
    case 'exact':
      return host === compiled.normHost;
    case 'subdomain':
      return host === compiled.normHost || host.endsWith(compiled.dotHost);
    case 'wildcard':
      // No `g` flag, so `test` carries no lastIndex state and the compiled
      // RegExp is safe to reuse across evaluations.
      return compiled.glob ? compiled.glob.test(host) : false;
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

function pathMatches(compiled: CompiledRule, path: string | undefined): boolean {
  const spec = compiled.rule.path;
  if (!spec) return true;
  const value = path ?? '/';
  if (spec.kind === 'prefix') return value.startsWith(spec.value);
  // An invalid regex must not silently match everything.
  return compiled.pathRe ? compiled.pathRe.test(value) : false;
}

function ruleMatches(compiled: CompiledRule, target: ScopeTarget, host: string): boolean {
  return (
    compiled.rule.enabled &&
    hostMatches(compiled, host) &&
    schemeMatches(compiled.rule, target.scheme) &&
    portMatches(compiled.rule, target.port) &&
    pathMatches(compiled, target.path)
  );
}

export function evaluateScope(config: ScopeConfig, target: ScopeTarget): ScopeDecision {
  const host = normalizeHost(target.host);
  const compiled = compile(config);

  const matchedRuleExclude = compiled.exclude.find((r) => ruleMatches(r, target, host));
  const matchedExclude = matchedRuleExclude?.rule;
  if (matchedExclude) {
    return {
      inScope: false,
      matchedExclude: matchedExclude.id,
      reason: `Excluded by rule "${matchedExclude.label ?? matchedExclude.id}"`,
    };
  }

  const matchedInclude = compiled.include.find((r) => ruleMatches(r, target, host))?.rule;
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
