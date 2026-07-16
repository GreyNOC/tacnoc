/**
 * Project scope model.
 *
 * Scope is the central safety gate: no automated request generation is allowed
 * against a destination until it is explicitly in scope. The *evaluation* logic
 * lives in `src/engine/scope/scope.ts`; this module holds the shared data
 * types so both the engine and the renderer agree on the shape.
 */

import type { Scheme } from './model.js';

/** How a rule matches the host component. */
export type HostMatchKind =
  | 'exact' // host must equal `host`
  | 'subdomain' // host equals `host` OR ends with "." + host
  | 'wildcard'; // simple glob where "*" matches one label, "**" matches many

export interface ScopeRule {
  id: string;
  /** Human label for the rule. */
  label?: string;
  enabled: boolean;
  hostMatch: HostMatchKind;
  /** Host pattern, e.g. "example.test" or "*.example.test". */
  host: string;
  /** Allowed schemes; empty array means "any scheme". */
  schemes: Scheme[];
  /** Allowed ports; empty array means "any port". */
  ports: number[];
  /**
   * Optional path matcher applied to the request path. When omitted, any path
   * matches. `kind` selects literal-prefix vs. regular-expression matching.
   */
  path?: { kind: 'prefix' | 'regex'; value: string };
}

/**
 * A project's scope. `include` rules add destinations; `exclude` rules remove
 * them. A destination is in scope iff it matches at least one enabled include
 * rule AND no enabled exclude rule. If there are no include rules, nothing is
 * in scope (fail-closed) — this is deliberate.
 */
export interface ScopeConfig {
  include: ScopeRule[];
  exclude: ScopeRule[];
}

export interface ScopeTarget {
  scheme: Scheme;
  host: string;
  port: number;
  path?: string;
}

export interface ScopeDecision {
  inScope: boolean;
  /** Id of the include rule that matched, if any. */
  matchedInclude?: string;
  /** Id of the exclude rule that vetoed, if any. */
  matchedExclude?: string;
  reason: string;
}

export function emptyScope(): ScopeConfig {
  return { include: [], exclude: [] };
}
