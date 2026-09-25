/** Build a Burp-style target/site map from bounded history metadata. */

import type { Scheme } from '../../shared/model.js';
import type { ScopeConfig } from '../../shared/scope.js';
import type { TargetEndpoint, TargetMap, TargetSite } from '../../shared/target.js';
import { evaluateScope, normalizeHost } from '../scope/scope.js';
import { originForm } from '../proxy/proxyUtil.js';
import type { SiteMapHistoryRow } from '../storage/historyRepo.js';

interface EndpointAccumulator {
  path: string;
  methods: Set<string>;
  statusCodes: Set<number>;
  mimeTypes: Set<string>;
  parameterNames: Set<string>;
  requestCount: number;
  firstSeen: number;
  lastSeen: number;
  latestExchangeId: string;
  /** Latest exchange's origin-form path INCLUDING the query, for scope eval. */
  scopePath: string;
}

interface SiteAccumulator {
  scheme: Scheme;
  host: string;
  port: number;
  requestCount: number;
  firstSeen: number;
  lastSeen: number;
  endpoints: Map<string, EndpointAccumulator>;
}

export function buildTargetMap(
  rows: readonly SiteMapHistoryRow[],
  scope: ScopeConfig,
  totalExchanges: number,
): TargetMap {
  const sites = new Map<string, SiteAccumulator>();

  for (const row of rows) {
    const parsed = parseTarget(row.url);
    // Canonicalize the host exactly as the scope gate does (lowercase + strip
    // ALL trailing dots), so mixed-case AND trailing-dot captures of one origin
    // (e.g. "example.com" and "example.com.") group into a single site instead
    // of splitting — the scope gate treats them as one.
    const host = normalizeHost(row.host);
    const siteId = originId(row.scheme, host, row.port);
    let site = sites.get(siteId);
    if (!site) {
      site = {
        scheme: row.scheme,
        host,
        port: row.port,
        requestCount: 0,
        firstSeen: row.createdAt,
        lastSeen: row.createdAt,
        endpoints: new Map(),
      };
      sites.set(siteId, site);
    }

    site.requestCount += 1;
    site.firstSeen = Math.min(site.firstSeen, row.createdAt);
    site.lastSeen = Math.max(site.lastSeen, row.createdAt);

    // Origin-form path WITH the query string — the exact shape the live scope
    // gate evaluates (proxyServer/variation/repeater all use originForm(url)).
    const scopePath = originForm(row.url);
    let endpoint = site.endpoints.get(parsed.path);
    if (!endpoint) {
      endpoint = {
        path: parsed.path,
        methods: new Set(),
        statusCodes: new Set(),
        mimeTypes: new Set(),
        parameterNames: new Set(),
        requestCount: 0,
        firstSeen: row.createdAt,
        lastSeen: row.createdAt,
        latestExchangeId: row.id,
        scopePath,
      };
      site.endpoints.set(parsed.path, endpoint);
    }

    endpoint.requestCount += 1;
    endpoint.methods.add(row.method.toUpperCase());
    if (row.statusCode !== null) endpoint.statusCodes.add(row.statusCode);
    if (row.mime) endpoint.mimeTypes.add(row.mime);
    for (const name of parsed.parameterNames) endpoint.parameterNames.add(name);
    endpoint.firstSeen = Math.min(endpoint.firstSeen, row.createdAt);
    // Strictly-greater keeps the newest exchange as "latest" regardless of input
    // order: rows arrive newest-first, so a same-millisecond tie must NOT
    // overwrite the first (newest) row's id with an older tied row's id.
    if (row.createdAt > endpoint.lastSeen) {
      endpoint.lastSeen = row.createdAt;
      endpoint.latestExchangeId = row.id;
      endpoint.scopePath = scopePath;
    }
  }

  // Scope was evaluated once per ENDPOINT, and each evaluation scans every rule
  // — so this loop was O(endpoints x rules). Measured at getTargetMap's default
  // of 100,000 exchanges: 14.9s with 1,000 rules and 462s (7.7 minutes) with
  // 30,000, all of it synchronous on the main process, triggered by nothing more
  // than clicking the Target tab.
  //
  // Every endpoint of a site shares that site's scheme, host and port; only the
  // path differs. So when no rule constrains a path at all — the common case,
  // and always the case for rules built from a hunt folder, since
  // `scopeRulesFromProposal` never sets one — the decision is constant across
  // the whole site and can be made once. Otherwise fall back to the per-endpoint
  // call. This calls the same `evaluateScope` with the same inputs, so the gate's
  // answer is unchanged either way.
  const anyPathRule = scope.include.some((r) => r.path) || scope.exclude.some((r) => r.path);

  const resultSites: TargetSite[] = [...sites.entries()].map(([siteId, site]) => {
    const constantInScope = anyPathRule
      ? undefined
      : evaluateScope(scope, {
          scheme: site.scheme,
          host: site.host,
          port: site.port,
          path: '/',
        }).inScope;

    const endpoints: TargetEndpoint[] = [...site.endpoints.values()]
      .map((endpoint) => {
        const inScope =
          constantInScope ??
          evaluateScope(scope, {
            scheme: site.scheme,
            host: site.host,
            port: site.port,
            path: endpoint.scopePath,
          }).inScope;
        return {
          id: `${siteId}${endpoint.path}`,
          path: endpoint.path,
          methods: [...endpoint.methods].sort(),
          statusCodes: [...endpoint.statusCodes].sort((a, b) => a - b),
          mimeTypes: [...endpoint.mimeTypes].sort(),
          parameterNames: [...endpoint.parameterNames].sort(),
          requestCount: endpoint.requestCount,
          firstSeen: endpoint.firstSeen,
          lastSeen: endpoint.lastSeen,
          latestExchangeId: endpoint.latestExchangeId,
          inScope,
        };
      })
      .sort((a, b) => a.path.localeCompare(b.path));

    return {
      id: siteId,
      scheme: site.scheme,
      host: site.host,
      port: site.port,
      requestCount: site.requestCount,
      firstSeen: site.firstSeen,
      lastSeen: site.lastSeen,
      inScopeEndpoints: endpoints.filter((e) => e.inScope).length,
      endpoints,
    };
  });

  resultSites.sort(
    (a, b) => a.host.localeCompare(b.host) || a.port - b.port || a.scheme.localeCompare(b.scheme),
  );

  return {
    generatedAt: Date.now(),
    totalExchanges,
    analyzedExchanges: rows.length,
    truncated: rows.length < totalExchanges,
    sites: resultSites,
  };
}

function parseTarget(url: string): { path: string; parameterNames: string[] } {
  try {
    const parsed = new URL(url);
    return { path: parsed.pathname || '/', parameterNames: queryNames(parsed.search) };
  } catch {
    // Fallback for targets new URL() rejects (e.g. an unbracketed IPv6 authority):
    // recover both the path and the query-parameter names instead of dropping them.
    const [beforeHash = ''] = url.split('#', 1);
    const q = beforeHash.indexOf('?');
    const pathPart = originForm(q === -1 ? beforeHash : beforeHash.slice(0, q));
    const query = q === -1 ? '' : beforeHash.slice(q + 1);
    return { path: pathPart.startsWith('/') ? pathPart : '/', parameterNames: queryNames(query) };
  }
}

/** Distinct, non-empty query-parameter names from a query string (leading '?' optional). */
function queryNames(query: string): string[] {
  const names = new Set<string>();
  new URLSearchParams(query).forEach((_value, name) => {
    if (name) names.add(name);
  });
  return [...names];
}

function originId(scheme: Scheme, host: string, port: number): string {
  return `${scheme}://${host}:${port}`;
}
