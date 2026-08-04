import { describe, expect, it } from 'vitest';
import { buildTargetMap } from '../../src/engine/target/siteMap.js';
import type { SiteMapHistoryRow } from '../../src/engine/storage/historyRepo.js';

function row(
  id: string,
  url: string,
  createdAt: number,
  method = 'GET',
  statusCode: number | null = 200,
): SiteMapHistoryRow {
  const parsed = new URL(url);
  return {
    id,
    createdAt,
    scheme: parsed.protocol.slice(0, -1) as 'http' | 'https',
    host: parsed.hostname,
    port: Number(parsed.port || (parsed.protocol === 'https:' ? 443 : 80)),
    method,
    url,
    statusCode,
    mime: 'application/json',
  };
}

describe('target/site map', () => {
  it('groups traffic by origin and normalized path while preserving useful observations', () => {
    const rows = [
      row('old', 'https://app.example.test/api/users?id=1', 10),
      row('new', 'https://app.example.test/api/users?id=2&expand=team', 20, 'POST', 201),
      row('health', 'https://app.example.test/health', 30),
      row('other', 'http://cdn.example.test/asset.js?v=4', 40),
    ];
    const map = buildTargetMap(
      rows,
      {
        include: [
          {
            id: 'app',
            enabled: true,
            hostMatch: 'exact',
            host: 'app.example.test',
            schemes: ['https'],
            ports: [443],
          },
        ],
        exclude: [
          {
            id: 'health',
            enabled: true,
            hostMatch: 'exact',
            host: 'app.example.test',
            schemes: [],
            ports: [],
            path: { kind: 'prefix', value: '/health' },
          },
        ],
      },
      4,
    );

    expect(map.sites).toHaveLength(2);
    const app = map.sites.find((site) => site.host === 'app.example.test')!;
    expect(app.requestCount).toBe(3);
    expect(app.inScopeEndpoints).toBe(1);

    const users = app.endpoints.find((endpoint) => endpoint.path === '/api/users')!;
    expect(users.requestCount).toBe(2);
    expect(users.methods).toEqual(['GET', 'POST']);
    expect(users.statusCodes).toEqual([200, 201]);
    expect(users.parameterNames).toEqual(['expand', 'id']);
    expect(users.latestExchangeId).toBe('new');
    expect(users.inScope).toBe(true);
    expect(app.endpoints.find((endpoint) => endpoint.path === '/health')?.inScope).toBe(false);
  });

  it('reports a bounded metadata scan as truncated', () => {
    const map = buildTargetMap(
      [row('one', 'https://example.test/', 1)],
      { include: [], exclude: [] },
      9,
    );
    expect(map.analyzedExchanges).toBe(1);
    expect(map.totalExchanges).toBe(9);
    expect(map.truncated).toBe(true);
  });

  it('keeps the newest exchange as "latest" when several share a millisecond (DESC input)', () => {
    // Production feeds rows newest-first (ORDER BY created_at DESC, rowid DESC).
    // A same-millisecond tie must not overwrite the newest id with an older one.
    const rows = [
      row('newest', 'https://app.test/api/users?id=3', 100),
      row('mid', 'https://app.test/api/users?id=2', 100),
      row('oldest', 'https://app.test/api/users?id=1', 100),
    ];
    const map = buildTargetMap(rows, { include: [], exclude: [] }, 3);
    const users = map.sites[0]!.endpoints.find((e) => e.path === '/api/users')!;
    expect(users.latestExchangeId).toBe('newest');
    expect(users.requestCount).toBe(3);
  });

  it('recovers path and parameter names from URLs new URL() rejects (unbracketed IPv6)', () => {
    const ipv6: SiteMapHistoryRow = {
      id: 'v6',
      createdAt: 10,
      scheme: 'http',
      host: '::1',
      port: 80,
      method: 'GET',
      url: 'http://::1/admin/panel?token=abc&=skip', // unbracketed IPv6 → new URL throws
      statusCode: 200,
      mime: null,
    };
    const map = buildTargetMap([ipv6], { include: [], exclude: [] }, 1);
    const endpoint = map.sites[0]!.endpoints[0]!;
    expect(endpoint.path).toBe('/admin/panel');
    expect(endpoint.parameterNames).toEqual(['token']); // empty '' name is dropped
  });

  it('groups mixed-case hosts into one origin (host names are case-insensitive)', () => {
    const mk = (id: string, host: string, createdAt: number): SiteMapHistoryRow => ({
      id,
      createdAt,
      scheme: 'https',
      host,
      port: 443,
      method: 'GET',
      url: `https://${host}/x`,
      statusCode: 200,
      mime: null,
    });
    const map = buildTargetMap(
      [mk('u', 'API.Example.Test', 1), mk('l', 'api.example.test', 2)],
      { include: [], exclude: [] },
      2,
    );
    expect(map.sites).toHaveLength(1);
    expect(map.sites[0]!.host).toBe('api.example.test');
    expect(map.sites[0]!.requestCount).toBe(2);
  });

  it('evaluates endpoint scope with the query string, matching the live gate for query-sensitive rules', () => {
    // The live gate evaluates scope against path+query (originForm(url)). A map
    // that scoped on the bare pathname would classify this excluded endpoint as
    // in-scope, misrepresenting the safety boundary the operator reads.
    const map = buildTargetMap(
      [row('x', 'https://app.test/s?action=logout', 5)],
      {
        include: [
          { id: 'i', enabled: true, hostMatch: 'exact', host: 'app.test', schemes: [], ports: [] },
        ],
        exclude: [
          {
            id: 'e',
            enabled: true,
            hostMatch: 'exact',
            host: 'app.test',
            schemes: [],
            ports: [],
            path: { kind: 'regex', value: 'action=logout' },
          },
        ],
      },
      1,
    );
    const endpoint = map.sites[0]!.endpoints.find((e) => e.path === '/s')!;
    expect(endpoint.inScope).toBe(false);
    expect(map.sites[0]!.inScopeEndpoints).toBe(0);
  });

  it('groups a trailing-dot FQDN with its dotless origin (matches scope host canonicalization)', () => {
    const mk = (id: string, host: string, createdAt: number): SiteMapHistoryRow => ({
      id,
      createdAt,
      scheme: 'https',
      host,
      port: 443,
      method: 'GET',
      url: `https://${host}/x`,
      statusCode: 200,
      mime: null,
    });
    const map = buildTargetMap(
      [mk('dotless', 'example.test', 1), mk('dotted', 'example.test.', 2)],
      { include: [], exclude: [] },
      2,
    );
    expect(map.sites).toHaveLength(1);
    expect(map.sites[0]!.host).toBe('example.test');
    expect(map.sites[0]!.requestCount).toBe(2);
  });
});
