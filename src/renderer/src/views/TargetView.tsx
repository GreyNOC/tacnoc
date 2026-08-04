import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import type { ExchangeDetail } from '@shared/detail.js';
import type { TargetEndpoint, TargetMap, TargetSite } from '@shared/target.js';
import { api } from '../api.js';
import { useStore } from '../store.js';
import { detailToRaw } from './HistoryView.js';
import { MessageViewer } from './MessageViewer.js';
import { statusClass, timeShort } from '../lib/format.js';

export function TargetView(): JSX.Element {
  const store = useStore();
  const [map, setMap] = useState<TargetMap>();
  const [selectedSiteId, setSelectedSiteId] = useState<string>();
  const [selectedEndpointId, setSelectedEndpointId] = useState<string>();
  const [detail, setDetail] = useState<ExchangeDetail>();
  const [search, setSearch] = useState('');
  const [inScopeOnly, setInScopeOnly] = useState(false);
  const [error, setError] = useState<string>();
  const lastLoadedAt = useRef(0);

  const load = useCallback(() => {
    lastLoadedAt.current = Date.now();
    void api
      .getTargetMap()
      .then((next) => {
        setError(undefined);
        setMap(next);
        setSelectedSiteId((current) =>
          current && next.sites.some((site) => site.id === current) ? current : next.sites[0]?.id,
        );
      })
      .catch((caught) => setError(caught instanceof Error ? caught.message : String(caught)));
  }, []);

  useEffect(() => {
    // Debounce bursts of captures, but cap the wait so sustained capture (ticks
    // arriving < 150 ms apart) still refreshes instead of starving the timer.
    const delay = Date.now() - lastLoadedAt.current > 1500 ? 0 : 150;
    const timer = setTimeout(load, delay);
    return () => clearTimeout(timer);
  }, [load, store.exchangeTick]);

  const visibleSites = useMemo(() => {
    const needle = search.trim().toLowerCase();
    return (map?.sites ?? []).filter((site) => {
      if (inScopeOnly && site.inScopeEndpoints === 0) return false;
      if (!needle) return true;
      return (
        site.id.toLowerCase().includes(needle) ||
        site.endpoints.some(
          (endpoint) =>
            endpoint.path.toLowerCase().includes(needle) ||
            endpoint.parameterNames.some((name) => name.toLowerCase().includes(needle)),
        )
      );
    });
  }, [map, search, inScopeOnly]);

  const selectedSite = (map?.sites ?? []).find((site) => site.id === selectedSiteId);
  const visibleEndpoints = useMemo(
    () => filterEndpoints(selectedSite, search, inScopeOnly),
    [selectedSite, search, inScopeOnly],
  );

  useEffect(() => {
    if (selectedEndpointId && visibleEndpoints.some((e) => e.id === selectedEndpointId)) return;
    setSelectedEndpointId(undefined);
    setDetail(undefined);
  }, [selectedEndpointId, visibleEndpoints]);

  const selectEndpoint = (endpoint: TargetEndpoint): void => {
    setSelectedEndpointId(endpoint.id);
    void api
      .getExchangeDetail(endpoint.latestExchangeId)
      .then(setDetail)
      .catch((caught) => setError(caught instanceof Error ? caught.message : String(caught)));
  };

  const endpoints = map?.sites.reduce((sum, site) => sum + site.endpoints.length, 0) ?? 0;

  return (
    <div className="view">
      <div className="toolbar">
        <strong>Target map</strong>
        <input
          value={search}
          onChange={(event) => setSearch(event.target.value)}
          placeholder="Filter host, path, or parameter…"
          style={{ minWidth: 240 }}
        />
        <label className="row" style={{ gap: 4 }}>
          <input
            type="checkbox"
            checked={inScopeOnly}
            onChange={(event) => setInScopeOnly(event.target.checked)}
          />
          in-scope only
        </label>
        <span className="spacer" style={{ flex: 1 }} />
        <span className="hint">
          {map?.sites.length ?? 0} origins · {endpoints} endpoints · {map?.totalExchanges ?? 0}{' '}
          exchanges
        </span>
        <button onClick={load}>Refresh</button>
      </div>

      {error && (
        <div className="danger-box" style={{ margin: 8 }}>
          {error}
        </div>
      )}

      {map?.truncated && (
        <div className="warn-box" style={{ margin: 8 }}>
          This map is based on the newest {map.analyzedExchanges.toLocaleString()} of{' '}
          {map.totalExchanges.toLocaleString()} exchanges. Older traffic was omitted to keep the
          workbench responsive.
        </div>
      )}

      <div className="split v">
        <div className="split target-columns">
          <SiteList
            sites={visibleSites}
            selected={selectedSiteId}
            onSelect={(site) => {
              setSelectedSiteId(site.id);
              setSelectedEndpointId(undefined);
              setDetail(undefined);
            }}
          />
          <EndpointList
            endpoints={visibleEndpoints}
            selected={selectedEndpointId}
            onSelect={selectEndpoint}
          />
        </div>

        <div className="pane">
          <div className="pane-title">
            Latest exchange for endpoint
            <span className="spacer" style={{ flex: 1 }} />
            <button
              disabled={!detail}
              onClick={() => detail && store.seedRepeater(detailToRaw(detail))}
            >
              Send to Repeater →
            </button>
          </div>
          <div className="split h" style={{ flex: 1 }}>
            <MessageViewer
              title="Request"
              message={
                detail
                  ? {
                      headline: `${detail.request.method} ${detail.request.target} ${detail.request.httpVersion}`,
                      ...detail.request,
                    }
                  : undefined
              }
            />
            <MessageViewer
              title="Response"
              message={
                detail?.response
                  ? {
                      headline: `${detail.response.httpVersion} ${detail.response.statusCode} ${detail.response.statusMessage}`,
                      ...detail.response,
                    }
                  : undefined
              }
            />
          </div>
        </div>
      </div>
    </div>
  );
}

function SiteList({
  sites,
  selected,
  onSelect,
}: {
  sites: TargetSite[];
  selected?: string;
  onSelect: (site: TargetSite) => void;
}): JSX.Element {
  return (
    <div className="pane">
      <div className="pane-title">Origins</div>
      <div className="table-wrap">
        <table className="grid">
          <thead>
            <tr>
              <th>Origin</th>
              <th>Paths</th>
              <th>Reqs</th>
            </tr>
          </thead>
          <tbody>
            {sites.map((site) => (
              <tr
                key={site.id}
                className={selected === site.id ? 'selected' : ''}
                onClick={() => onSelect(site)}
              >
                <td className="mono" title={site.id}>
                  {site.id}
                </td>
                <td className="mono">
                  {site.inScopeEndpoints}/{site.endpoints.length}
                </td>
                <td className="mono">{site.requestCount}</td>
              </tr>
            ))}
            {sites.length === 0 && (
              <tr>
                <td colSpan={3} className="empty">
                  No mapped origins.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function EndpointList({
  endpoints,
  selected,
  onSelect,
}: {
  endpoints: TargetEndpoint[];
  selected?: string;
  onSelect: (endpoint: TargetEndpoint) => void;
}): JSX.Element {
  return (
    <div className="pane">
      <div className="pane-title">Endpoints</div>
      <div className="table-wrap">
        <table className="grid">
          <thead>
            <tr>
              <th>Method</th>
              <th>Path</th>
              <th>Parameters</th>
              <th>Status</th>
              <th>MIME</th>
              <th>Seen</th>
              <th>Scope</th>
              <th>Last</th>
            </tr>
          </thead>
          <tbody>
            {endpoints.map((endpoint) => (
              <tr
                key={endpoint.id}
                className={selected === endpoint.id ? 'selected' : ''}
                onClick={() => onSelect(endpoint)}
              >
                <td className="mono">{endpoint.methods.join(', ')}</td>
                <td className="mono" title={endpoint.path}>
                  {endpoint.path}
                </td>
                <td className="mono">{endpoint.parameterNames.join(', ') || '—'}</td>
                <td className={`mono ${statusClass(endpoint.statusCodes.at(-1))}`}>
                  {endpoint.statusCodes.join(', ') || '—'}
                </td>
                <td>{endpoint.mimeTypes.join(', ') || '—'}</td>
                <td className="mono">{endpoint.requestCount}</td>
                <td>
                  <span className={`badge ${endpoint.inScope ? 'scope-in' : 'scope-out'}`}>
                    {endpoint.inScope ? 'in' : 'out'}
                  </span>
                </td>
                <td className="mono">{timeShort(endpoint.lastSeen)}</td>
              </tr>
            ))}
            {endpoints.length === 0 && (
              <tr>
                <td colSpan={8} className="empty">
                  Select an origin or broaden the filter.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function filterEndpoints(
  site: TargetSite | undefined,
  search: string,
  inScopeOnly: boolean,
): TargetEndpoint[] {
  if (!site) return [];
  const needle = search.trim().toLowerCase();
  return site.endpoints.filter((endpoint) => {
    if (inScopeOnly && !endpoint.inScope) return false;
    if (!needle || site.id.toLowerCase().includes(needle)) return true;
    return (
      endpoint.path.toLowerCase().includes(needle) ||
      endpoint.methods.some((method) => method.toLowerCase().includes(needle)) ||
      endpoint.parameterNames.some((name) => name.toLowerCase().includes(needle))
    );
  });
}
