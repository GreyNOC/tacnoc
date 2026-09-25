import React, { useEffect, useMemo, useState } from 'react';
import { api } from '../api.js';
import { useStore } from '../store.js';
import type { ScopeConfig, ScopeRule, HostMatchKind } from '@shared/scope.js';

/**
 * Rules drawn per bucket before "Show more".
 *
 * Both lists always render — there is no tab or collapse — so an engagement
 * adopted from a hunt folder paid for every include AND every exclude at once.
 * Measured at 50,000 rules: 800,034 DOM nodes and 8.3s of blocked renderer,
 * which is a second freeze the operator hits immediately after surviving the
 * first one, just by clicking Scope in the sidebar.
 */
const RULE_PAGE = 200;

function newRule(): ScopeRule {
  return {
    id: crypto.randomUUID(),
    enabled: true,
    // 'exact', not 'subdomain'. Typing an apex host and getting every subdomain
    // at any depth silently grants more than the operator asked for, and scope
    // is the boundary that decides whether a request is authorized. Widening is
    // one dropdown away and should be a deliberate act.
    hostMatch: 'exact',
    host: '',
    schemes: [],
    ports: [],
  };
}

export function ScopeView(): JSX.Element {
  const s = useStore();
  const setToast = s.setToast;
  const [scope, setScope] = useState<ScopeConfig>({ include: [], exclude: [] });
  const [draft, setDraft] = useState<ScopeRule>(newRule());
  // The ports box is text while it is being typed ("8443," mid-entry parses to
  // one port); `draft.ports` holds the parsed truth that gets saved.
  const [portsText, setPortsText] = useState('');
  const [list, setList] = useState<'include' | 'exclude'>('include');
  /** Host filter, applied to the WHOLE bucket — not just the rendered page. */
  const [filter, setFilter] = useState('');
  const [shown, setShown] = useState<Record<'include' | 'exclude', number>>({
    include: RULE_PAGE,
    exclude: RULE_PAGE,
  });

  // Filter first, THEN page. Searching only the rendered rows would leave this
  // screen unable to answer "is this host in my scope?" on a large engagement —
  // and this view is the only place an operator can audit the gate.
  const filtered = useMemo(() => {
    const needle = filter.trim().toLowerCase();
    if (!needle) return scope;
    const match = (r: ScopeRule): boolean => r.host.toLowerCase().includes(needle);
    return { include: scope.include.filter(match), exclude: scope.exclude.filter(match) };
  }, [scope, filter]);

  useEffect(() => {
    // Surface a load failure instead of silently rendering an empty scope — an
    // empty list here is otherwise indistinguishable from "scope was reset".
    void api
      .getScope()
      .then(setScope)
      .catch((err) =>
        setToast(`Could not load scope: ${err instanceof Error ? err.message : String(err)}`),
      );
    // Re-sync if scope changes anywhere else (import, another surface, tests).
    return api.onEvent((e) => {
      if (e.type === 'scope-changed') setScope(e.payload);
    });
  }, [setToast]);

  const persist = async (next: ScopeConfig): Promise<void> => {
    const prev = scope;
    setScope(next); // optimistic
    try {
      await api.setScope(next);
    } catch (err) {
      // The write failed — roll the UI back to what is actually persisted so a
      // failed save can never masquerade as an accepted-then-reset rule.
      setScope(prev);
      setToast(`Could not save scope: ${err instanceof Error ? err.message : String(err)}`);
    }
  };

  const addRule = async (): Promise<void> => {
    if (!draft.host.trim()) {
      s.setToast('Enter a host pattern.');
      return;
    }
    const next: ScopeConfig = {
      include: list === 'include' ? [...scope.include, draft] : scope.include,
      exclude: list === 'exclude' ? [...scope.exclude, draft] : scope.exclude,
    };
    await persist(next);
    setDraft(newRule());
    setPortsText('');
  };

  const removeRule = async (bucket: 'include' | 'exclude', id: string): Promise<void> => {
    await persist({ ...scope, [bucket]: scope[bucket].filter((r) => r.id !== id) });
  };

  const toggleRule = async (bucket: 'include' | 'exclude', id: string): Promise<void> => {
    await persist({
      ...scope,
      [bucket]: scope[bucket].map((r) => (r.id === id ? { ...r, enabled: !r.enabled } : r)),
    });
  };

  const renderList = (bucket: 'include' | 'exclude'): JSX.Element => {
    const matches = filtered[bucket];
    const page = matches.slice(0, shown[bucket]);
    const total = scope[bucket].length;
    return (
      <>
        <div className="row" style={{ gap: 8, flexWrap: 'wrap', marginBottom: 6 }}>
          <span className="hint">
            Showing {page.length.toLocaleString()} of {matches.length.toLocaleString()}
            {filter.trim() ? ` matching (${total.toLocaleString()} total)` : ''} rule(s)
          </span>
          {page.length < matches.length && (
            <button
              className="ghost"
              onClick={() => setShown((s) => ({ ...s, [bucket]: s[bucket] + RULE_PAGE }))}
            >
              Show {RULE_PAGE} more
            </button>
          )}
        </div>
        <table className="grid">
          <thead>
            <tr>
              <th>On</th>
              <th>Match</th>
              <th>Host</th>
              <th>Schemes</th>
              <th>Ports</th>
              <th>Path</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {page.map((r) => (
              <tr key={r.id}>
                <td>
                  <input
                    type="checkbox"
                    checked={r.enabled}
                    onChange={() => toggleRule(bucket, r.id)}
                  />
                </td>
                <td>{r.hostMatch}</td>
                <td className="mono">{r.host}</td>
                <td>{r.schemes.join(', ') || 'any'}</td>
                <td>{r.ports.join(', ') || 'any'}</td>
                <td className="mono">{r.path ? `${r.path.kind}:${r.path.value}` : 'any'}</td>
                <td>
                  <button className="ghost" onClick={() => removeRule(bucket, r.id)}>
                    ✕
                  </button>
                </td>
              </tr>
            ))}
            {total === 0 && (
              <tr>
                <td colSpan={7} className="empty">
                  No {bucket} rules.
                </td>
              </tr>
            )}
            {total > 0 && matches.length === 0 && (
              <tr>
                <td colSpan={7} className="empty">
                  No {bucket} rule matches “{filter.trim()}”.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </>
    );
  };

  return (
    <div className="view">
      <div className="scrolly">
        <div className="warn-box">
          Scope is fail-closed: with no include rules, nothing is in scope and automated request
          generation is blocked. Add hosts you are <strong>authorized</strong> to test.
          {scope.include.length === 0 && (
            <>
              {' '}
              If your program policy or scope document is in the engagement folder,{' '}
              <a
                href="#engagement"
                onClick={(e) => {
                  e.preventDefault();
                  s.setView('engagement');
                }}
              >
                Engagement → Proposed scope
              </a>{' '}
              reads the hosts out of it — with the line each came from — so you can tick and add
              them instead of retyping the list.
            </>
          )}
        </div>

        <div className="card">
          <h3 style={{ marginTop: 0 }}>Add rule</h3>
          <div className="row" style={{ flexWrap: 'wrap', gap: 8 }}>
            <select value={list} onChange={(e) => setList(e.target.value as 'include' | 'exclude')}>
              <option value="include">include</option>
              <option value="exclude">exclude</option>
            </select>
            <select
              value={draft.hostMatch}
              onChange={(e) => setDraft({ ...draft, hostMatch: e.target.value as HostMatchKind })}
            >
              <option value="exact">exact</option>
              <option value="subdomain">subdomain</option>
              <option value="wildcard">wildcard</option>
            </select>
            <input
              placeholder="host e.g. example.test or *.example.test"
              style={{ width: 260 }}
              value={draft.host}
              onChange={(e) => setDraft({ ...draft, host: e.target.value })}
            />
            {/*
              Every field here is CONTROLLED off `draft`.

              Ports, scheme, and path were uncontrolled inputs, so adding a rule
              reset the draft while the boxes kept displaying what had just been
              typed. The next rule was then saved with no port, no scheme, and no
              path restriction while the screen still showed all three — a scope
              rule strictly WIDER than the one the operator was looking at. In a
              fail-closed scope gate, the displayed rule and the stored rule have
              to be the same rule.
            */}
            <input
              placeholder="ports (comma) — blank = any"
              style={{ width: 160 }}
              value={portsText}
              onChange={(e) => {
                setPortsText(e.target.value);
                setDraft({
                  ...draft,
                  ports: e.target.value
                    .split(',')
                    .map((x) => Number(x.trim()))
                    .filter((n) => Number.isFinite(n)),
                });
              }}
            />
            <select
              aria-label="Scheme"
              value={draft.schemes[0] ?? ''}
              onChange={(e) =>
                setDraft({
                  ...draft,
                  schemes: e.target.value ? [e.target.value as 'http' | 'https'] : [],
                })
              }
            >
              <option value="">any scheme</option>
              <option value="http">http</option>
              <option value="https">https</option>
            </select>
            <input
              placeholder="path prefix (optional)"
              style={{ width: 180 }}
              value={draft.path?.value ?? ''}
              onChange={(e) =>
                setDraft({
                  ...draft,
                  path: e.target.value ? { kind: 'prefix', value: e.target.value } : undefined,
                })
              }
            />
            <button className="primary" onClick={addRule}>
              Add
            </button>
          </div>
        </div>

        <div className="card">
          <div className="row" style={{ gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
            <h3 style={{ margin: 0 }}>Include rules</h3>
            <input
              placeholder="filter by host…"
              style={{ width: 220 }}
              aria-label="Filter rules by host"
              value={filter}
              onChange={(e) => {
                setFilter(e.target.value);
                setShown({ include: RULE_PAGE, exclude: RULE_PAGE });
              }}
            />
          </div>
          {renderList('include')}
        </div>
        <div className="card">
          <h3 style={{ marginTop: 0 }}>Exclude rules</h3>
          {renderList('exclude')}
        </div>
      </div>
    </div>
  );
}
