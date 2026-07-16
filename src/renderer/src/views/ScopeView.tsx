import React, { useEffect, useState } from 'react';
import { api } from '../api.js';
import { useStore } from '../store.js';
import type { ScopeConfig, ScopeRule, HostMatchKind } from '@shared/scope.js';

function newRule(): ScopeRule {
  return {
    id: crypto.randomUUID(),
    enabled: true,
    hostMatch: 'subdomain',
    host: '',
    schemes: [],
    ports: [],
  };
}

export function ScopeView(): JSX.Element {
  const s = useStore();
  const [scope, setScope] = useState<ScopeConfig>({ include: [], exclude: [] });
  const [draft, setDraft] = useState<ScopeRule>(newRule());
  const [list, setList] = useState<'include' | 'exclude'>('include');

  useEffect(() => {
    void api.getScope().then(setScope);
  }, []);

  const persist = async (next: ScopeConfig): Promise<void> => {
    setScope(next);
    await api.setScope(next);
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

  const renderList = (bucket: 'include' | 'exclude'): JSX.Element => (
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
        {scope[bucket].map((r) => (
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
        {scope[bucket].length === 0 && (
          <tr>
            <td colSpan={7} className="empty">
              No {bucket} rules.
            </td>
          </tr>
        )}
      </tbody>
    </table>
  );

  return (
    <div className="view">
      <div className="scrolly">
        <div className="warn-box">
          Scope is fail-closed: with no include rules, nothing is in scope and automated request
          generation is blocked. Add hosts you are <strong>authorized</strong> to test.
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
            <input
              placeholder="ports (comma) — blank = any"
              style={{ width: 160 }}
              onChange={(e) =>
                setDraft({
                  ...draft,
                  ports: e.target.value
                    .split(',')
                    .map((x) => Number(x.trim()))
                    .filter((n) => Number.isFinite(n)),
                })
              }
            />
            <select
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
          <h3 style={{ marginTop: 0 }}>Include rules</h3>
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
