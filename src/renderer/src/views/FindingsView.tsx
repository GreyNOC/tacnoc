import React, { useCallback, useEffect, useState } from 'react';
import { api } from '../api.js';
import { useStore } from '../store.js';
import type { Finding } from '@shared/findings.js';

export function FindingsView(): JSX.Element {
  const s = useStore();
  const [findings, setFindings] = useState<Finding[]>([]);
  const [includeSuppressed, setIncludeSuppressed] = useState(false);
  const [selected, setSelected] = useState<Finding | null>(null);
  const [modules, setModules] = useState<{ module: string; version: string }[]>([]);

  const load = useCallback(() => {
    void api.listFindings(includeSuppressed).then(setFindings);
    void api.scannerModules().then(setModules);
  }, [includeSuppressed]);

  useEffect(() => {
    load();
  }, [load, s.findingsCount]);

  const suppress = async (f: Finding, on: boolean): Promise<void> => {
    await api.setFindingSuppressed(f.id, on);
    load();
    s.refreshFindings();
  };

  return (
    <div className="view">
      <div className="toolbar">
        <strong>Passive findings</strong>
        <label className="row" style={{ gap: 4 }}>
          <input
            type="checkbox"
            checked={includeSuppressed}
            onChange={(e) => setIncludeSuppressed(e.target.checked)}
          />
          include suppressed
        </label>
        <span className="spacer" style={{ flex: 1 }} />
        <span className="hint">
          {modules.length} scanner modules · {findings.length} findings
        </span>
      </div>
      <div className="split h" style={{ flex: 1 }}>
        <div className="pane">
          <div className="table-wrap">
            <table className="grid">
              <thead>
                <tr>
                  <th>Sev</th>
                  <th>Title</th>
                  <th>Confidence</th>
                  <th>Module</th>
                </tr>
              </thead>
              <tbody>
                {findings.map((f) => (
                  <tr
                    key={f.id}
                    className={selected?.id === f.id ? 'selected' : ''}
                    onClick={() => setSelected(f)}
                    style={{ opacity: f.suppressed ? 0.5 : 1 }}
                  >
                    <td>
                      <span className={`sev ${f.severity}`}>{f.severity}</span>
                    </td>
                    <td>{f.title}</td>
                    <td>{f.confidence}</td>
                    <td className="mono">{f.module}</td>
                  </tr>
                ))}
                {findings.length === 0 && (
                  <tr>
                    <td colSpan={4} className="empty">
                      No findings yet. Capture some traffic — the passive scanner runs
                      automatically.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
        <div className="pane">
          <div className="pane-title">Detail</div>
          <div className="scrolly">
            {!selected && <div className="empty">Select a finding.</div>}
            {selected && (
              <div>
                <h3 style={{ marginTop: 0 }}>
                  <span className={`sev ${selected.severity}`}>{selected.severity}</span>{' '}
                  {selected.title}
                </h3>
                <dl className="kv">
                  <dt>Confidence</dt>
                  <dd>{selected.confidence}</dd>
                  <dt>Module</dt>
                  <dd>
                    {selected.module} v{selected.moduleVersion}
                  </dd>
                  <dt>Exchange</dt>
                  <dd>{selected.exchangeId}</dd>
                  <dt>Dedupe key</dt>
                  <dd>{selected.dedupeKey}</dd>
                </dl>
                <h4>Description</h4>
                <p>{selected.description}</p>
                <h4>Remediation</h4>
                <p>{selected.remediation}</p>
                <h4>Evidence (redacted)</h4>
                {selected.evidence.map((e, i) => (
                  <pre key={i} className="message" style={{ maxHeight: 120 }}>
                    [{e.location}] {e.field ? `${e.field}: ` : ''}
                    {e.excerpt}
                  </pre>
                ))}
                <div className="row" style={{ marginTop: 10 }}>
                  <button onClick={() => suppress(selected, !selected.suppressed)}>
                    {selected.suppressed ? 'Un-suppress' : 'Suppress (false positive)'}
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
