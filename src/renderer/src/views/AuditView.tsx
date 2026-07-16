import React, { useEffect, useState } from 'react';
import { api } from '../api.js';
import { useStore } from '../store.js';
import type { AuditEntry } from '@shared/project.js';
import { timeShort } from '../lib/format.js';

export function AuditView(): JSX.Element {
  const s = useStore();
  const [entries, setEntries] = useState<AuditEntry[]>([]);

  const load = (): void => {
    void api.listAudit(1000).then(setEntries);
  };
  useEffect(load, [s.jobs]);

  return (
    <div className="view">
      <div className="toolbar">
        <strong>Audit log</strong>
        <span className="hint">every automated action is recorded here (secrets redacted)</span>
        <span className="spacer" style={{ flex: 1 }} />
        <button className="ghost" onClick={load}>
          Refresh
        </button>
      </div>
      <div className="table-wrap">
        <table className="grid">
          <thead>
            <tr>
              <th>Time</th>
              <th>Actor</th>
              <th>Action</th>
              <th>Target</th>
              <th>Detail</th>
            </tr>
          </thead>
          <tbody>
            {entries.map((e) => (
              <tr key={e.id}>
                <td className="mono">{timeShort(e.ts)}</td>
                <td>{e.actor}</td>
                <td className="mono">{e.action}</td>
                <td className="mono">{e.target ?? ''}</td>
                <td className="mono">{e.detail ? JSON.stringify(e.detail) : ''}</td>
              </tr>
            ))}
            {entries.length === 0 && (
              <tr>
                <td colSpan={5} className="empty">
                  No automated actions yet.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
