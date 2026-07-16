import React, { useState } from 'react';
import { api } from '../api.js';
import { useStore } from '../store.js';

export function Welcome(): JSX.Element {
  const s = useStore();
  const [name, setName] = useState('Engagement');
  const [authRef, setAuthRef] = useState('');
  const [dir, setDir] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const pick = async (): Promise<void> => {
    const d = await api.pickDirectory();
    if (d) setDir(d);
  };

  const create = async (): Promise<void> => {
    if (!dir || !name.trim()) {
      setError('Choose a location and a project name.');
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const info = await api.createProject(dir, name.trim(), authRef.trim() || undefined);
      s.setProject(info);
    } catch (e) {
      setError(String(e instanceof Error ? e.message : e));
    } finally {
      setBusy(false);
    }
  };

  const open = async (): Promise<void> => {
    const d = await api.pickDirectory();
    if (!d) return;
    setBusy(true);
    setError(null);
    try {
      const info = await api.openProject(d);
      s.setProject(info);
    } catch (e) {
      setError(String(e instanceof Error ? e.message : e));
    } finally {
      setBusy(false);
    }
  };

  const importProject = async (): Promise<void> => {
    const d = await api.pickDirectory();
    if (!d) return;
    setBusy(true);
    setError(null);
    try {
      const info = await api.importProjectFromFile(d);
      if (info) s.setProject(info);
    } catch (e) {
      setError(String(e instanceof Error ? e.message : e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="welcome">
      <div className="card">
        <h2 style={{ marginTop: 0 }}>GreyNOC Belcher</h2>
        <p className="hint">
          An extensible web-application security research suite for{' '}
          <strong>authorized testing</strong>. The proxy binds to 127.0.0.1 and nothing is sent to
          external services.
        </p>

        <div className="form-row">
          <label htmlFor="pname">Project name</label>
          <input id="pname" value={name} onChange={(e) => setName(e.target.value)} />
        </div>
        <div className="form-row">
          <label htmlFor="pauth">Authorization reference (optional)</label>
          <input
            id="pauth"
            placeholder="e.g. signed SOW / engagement ID"
            value={authRef}
            onChange={(e) => setAuthRef(e.target.value)}
          />
        </div>
        <div className="form-row">
          <label>Location</label>
          <div className="row">
            <input
              className="grow mono"
              readOnly
              value={dir ?? ''}
              placeholder="Choose a folder…"
            />
            <button onClick={pick}>Browse…</button>
          </div>
        </div>

        {error && <div className="danger-box">{error}</div>}

        <div className="row" style={{ marginTop: 12 }}>
          <button className="primary" onClick={create} disabled={busy}>
            Create project
          </button>
          <button onClick={open} disabled={busy}>
            Open existing…
          </button>
          <button className="ghost" onClick={importProject} disabled={busy}>
            Import export…
          </button>
        </div>
      </div>
    </div>
  );
}
