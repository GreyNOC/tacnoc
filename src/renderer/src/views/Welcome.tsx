import React, { useState } from 'react';
import { api } from '../api.js';
import { useStore } from '../store.js';
import { OwlMark } from '../components/OwlMark.js';

export function Welcome(): JSX.Element {
  const s = useStore();
  const [name, setName] = useState('Engagement');
  const [authRef, setAuthRef] = useState('');
  const [dir, setDir] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [adopted, setAdopted] = useState<string | null>(null);

  /**
   * Adopt a folder that already holds the engagement.
   *
   * The normal case in real work: the program policy, the brief, prior reports,
   * and a `recon/` directory all exist before anyone opens a proxy. This creates
   * the project inside that folder and points the engagement folder at it, so the
   * material is usable immediately instead of after a manual re-pointing step.
   *
   * Picking the folder IS the egress decision, which is why the button says so.
   */
  const adopt = async (): Promise<void> => {
    const d = await api.pickHuntFolder();
    if (!d) return;
    setBusy(true);
    setError(null);
    setAdopted(null);
    try {
      const res = await api.adoptHuntFolder(
        d,
        name.trim() || undefined,
        authRef.trim() || undefined,
      );
      const k = res.scan.byKind;
      setAdopted(
        `${res.created ? 'Created a project in' : 'Opened the project in'} ${res.projectDirectory}. ` +
          `Read ${res.scan.filesRead} of ${res.scan.filesSeen} document(s) — ` +
          `${k.scope} scope, ${k.engagement} engagement, ${k.report} report, ${k.recon} recon. ` +
          'Check Engagement → Proposed scope before testing anything.',
      );
      s.setProject(res.info);
    } catch (e) {
      setError(String(e instanceof Error ? e.message : e));
    } finally {
      setBusy(false);
    }
  };

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
        <div className="brand-hero">
          <OwlMark className="brand-hero-mark" title="GreyNOC" />
          <h2>TACNOC</h2>
        </div>
        <p className="hint">
          An extensible web-application security research suite for{' '}
          <strong>authorized testing</strong>. The proxy binds to 127.0.0.1, and nothing leaves the
          machine unless you turn the AI mesh on — which is off by default and sends captured
          traffic and your engagement folder to the model provider when enabled.
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
        {adopted && <div className="warn-box">{adopted}</div>}

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

        <hr style={{ margin: '16px 0', border: 0, borderTop: '1px solid var(--border)' }} />

        <h3 style={{ margin: '0 0 6px' }}>Already have a hunt folder?</h3>
        <p className="hint" style={{ marginTop: 0 }}>
          Point TACNOC at a folder that already holds the engagement — the program policy, the
          brief, prior reports, <span className="mono">recon/</span> output, your notes. It creates
          the project inside that folder, reads what is there, and tells you which files carry the
          scope. Nothing is added to scope automatically; you still tick each host.
        </p>
        <p className="hint" style={{ marginTop: 0 }}>
          <strong>Choosing the folder is the egress decision.</strong> Everything readable in it
          becomes available to the AI and is sent to the model provider during a run — so pick a
          folder you are willing to expose. Leave the mesh off and nothing leaves the machine.
        </p>
        <button onClick={adopt} disabled={busy}>
          Open hunt folder…
        </button>
      </div>
    </div>
  );
}
