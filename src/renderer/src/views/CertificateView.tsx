import React, { useEffect, useState } from 'react';
import { api } from '../api.js';
import { useStore } from '../store.js';
import type { CaInfoDto } from '@shared/ipc.js';

export function CertificateView(): JSX.Element {
  const s = useStore();
  const [ca, setCa] = useState<CaInfoDto | null>(null);
  const [acknowledged, setAcknowledged] = useState(false);
  const [savedPath, setSavedPath] = useState<string | null>(null);

  // Re-read on 'ca-changed'. The CA can be replaced or destroyed from outside
  // this view — Engagement rotates and revokes it, and the mesh can too when
  // cert ops are granted. Without this the page kept presenting a fingerprint
  // and a PEM for a certificate that no longer existed.
  useEffect(() => {
    void api.getCaInfo().then(setCa);
    return api.onEvent((e) => {
      if (e.type === 'ca-changed') void api.getCaInfo().then(setCa);
    });
  }, []);

  const save = async (): Promise<void> => {
    try {
      const p = await api.saveCaCertificate();
      if (p) {
        setSavedPath(p);
        s.setToast('CA certificate saved.');
      }
    } catch (err) {
      // The main process refuses to write a 0-byte .crt for a revoked CA. That
      // rejection used to go nowhere: the click produced an unhandled rejection
      // and no visible response at all, which reads as "saved".
      s.setToast(
        `Could not save the CA certificate: ${err instanceof Error ? err.message : String(err)}`,
      );
    }
  };

  if (!ca) return <div className="empty">Loading CA…</div>;

  // A revoked project has no certificate. Say so where the fingerprint would be,
  // rather than rendering an empty PEM pane under an enabled Save button.
  const revoked = !ca.certPem;

  return (
    <div className="view">
      <div className="scrolly">
        <div className="card">
          <h3 style={{ marginTop: 0 }}>Project CA certificate</h3>
          <dl className="kv">
            <dt>SHA-256 fingerprint</dt>
            <dd>{revoked ? 'none — this project’s CA was revoked' : ca.fingerprint}</dd>
            <dt>Key protection</dt>
            <dd>{ca.backendName}</dd>
          </dl>

          {revoked && (
            <div className="danger-box">
              <strong>This project has no CA.</strong> It was revoked, so HTTPS tunnels pass through
              unread and there is nothing to install or save. Issue a new CA from{' '}
              <a
                href="#engagement"
                onClick={(e) => {
                  e.preventDefault();
                  s.setView('engagement');
                }}
              >
                Engagement → Interception certificate
              </a>
              , then install it in your test browser.
            </div>
          )}

          <div className="danger-box">
            <strong>Warning — trusting this CA is powerful.</strong> Any host whose certificate is
            signed by this CA will be trusted by whatever you install it into. Install it{' '}
            <em>only</em> into the browser/profile you use for this authorized engagement, and
            remove it when you are finished. TACNOC never modifies your operating system trust store
            for you.
          </div>

          <div className="warn-box">
            <strong>How to trust it (manual):</strong>
            <div style={{ marginTop: 6 }}>{ca.installInstructions}</div>
          </div>

          <label className="row" style={{ gap: 6, margin: '10px 0' }}>
            <input
              type="checkbox"
              checked={acknowledged}
              onChange={(e) => setAcknowledged(e.target.checked)}
            />
            I understand the risk and am authorized to intercept traffic in this environment.
          </label>
          <button className="primary" disabled={!acknowledged || revoked} onClick={save}>
            Save CA certificate to file…
          </button>
          {savedPath && <p className="hint mono">Saved to {savedPath}</p>}
        </div>

        {!revoked && (
          <div className="card">
            <div className="pane-title">Certificate (PEM)</div>
            <pre className="message" style={{ maxHeight: 220 }}>
              {ca.certPem}
            </pre>
          </div>
        )}
      </div>
    </div>
  );
}
