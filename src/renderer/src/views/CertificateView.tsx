import React, { useEffect, useState } from 'react';
import { api } from '../api.js';
import { useStore } from '../store.js';
import type { CaInfoDto } from '@shared/ipc.js';

export function CertificateView(): JSX.Element {
  const s = useStore();
  const [ca, setCa] = useState<CaInfoDto | null>(null);
  const [acknowledged, setAcknowledged] = useState(false);
  const [savedPath, setSavedPath] = useState<string | null>(null);

  useEffect(() => {
    void api.getCaInfo().then(setCa);
  }, []);

  const save = async (): Promise<void> => {
    const p = await api.saveCaCertificate();
    if (p) {
      setSavedPath(p);
      s.setToast('CA certificate saved.');
    }
  };

  if (!ca) return <div className="empty">Loading CA…</div>;

  return (
    <div className="view">
      <div className="scrolly">
        <div className="card">
          <h3 style={{ marginTop: 0 }}>Project CA certificate</h3>
          <dl className="kv">
            <dt>SHA-256 fingerprint</dt>
            <dd>{ca.fingerprint}</dd>
            <dt>Key protection</dt>
            <dd>{ca.backendName}</dd>
          </dl>

          <div className="danger-box">
            <strong>Warning — trusting this CA is powerful.</strong> Any host whose certificate is
            signed by this CA will be trusted by whatever you install it into. Install it{' '}
            <em>only</em> into the browser/profile you use for this authorized engagement, and
            remove it when you are finished. GreyNOC Belcher never modifies your operating system
            trust store for you.
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
          <button className="primary" disabled={!acknowledged} onClick={save}>
            Save CA certificate to file…
          </button>
          {savedPath && <p className="hint mono">Saved to {savedPath}</p>}
        </div>

        <div className="card">
          <div className="pane-title">Certificate (PEM)</div>
          <pre className="message" style={{ maxHeight: 220 }}>
            {ca.certPem}
          </pre>
        </div>
      </div>
    </div>
  );
}
