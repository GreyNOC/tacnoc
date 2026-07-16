import React, { useEffect, useState } from 'react';
import { api } from '../api.js';
import { useStore } from '../store.js';
import type { ExtensionManifest, Permission } from '@sdk/api.js';

export function ExtensionsView(): JSX.Element {
  const s = useStore();
  const [exts, setExts] = useState<{ manifest: ExtensionManifest; granted: Permission[] }[]>([]);
  const [transforms, setTransforms] = useState<{ id: string; label: string; category: string }[]>(
    [],
  );
  const [error, setError] = useState<string | null>(null);

  const load = (): void => {
    void api.listExtensions().then(setExts);
    void api.listTransforms().then((t) => setTransforms(t.filter((x) => x.id.startsWith('ext.'))));
  };
  useEffect(load, []);

  const loadExample = async (): Promise<void> => {
    setError(null);
    try {
      await api.loadExampleExtension();
      s.setToast('Example extension loaded.');
      load();
    } catch (e) {
      setError(String(e instanceof Error ? e.message : e));
    }
  };

  return (
    <div className="view">
      <div className="scrolly">
        <div className="card">
          <h3 style={{ marginTop: 0 }}>Extensions</h3>
          <p className="hint">
            Extensions run in a restricted sandbox and receive only the capabilities you approve.
            They cannot access the filesystem, processes, network, or secrets through the SDK. Only
            load extensions you trust.
          </p>
          <button className="primary" onClick={loadExample}>
            Load bundled example (header-hygiene)
          </button>
          {error && <div className="danger-box">{error}</div>}
        </div>

        <div className="card">
          <h3 style={{ marginTop: 0 }}>Loaded</h3>
          {exts.length === 0 && <div className="empty">No extensions loaded.</div>}
          {exts.map((e) => (
            <div key={e.manifest.id} style={{ marginBottom: 10 }}>
              <strong>{e.manifest.name}</strong> <span className="hint">v{e.manifest.version}</span>
              <div className="hint">{e.manifest.description}</div>
              <div>
                {e.granted.map((p) => (
                  <span key={p} className="tag">
                    {p}
                  </span>
                ))}
              </div>
            </div>
          ))}
        </div>

        {transforms.length > 0 && (
          <div className="card">
            <h3 style={{ marginTop: 0 }}>Extension-provided transforms</h3>
            {transforms.map((t) => (
              <span key={t.id} className="tag">
                {t.label}
              </span>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
