import React, { useEffect, useState } from 'react';
import { api } from '../api.js';
import type { JwtInspection } from '@engine/transforms/codec.js';

export function EncoderView(): JSX.Element {
  const [transforms, setTransforms] = useState<{ id: string; label: string; category: string }[]>(
    [],
  );
  const [transform, setTransform] = useState('base64.encode');
  const [input, setInput] = useState('');
  const [output, setOutput] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [jwt, setJwt] = useState('');
  const [jwtInfo, setJwtInfo] = useState<JwtInspection | null>(null);

  useEffect(() => {
    void api.listTransforms().then(setTransforms);
  }, []);

  const run = async (): Promise<void> => {
    setError(null);
    try {
      setOutput(await api.applyTransform(transform, input));
    } catch (e) {
      setError(String(e instanceof Error ? e.message : e));
      setOutput('');
    }
  };

  const inspect = async (): Promise<void> => {
    try {
      setJwtInfo(await api.inspectJwt(jwt));
    } catch (e) {
      setError(String(e));
    }
  };

  return (
    <div className="view">
      <div className="scrolly">
        <div className="card">
          <h3 style={{ marginTop: 0 }}>Encoder / Decoder</h3>
          <div className="row" style={{ marginBottom: 8 }}>
            <select
              value={transform}
              onChange={(e) => setTransform(e.target.value)}
              style={{ width: 260 }}
            >
              {['encode', 'decode', 'hash', 'compress', 'inspect', 'other'].map((cat) => {
                const items = transforms.filter((t) => t.category === cat);
                if (items.length === 0) return null;
                return (
                  <optgroup key={cat} label={cat}>
                    {items.map((t) => (
                      <option key={t.id} value={t.id}>
                        {t.label}
                      </option>
                    ))}
                  </optgroup>
                );
              })}
            </select>
            <button className="primary" onClick={run}>
              Apply →
            </button>
          </div>
          <div className="split h" style={{ height: 220, background: 'var(--border)' }}>
            <div className="pane">
              <div className="pane-title">Input</div>
              <textarea
                style={{ flex: 1, border: 'none' }}
                value={input}
                onChange={(e) => setInput(e.target.value)}
              />
            </div>
            <div className="pane">
              <div className="pane-title">Output</div>
              <textarea style={{ flex: 1, border: 'none' }} readOnly value={output} />
            </div>
          </div>
          {error && <div className="danger-box">{error}</div>}
        </div>

        <div className="card">
          <h3 style={{ marginTop: 0 }}>JWT inspector</h3>
          <small className="hint">
            Decodes header + payload for inspection only. The signature is never verified or
            altered.
          </small>
          <div className="row" style={{ margin: '8px 0' }}>
            <input
              className="grow mono"
              placeholder="paste a JWT"
              value={jwt}
              onChange={(e) => setJwt(e.target.value)}
            />
            <button onClick={inspect}>Inspect</button>
          </div>
          {jwtInfo && (
            <div className="split h" style={{ height: 180, background: 'var(--border)' }}>
              <div className="pane">
                <div className="pane-title">Header</div>
                <pre className="message">{JSON.stringify(jwtInfo.header, null, 2)}</pre>
              </div>
              <div className="pane">
                <div className="pane-title">Payload</div>
                <pre className="message">{JSON.stringify(jwtInfo.payload, null, 2)}</pre>
              </div>
            </div>
          )}
          {jwtInfo && <small className="hint">{jwtInfo.note}</small>}
        </div>
      </div>
    </div>
  );
}
