import React, { useState } from 'react';
import { api } from '../api.js';
import { textToB64 } from '../lib/format.js';
import type { LineDiff, JsonDiffEntry, ByteDiff } from '@engine/compare/compare.js';

type Mode = 'text' | 'json' | 'bytes';

export function CompareView(): JSX.Element {
  const [left, setLeft] = useState('');
  const [right, setRight] = useState('');
  const [mode, setMode] = useState<Mode>('text');
  const [lines, setLines] = useState<LineDiff[] | null>(null);
  const [json, setJson] = useState<JsonDiffEntry[] | null>(null);
  const [bytes, setBytes] = useState<ByteDiff | null>(null);
  const [error, setError] = useState<string | null>(null);

  const run = async (): Promise<void> => {
    setError(null);
    setLines(null);
    setJson(null);
    setBytes(null);
    try {
      if (mode === 'text') setLines(await api.diffText(left, right));
      else if (mode === 'json') setJson(await api.diffJson(left, right));
      else setBytes(await api.diffBytes(textToB64(left), textToB64(right)));
    } catch (e) {
      setError(String(e instanceof Error ? e.message : e));
    }
  };

  return (
    <div className="view">
      <div className="toolbar">
        <strong>Compare</strong>
        <select value={mode} onChange={(e) => setMode(e.target.value as Mode)}>
          <option value="text">text (line)</option>
          <option value="json">JSON-aware</option>
          <option value="bytes">byte-level</option>
        </select>
        <button className="primary" onClick={run}>
          Compare
        </button>
      </div>
      <div className="split h" style={{ height: 200, background: 'var(--border)' }}>
        <div className="pane">
          <div className="pane-title">Left</div>
          <textarea
            style={{ flex: 1, border: 'none' }}
            value={left}
            onChange={(e) => setLeft(e.target.value)}
          />
        </div>
        <div className="pane">
          <div className="pane-title">Right</div>
          <textarea
            style={{ flex: 1, border: 'none' }}
            value={right}
            onChange={(e) => setRight(e.target.value)}
          />
        </div>
      </div>
      <div className="pane" style={{ flex: 1 }}>
        <div className="pane-title">Diff</div>
        <div className="scrolly mono" style={{ fontSize: 12 }}>
          {error && <div className="danger-box">{error}</div>}
          {lines &&
            lines.map((l, i) => (
              <div
                key={i}
                className={l.type === 'add' ? 'diff-add' : l.type === 'remove' ? 'diff-del' : ''}
              >
                {l.type === 'add' ? '+ ' : l.type === 'remove' ? '- ' : '  '}
                {l.text}
              </div>
            ))}
          {json &&
            json.map((e, i) => (
              <div
                key={i}
                className={e.kind === 'added' ? 'diff-add' : e.kind === 'removed' ? 'diff-del' : ''}
              >
                {e.path} [{e.kind}]{' '}
                {e.kind === 'changed'
                  ? `${JSON.stringify(e.left)} → ${JSON.stringify(e.right)}`
                  : ''}
              </div>
            ))}
          {json && json.length === 0 && <div>Documents are structurally equal.</div>}
          {bytes && (
            <div>
              equal: {String(bytes.equal)} · first diff at offset {bytes.firstDiffOffset} · left{' '}
              {bytes.leftLength}B · right {bytes.rightLength}B · differing {bytes.differingBytes}B
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
