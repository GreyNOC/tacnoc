import React, { useEffect, useState } from 'react';
import { api } from '../api.js';
import { useStore } from '../store.js';
import type {
  PayloadSource,
  VariationMode,
  VariationPlan,
  VariationResultRow,
} from '@shared/variation.js';

interface PositionDraft {
  marker: string;
  kind: 'list' | 'range' | 'builtin';
  values: string;
  from: number;
  to: number;
  step: number;
}

function toSource(p: PositionDraft): PayloadSource {
  if (p.kind === 'list')
    return { kind: 'list', values: p.values.split('\n').filter((v) => v.length > 0) };
  if (p.kind === 'range') return { kind: 'range', from: p.from, to: p.to, step: p.step };
  return { kind: 'builtin', set: 'safe-structural' };
}

export function VariationView(): JSX.Element {
  const s = useStore();
  const [host, setHost] = useState('example.test');
  const [port, setPort] = useState(443);
  const [scheme, setScheme] = useState<'http' | 'https'>('https');
  const [raw, setRaw] = useState('GET /search?q={{0}} HTTP/1.1\r\nHost: example.test\r\n\r\n');
  const [mode, setMode] = useState<VariationMode>('batteringram');
  const [positions, setPositions] = useState<PositionDraft[]>([
    { marker: '{{0}}', kind: 'builtin', values: '', from: 0, to: 10, step: 1 },
  ]);
  const [markers, setMarkers] = useState('');
  const [extractors, setExtractors] = useState('');
  const [concurrency, setConcurrency] = useState(4);
  const [rps, setRps] = useState(8);
  const [maxReq, setMaxReq] = useState(500);

  const [jobId, setJobId] = useState<string | null>(null);
  const [count, setCount] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [results, setResults] = useState<VariationResultRow[]>([]);

  const progress = s.jobs.find((j) => j.id === jobId);

  useEffect(() => {
    if (!jobId) return;
    const t = setInterval(() => void api.getVariationResults(jobId).then(setResults), 500);
    return () => clearInterval(t);
  }, [jobId]);

  const buildPlan = (): VariationPlan => ({
    name: `variation-${host}`,
    base: { scheme, host, port, raw },
    positions: positions.map((p) => ({ marker: p.marker, source: toSource(p) })),
    mode,
    limits: {
      maxConcurrency: concurrency,
      requestsPerSecond: rps,
      timeoutMs: 20000,
      maxRequestsPerJob: maxReq,
    },
    responseMarkers: markers
      .split(/\r?\n/)
      .map((m) => m.trim())
      .filter(Boolean),
    responseExtractors: extractors
      .split(/\r?\n/)
      .map((line) => {
        const separator = line.indexOf('::');
        if (separator < 1) return undefined;
        return {
          name: line.slice(0, separator).trim(),
          pattern: line.slice(separator + 2).trim(),
        };
      })
      .filter((value): value is { name: string; pattern: string } => !!value),
  });

  const prepare = async (): Promise<void> => {
    setError(null);
    try {
      const { id, count: c } = await api.createVariationJob(buildPlan());
      setJobId(id);
      setCount(c);
      setResults([]);
    } catch (e) {
      setError(String(e instanceof Error ? e.message : e));
      setJobId(null);
      setCount(null);
    }
  };

  const run = async (): Promise<void> => {
    if (!jobId) return;
    setError(null);
    try {
      await api.runVariationJob(jobId);
    } catch (e) {
      // A refusal here is the scope gate or a limit doing its job — the operator
      // has to see which. Unreported, a blocked run is indistinguishable from a
      // run that found nothing.
      setError(String(e instanceof Error ? e.message : e));
    }
    void api.getVariationResults(jobId).then(setResults);
  };

  /** Job controls report failures instead of dropping them into a dead promise. */
  const control = (action: (id: string) => Promise<void>) => (): void => {
    if (!jobId) return;
    setError(null);
    void action(jobId).catch((e: unknown) => setError(String(e instanceof Error ? e.message : e)));
  };

  const addPosition = (): void =>
    setPositions((p) => [
      ...p,
      { marker: `{{${p.length}}}`, kind: 'list', values: '', from: 0, to: 10, step: 1 },
    ]);

  return (
    <div className="view">
      <div className="toolbar">
        <strong>Controlled variation</strong>
        <span className="hint">scope-gated · rate-limited · audited</span>
        <span className="spacer" style={{ flex: 1 }} />
        <button onClick={prepare}>Prepare</button>
        <button
          className="primary"
          disabled={!jobId || progress?.status === 'running'}
          onClick={run}
        >
          Run
        </button>
        <button disabled={!jobId} onClick={control(api.pauseVariationJob)}>
          Pause
        </button>
        <button disabled={!jobId} onClick={control(api.resumeVariationJob)}>
          Resume
        </button>
        <button className="danger" disabled={!jobId} onClick={control(api.stopVariationJob)}>
          Stop
        </button>
      </div>

      <div className="split h" style={{ flex: 1 }}>
        <div className="pane">
          <div className="scrolly">
            <div className="row" style={{ marginBottom: 8 }}>
              <select
                value={scheme}
                onChange={(e) => setScheme(e.target.value as 'http' | 'https')}
              >
                <option value="https">https</option>
                <option value="http">http</option>
              </select>
              <input value={host} onChange={(e) => setHost(e.target.value)} placeholder="host" />
              <input
                type="number"
                style={{ width: 80 }}
                value={port}
                onChange={(e) => setPort(Number(e.target.value))}
              />
            </div>
            <label>Base request (insert markers like {'{{0}}'})</label>
            <textarea
              style={{ width: '100%', minHeight: 120 }}
              value={raw}
              onChange={(e) => setRaw(e.target.value)}
            />

            <div className="row" style={{ margin: '10px 0' }}>
              <label>Mode</label>
              <select value={mode} onChange={(e) => setMode(e.target.value as VariationMode)}>
                <option value="batteringram">battering ram</option>
                <option value="sniper">sniper</option>
                <option value="pitchfork">pitchfork</option>
                <option value="clusterbomb">cluster bomb</option>
              </select>
              <button className="ghost" onClick={addPosition}>
                + position
              </button>
            </div>

            {positions.map((p, i) => (
              <div key={i} className="card" style={{ margin: '8px 0' }}>
                <div className="row">
                  <input
                    style={{ width: 90 }}
                    value={p.marker}
                    onChange={(e) =>
                      setPositions((arr) =>
                        arr.map((x, j) => (j === i ? { ...x, marker: e.target.value } : x)),
                      )
                    }
                  />
                  <select
                    value={p.kind}
                    onChange={(e) =>
                      setPositions((arr) =>
                        arr.map((x, j) =>
                          j === i ? { ...x, kind: e.target.value as PositionDraft['kind'] } : x,
                        ),
                      )
                    }
                  >
                    <option value="builtin">safe structural set</option>
                    <option value="list">list</option>
                    <option value="range">number range</option>
                  </select>
                </div>
                {p.kind === 'list' && (
                  <textarea
                    style={{ width: '100%', minHeight: 60, marginTop: 6 }}
                    placeholder="one payload per line"
                    value={p.values}
                    onChange={(e) =>
                      setPositions((arr) =>
                        arr.map((x, j) => (j === i ? { ...x, values: e.target.value } : x)),
                      )
                    }
                  />
                )}
                {p.kind === 'range' && (
                  <div className="row" style={{ marginTop: 6 }}>
                    <input
                      type="number"
                      style={{ width: 80 }}
                      value={p.from}
                      onChange={(e) =>
                        setPositions((arr) =>
                          arr.map((x, j) => (j === i ? { ...x, from: Number(e.target.value) } : x)),
                        )
                      }
                    />
                    <input
                      type="number"
                      style={{ width: 80 }}
                      value={p.to}
                      onChange={(e) =>
                        setPositions((arr) =>
                          arr.map((x, j) => (j === i ? { ...x, to: Number(e.target.value) } : x)),
                        )
                      }
                    />
                    <input
                      type="number"
                      style={{ width: 80 }}
                      value={p.step}
                      onChange={(e) =>
                        setPositions((arr) =>
                          arr.map((x, j) => (j === i ? { ...x, step: Number(e.target.value) } : x)),
                        )
                      }
                    />
                  </div>
                )}
              </div>
            ))}

            <label>Response markers (one regex per line)</label>
            <textarea
              style={{ width: '100%' }}
              value={markers}
              onChange={(e) => setMarkers(e.target.value)}
              placeholder={'error\n"authenticated":false'}
            />

            <label style={{ display: 'block', marginTop: 8 }}>
              Named response extractors (one <span className="mono">name :: regex</span> per line)
            </label>
            <textarea
              style={{ width: '100%' }}
              value={extractors}
              onChange={(e) => setExtractors(e.target.value)}
              placeholder={'csrf :: name="csrf" value="([^"]+)"\nuserId :: "id":(\\d+)'}
            />

            <div className="row" style={{ marginTop: 10, flexWrap: 'wrap' }}>
              <label>concurrency</label>
              <input
                type="number"
                style={{ width: 70 }}
                value={concurrency}
                onChange={(e) => setConcurrency(Number(e.target.value))}
              />
              <label>req/s</label>
              <input
                type="number"
                style={{ width: 70 }}
                value={rps}
                onChange={(e) => setRps(Number(e.target.value))}
              />
              <label>max requests</label>
              <input
                type="number"
                style={{ width: 90 }}
                value={maxReq}
                onChange={(e) => setMaxReq(Number(e.target.value))}
              />
            </div>

            {error && <div className="danger-box">{error}</div>}
            {count !== null && (
              <div className="warn-box">
                This job will generate <strong>{count}</strong> request(s). Review before running.
              </div>
            )}
          </div>
        </div>

        <div className="pane">
          <div className="pane-title">
            Results{' '}
            {progress &&
              `— ${progress.status} · ${progress.completed}/${progress.total} · ${progress.skipped} skipped · ${progress.errors} errors`}
          </div>
          <div className="table-wrap">
            <table className="grid">
              <thead>
                <tr>
                  <th>#</th>
                  <th>Payload</th>
                  <th>Status</th>
                  <th>Len</th>
                  <th>Words</th>
                  <th>Lines</th>
                  <th>ms</th>
                  <th>Hash</th>
                  <th>Markers</th>
                  <th>Extracted</th>
                </tr>
              </thead>
              <tbody>
                {results.map((r) => (
                  <tr key={r.index}>
                    <td className="mono">{r.index}</td>
                    <td className="mono">{r.payloads.join(', ')}</td>
                    <td className="mono">{r.skipped ? 'skip' : r.error ? 'ERR' : r.status}</td>
                    <td className="mono">
                      {r.responseLength}
                      {r.responseTruncated ? '+' : ''}
                    </td>
                    <td className="mono">{r.responseWords ?? '—'}</td>
                    <td className="mono">{r.responseLines ?? '—'}</td>
                    <td className="mono">{r.durationMs}</td>
                    <td className="mono">{r.responseHash ?? '—'}</td>
                    <td className="mono">{r.markerHits?.join(' | ')}</td>
                    <td className="mono">
                      {r.extracted
                        ? Object.entries(r.extracted)
                            .map(([name, value]) => `${name}=${value}`)
                            .join(' | ')
                        : ''}
                    </td>
                  </tr>
                ))}
                {results.length === 0 && (
                  <tr>
                    <td colSpan={10} className="empty">
                      Prepare a job to see the request count, then run it.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
}
