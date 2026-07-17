import React, { useEffect, useState } from 'react';
import { api } from '../api.js';
import { useStore } from '../store.js';
import type { EngineConfig } from '@shared/config.js';

/** Hosts safe to bind without a warning (mirrors engine SAFE_BIND_HOSTS). */
const LOOPBACK_HOSTS = new Set(['127.0.0.1', '::1', 'localhost']);
const isLoopback = (host: string): boolean => LOOPBACK_HOSTS.has(host.trim().toLowerCase());

const MB = 1024 * 1024;
const clamp = (n: number, min: number, fallback: number): number =>
  Number.isFinite(n) && n >= min ? n : fallback;

export function SettingsView(): JSX.Element {
  const s = useStore();
  const [cfg, setCfg] = useState<EngineConfig | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    void api.getConfig().then(setCfg);
  }, []);

  if (!cfg) return <div className="scrolly">Loading settings…</div>;

  // Immutable nested updates keep this a controlled form.
  const patchLimits = (p: Partial<EngineConfig['limits']>): void =>
    setCfg({ ...cfg, limits: { ...cfg.limits, ...p } });
  const patchAutomation = (p: Partial<EngineConfig['limits']['automation']>): void =>
    patchLimits({ automation: { ...cfg.limits.automation, ...p } });
  const patchBody = (p: Partial<EngineConfig['limits']['body']>): void =>
    patchLimits({ body: { ...cfg.limits.body, ...p } });
  const patchRedaction = (p: Partial<EngineConfig['redaction']>): void =>
    setCfg({ ...cfg, redaction: { ...cfg.redaction, ...p } });

  const save = async (): Promise<void> => {
    setBusy(true);
    setError(null);
    // Clamp to safe minimums so a mistaken 0 can't wedge the rate limiter or
    // uncap capture. These are safety controls, not free-form tuning knobs.
    const a = cfg.limits.automation;
    const body = cfg.limits.body;
    const spill = clamp(body.spillToDiskAfterBytes, 64 * 1024, 5 * MB);
    const normalized: EngineConfig = {
      ...cfg,
      listener: {
        host: cfg.listener.host.trim() || '127.0.0.1',
        port: clamp(cfg.listener.port, 1, 8080),
      },
      limits: {
        ...cfg.limits,
        automation: {
          maxConcurrency: clamp(a.maxConcurrency, 1, 4),
          requestsPerSecond: clamp(a.requestsPerSecond, 1, 8),
          timeoutMs: clamp(a.timeoutMs, 1000, 20_000),
          maxRequestsPerJob: clamp(a.maxRequestsPerJob, 1, 5_000),
        },
        body: {
          spillToDiskAfterBytes: spill,
          // maxCaptured must be at least the spill threshold to stay coherent.
          maxCapturedBytes: clamp(body.maxCapturedBytes, spill, 100 * MB),
        },
        maxProxyConnections: clamp(cfg.limits.maxProxyConnections, 1, 512),
        upstreamTimeoutMs: clamp(cfg.limits.upstreamTimeoutMs, 1000, 30_000),
      },
    };
    try {
      await api.setConfig(normalized);
      setCfg(normalized);
      s.setToast(
        'Settings saved. Redaction & repeater limits apply now; listener and capture settings apply on the next proxy start.',
      );
    } catch (e) {
      setError(String(e instanceof Error ? e.message : e));
    } finally {
      setBusy(false);
    }
  };

  const exportProject = async (): Promise<void> => {
    setError(null);
    try {
      const path = await api.exportProjectToFile();
      s.setToast(path ? `Exported to ${path}` : 'Export cancelled.');
    } catch (e) {
      setError(String(e instanceof Error ? e.message : e));
    }
  };

  const closeProject = async (): Promise<void> => {
    await api.closeProject();
    s.setProject(undefined);
  };

  const nonLoopback = !isLoopback(cfg.listener.host);

  return (
    <div className="view">
      <div className="scrolly">
        <div className="card">
          <h3 style={{ marginTop: 0 }}>Proxy listener</h3>
          <p className="hint">
            Where the intercepting proxy binds. Applies the next time you start the proxy.
          </p>
          <div className="row" style={{ gap: 12, flexWrap: 'wrap' }}>
            <div className="form-row" style={{ marginBottom: 0 }}>
              <label>Bind host</label>
              <input
                style={{ width: 200 }}
                value={cfg.listener.host}
                onChange={(e) =>
                  setCfg({ ...cfg, listener: { ...cfg.listener, host: e.target.value } })
                }
              />
            </div>
            <div className="form-row" style={{ marginBottom: 0 }}>
              <label>Port</label>
              <input
                type="number"
                style={{ width: 100 }}
                value={cfg.listener.port}
                onChange={(e) =>
                  setCfg({ ...cfg, listener: { ...cfg.listener, port: Number(e.target.value) } })
                }
              />
            </div>
          </div>
          {nonLoopback && (
            <div className="warn-box">
              <strong>Non-loopback bind.</strong> Binding to {cfg.listener.host || '(blank)'}{' '}
              exposes the intercepting proxy beyond this machine. Only do this deliberately, on a
              trusted network you are authorized to test from.
            </div>
          )}
        </div>

        <div className="card">
          <h3 style={{ marginTop: 0 }}>Automation limits (defaults for new variation jobs)</h3>
          <p className="hint">
            Safety controls for automated request generation. Kept deliberately low. New Variation
            jobs start from these values; you can still lower them per job.
          </p>
          <div className="row" style={{ gap: 16, flexWrap: 'wrap' }}>
            <NumField
              label="Max concurrency"
              value={cfg.limits.automation.maxConcurrency}
              min={1}
              onChange={(v) => patchAutomation({ maxConcurrency: v })}
            />
            <NumField
              label="Requests / second"
              value={cfg.limits.automation.requestsPerSecond}
              min={1}
              onChange={(v) => patchAutomation({ requestsPerSecond: v })}
            />
            <NumField
              label="Request timeout (ms)"
              value={cfg.limits.automation.timeoutMs}
              min={1000}
              step={1000}
              onChange={(v) => patchAutomation({ timeoutMs: v })}
            />
            <NumField
              label="Max requests / job"
              value={cfg.limits.automation.maxRequestsPerJob}
              min={1}
              onChange={(v) => patchAutomation({ maxRequestsPerJob: v })}
            />
          </div>
        </div>

        <div className="card">
          <h3 style={{ marginTop: 0 }}>Capture &amp; body limits</h3>
          <p className="hint">
            Bound memory/disk use on hostile traffic. The proxy always forwards every byte to the
            peer; these caps only limit what is <em>captured</em>. Applies on next proxy start.
          </p>
          <div className="row" style={{ gap: 16, flexWrap: 'wrap' }}>
            <NumField
              label="Spill to disk after (MB)"
              value={Math.round((cfg.limits.body.spillToDiskAfterBytes / MB) * 10) / 10}
              min={0.0625}
              step={1}
              onChange={(v) => patchBody({ spillToDiskAfterBytes: Math.round(v * MB) })}
            />
            <NumField
              label="Max captured / body (MB)"
              value={Math.round((cfg.limits.body.maxCapturedBytes / MB) * 10) / 10}
              min={0.0625}
              step={1}
              onChange={(v) => patchBody({ maxCapturedBytes: Math.round(v * MB) })}
            />
            <NumField
              label="Max proxy connections"
              value={cfg.limits.maxProxyConnections}
              min={1}
              onChange={(v) => patchLimits({ maxProxyConnections: v })}
            />
            <NumField
              label="Upstream timeout (ms)"
              value={cfg.limits.upstreamTimeoutMs}
              min={1000}
              step={1000}
              onChange={(v) => patchLimits({ upstreamTimeoutMs: v })}
            />
          </div>
          <div className="row" style={{ gap: 20, marginTop: 12, flexWrap: 'wrap' }}>
            <label className="row" style={{ gap: 6 }}>
              <input
                type="checkbox"
                checked={cfg.captureWebSockets}
                onChange={(e) => setCfg({ ...cfg, captureWebSockets: e.target.checked })}
              />
              Capture WebSocket frames
            </label>
            <label className="row" style={{ gap: 6 }}>
              <input
                type="checkbox"
                checked={cfg.interceptHttp2}
                onChange={(e) => setCfg({ ...cfg, interceptHttp2: e.target.checked })}
              />
              Intercept HTTP/2 (ALPN h2)
            </label>
          </div>
        </div>

        <div className="card">
          <h3 style={{ marginTop: 0 }}>Secret redaction</h3>
          <p className="hint">
            Masks secrets in logs, findings evidence, and exports. Applies to new scans as soon as
            you save. Captured traffic is still stored in full (encrypted at rest).
          </p>
          <div className="row" style={{ gap: 20, flexWrap: 'wrap' }}>
            <label className="row" style={{ gap: 6 }}>
              <input
                type="checkbox"
                checked={cfg.redaction.maskCookies}
                onChange={(e) => patchRedaction({ maskCookies: e.target.checked })}
              />
              Mask cookies
            </label>
            <label className="row" style={{ gap: 6 }}>
              <input
                type="checkbox"
                checked={cfg.redaction.maskAuthorization}
                onChange={(e) => patchRedaction({ maskAuthorization: e.target.checked })}
              />
              Mask Authorization headers
            </label>
            <label className="row" style={{ gap: 6 }}>
              <input
                type="checkbox"
                checked={cfg.redaction.maskSecretPatterns}
                onChange={(e) => patchRedaction({ maskSecretPatterns: e.target.checked })}
              />
              Mask secret patterns (tokens/keys)
            </label>
          </div>
        </div>

        {error && <div className="danger-box">{error}</div>}

        <div className="row" style={{ margin: '0 12px 16px' }}>
          <button className="primary" onClick={save} disabled={busy}>
            {busy ? 'Saving…' : 'Save settings'}
          </button>
          <button onClick={() => void api.getConfig().then(setCfg)} disabled={busy}>
            Reload
          </button>
        </div>

        <div className="card">
          <h3 style={{ marginTop: 0 }}>Project</h3>
          <p className="hint">
            Export writes a versioned, portable JSON snapshot (history, findings, scope, config,
            saved requests, audit). Closing returns to the welcome screen.
          </p>
          <div className="row">
            <button onClick={exportProject}>Export project…</button>
            <button className="ghost" onClick={closeProject}>
              Close project
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

function NumField(props: {
  label: string;
  value: number;
  min: number;
  step?: number;
  onChange: (v: number) => void;
}): JSX.Element {
  return (
    <div className="form-row" style={{ marginBottom: 0 }}>
      <label>{props.label}</label>
      <input
        type="number"
        style={{ width: 150 }}
        min={props.min}
        step={props.step ?? 1}
        value={props.value}
        onChange={(e) => props.onChange(Number(e.target.value))}
      />
    </div>
  );
}
