import React, { useEffect, useRef, useState } from 'react';
import { api } from '../api.js';
import { useStore } from '../store.js';
import {
  AGENT_ROLES,
  AI_EFFORTS,
  defaultAiConfig,
  type AgentRole,
  type AiAutonomy,
  type AiConfig,
  type AiEffort,
  type AiKeyStatus,
  type MeshRunProgress,
  type MeshStep,
} from '@shared/ai.js';

const TERMINAL = new Set(['done', 'error', 'stopped']);

const ROLE_COLORS: Record<AgentRole, string> = {
  recon: '#9d8bf0',
  planner: '#6ea8fe',
  attacker: '#f0868e',
  analyst: '#7bd88f',
  reporter: '#d6a860',
};

export function AiMeshView(): JSX.Element {
  const s = useStore();
  const setToast = s.setToast;

  const [config, setConfig] = useState<AiConfig>(defaultAiConfig());
  const [keyStatus, setKeyStatus] = useState<AiKeyStatus | undefined>(undefined);
  const [apiKey, setApiKey] = useState('');
  const [objective, setObjective] = useState('');

  const [run, setRun] = useState<MeshRunProgress | undefined>(undefined);
  const [steps, setSteps] = useState<MeshStep[]>([]);
  const [report, setReport] = useState<string | undefined>(undefined);
  const runIdRef = useRef<string | undefined>(undefined);

  useEffect(() => {
    void api
      .getAiConfig()
      .then(setConfig)
      .catch(() => undefined);
    void api
      .getAiKeyStatus()
      .then(setKeyStatus)
      .catch(() => undefined);
    return api.onEvent((e) => {
      if (e.type === 'mesh-step') {
        if (e.payload.runId === runIdRef.current) setSteps((prev) => [...prev, e.payload]);
      } else if (e.type === 'mesh-progress') {
        if (e.payload.runId !== runIdRef.current) return;
        setRun(e.payload);
        if (TERMINAL.has(e.payload.status)) {
          void api.getMeshRun(e.payload.runId).then((r) => setReport(r?.report));
        }
      }
    });
  }, []);

  const saveKey = async (): Promise<void> => {
    try {
      await api.setAiApiKey(apiKey);
      setApiKey('');
      setKeyStatus(await api.getAiKeyStatus());
      setToast('API key saved to OS secure storage.');
    } catch (err) {
      setToast(`Could not save key: ${err instanceof Error ? err.message : String(err)}`);
    }
  };

  const clearKey = async (): Promise<void> => {
    await api.clearAiApiKey();
    setKeyStatus(await api.getAiKeyStatus());
    setToast('API key cleared.');
  };

  const saveConfig = async (next: AiConfig): Promise<void> => {
    setConfig(next);
    try {
      await api.setAiConfig(next);
    } catch (err) {
      setToast(`Could not save AI settings: ${err instanceof Error ? err.message : String(err)}`);
    }
  };

  const start = async (): Promise<void> => {
    if (!objective.trim()) {
      setToast('Enter a testing objective.');
      return;
    }
    setSteps([]);
    setReport(undefined);
    try {
      const progress = await api.startMeshRun({ objective: objective.trim() });
      runIdRef.current = progress.runId;
      setRun(progress);
    } catch (err) {
      setToast(`Could not start run: ${err instanceof Error ? err.message : String(err)}`);
    }
  };

  const stop = async (): Promise<void> => {
    if (runIdRef.current) await api.stopMeshRun(runIdRef.current);
  };

  const running = run !== undefined && !TERMINAL.has(run.status);

  return (
    <div className="view">
      <div className="scrolly">
        <div className="warn-box">
          The AI mesh drives the engine to test <strong>authorized</strong> targets on its own,
          bounded by project scope, rate limits, a per-run request cap, the audit log, and emergency
          stop. Running it sends captured traffic to the configured model provider — enable egress
          only for engagements you are authorized to expose this way.
        </div>

        {/* ---- provider key ---- */}
        <div className="card">
          <h3 style={{ marginTop: 0 }}>Anthropic API key</h3>
          <p className="mono" style={{ fontSize: 12, opacity: 0.8 }}>
            {keyStatus
              ? keyStatus.configured
                ? `Configured · ${keyStatus.secure ? 'OS-encrypted' : 'UNENCRYPTED fallback'} · ${keyStatus.backendName}`
                : `Not configured · ${keyStatus.secure ? 'OS secure storage available' : 'no OS encryption — key would be stored unencrypted'} · ${keyStatus.backendName}`
              : 'checking…'}
          </p>
          <div className="row" style={{ gap: 8 }}>
            <input
              type="password"
              placeholder="sk-ant-…"
              style={{ width: 320 }}
              value={apiKey}
              onChange={(e) => setApiKey(e.target.value)}
            />
            <button className="primary" onClick={saveKey} disabled={!apiKey.trim()}>
              Save key
            </button>
            {keyStatus?.configured && (
              <button className="ghost" onClick={clearKey}>
                Clear
              </button>
            )}
          </div>
          <p style={{ fontSize: 12, opacity: 0.7 }}>
            The key is held app-wide in OS secure storage and used only in the main process — it is
            never shown back or sent to the page.
          </p>
        </div>

        {/* ---- config ---- */}
        <div className="card">
          <h3 style={{ marginTop: 0 }}>Mesh settings</h3>
          <div className="row" style={{ flexWrap: 'wrap', gap: 16 }}>
            <label className="row" style={{ gap: 6 }}>
              <input
                type="checkbox"
                checked={config.enabled}
                onChange={(e) => saveConfig({ ...config, enabled: e.target.checked })}
              />
              Enabled
            </label>
            <label
              className="row"
              style={{ gap: 6, color: config.egressAcknowledged ? '#f0868e' : undefined }}
            >
              <input
                type="checkbox"
                checked={config.egressAcknowledged}
                onChange={(e) => saveConfig({ ...config, egressAcknowledged: e.target.checked })}
              />
              Acknowledge egress (send captured traffic to provider)
            </label>
            <label className="row" style={{ gap: 6 }}>
              <input
                type="checkbox"
                checked={config.redactBeforeSend}
                onChange={(e) => saveConfig({ ...config, redactBeforeSend: e.target.checked })}
              />
              Redact secrets (cookies, auth, tokens) before sending — best-effort
            </label>
            <label className="row" style={{ gap: 6 }}>
              Autonomy
              <select
                value={config.autonomy}
                onChange={(e) => saveConfig({ ...config, autonomy: e.target.value as AiAutonomy })}
              >
                <option value="auto">autonomous within scope</option>
                <option value="readonly">read-only (no traffic)</option>
              </select>
            </label>
          </div>

          <div className="row" style={{ flexWrap: 'wrap', gap: 16, marginTop: 12 }}>
            <label className="row" style={{ gap: 6 }}>
              <input
                type="checkbox"
                checked={config.workspaceAccess}
                onChange={(e) => saveConfig({ ...config, workspaceAccess: e.target.checked })}
              />
              Read the engagement folder during recon (its contents are sent to the provider)
            </label>
            <label
              className="row"
              style={{ gap: 6, color: config.allowCertOps ? '#f0868e' : undefined }}
            >
              <input
                type="checkbox"
                checked={config.allowCertOps}
                onChange={(e) => saveConfig({ ...config, allowCertOps: e.target.checked })}
              />
              Allow the mesh to issue and revoke the interception CA (breaks installed trust)
            </label>
          </div>

          <div className="row" style={{ flexWrap: 'wrap', gap: 16, marginTop: 12 }}>
            <label className="row" style={{ gap: 6 }}>
              Run token budget
              <input
                type="number"
                style={{ width: 120 }}
                value={config.runTokenBudget}
                onChange={(e) =>
                  saveConfig({ ...config, runTokenBudget: Number(e.target.value) || 0 })
                }
              />
            </label>
            <label className="row" style={{ gap: 6 }}>
              Max active requests / run
              <input
                type="number"
                style={{ width: 100 }}
                value={config.maxActiveRequestsPerRun}
                onChange={(e) =>
                  saveConfig({
                    ...config,
                    maxActiveRequestsPerRun: Math.max(0, Number(e.target.value) || 0),
                  })
                }
              />
            </label>
          </div>

          <table className="grid" style={{ marginTop: 12 }}>
            <thead>
              <tr>
                <th>Role</th>
                <th>Model</th>
                <th>Effort</th>
              </tr>
            </thead>
            <tbody>
              {AGENT_ROLES.map((role) => (
                <tr key={role}>
                  <td style={{ color: ROLE_COLORS[role] }}>{role}</td>
                  <td>
                    <input
                      className="mono"
                      style={{ width: 260 }}
                      value={config.roles[role].model}
                      onChange={(e) =>
                        saveConfig({
                          ...config,
                          roles: {
                            ...config.roles,
                            [role]: { ...config.roles[role], model: e.target.value },
                          },
                        })
                      }
                    />
                  </td>
                  <td>
                    <select
                      value={config.roles[role].effort ?? 'high'}
                      onChange={(e) =>
                        saveConfig({
                          ...config,
                          roles: {
                            ...config.roles,
                            [role]: { ...config.roles[role], effort: e.target.value as AiEffort },
                          },
                        })
                      }
                    >
                      {AI_EFFORTS.map((level) => (
                        <option key={level} value={level}>
                          {level}
                        </option>
                      ))}
                    </select>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          <p style={{ fontSize: 12, opacity: 0.7 }}>
            Effort controls how much the model reasons per turn — it does not raise how many
            requests reach the target. Higher effort generally means fewer, better-aimed probes.
          </p>
        </div>

        {/* ---- run ---- */}
        <div className="card">
          <h3 style={{ marginTop: 0 }}>Run</h3>
          <textarea
            placeholder="Objective, e.g. “probe the auth and search endpoints for authz and reflection issues”"
            style={{ width: '100%', minHeight: 60 }}
            value={objective}
            onChange={(e) => setObjective(e.target.value)}
            disabled={running}
          />
          <div className="row" style={{ gap: 8, marginTop: 8, alignItems: 'center' }}>
            <button className="primary" onClick={start} disabled={running}>
              Start mesh ▶
            </button>
            <button className="ghost" onClick={stop} disabled={!running}>
              Stop
            </button>
            {run && (
              <span className="mono" style={{ fontSize: 12, opacity: 0.85 }}>
                {run.status}
                {run.role ? ` · ${run.role}` : ''} · {run.stepCount} steps · {run.activeRequests}{' '}
                active · {run.tokens.input + run.tokens.output} tok
              </span>
            )}
          </div>
          {run?.error && (
            <div className="warn-box" style={{ marginTop: 8 }}>
              {run.error}
            </div>
          )}
        </div>

        {/* ---- step stream ---- */}
        <div className="card">
          <h3 style={{ marginTop: 0 }}>Activity</h3>
          {steps.length === 0 ? (
            <div className="empty">No activity yet.</div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
              {steps.map((step) => (
                <div
                  key={step.id}
                  className="mono"
                  style={{
                    fontSize: 12,
                    padding: '3px 6px',
                    borderLeft: `3px solid ${ROLE_COLORS[step.role]}`,
                    background: step.mutating ? 'rgba(240,134,142,0.08)' : 'transparent',
                    whiteSpace: 'pre-wrap',
                  }}
                >
                  <strong style={{ color: ROLE_COLORS[step.role] }}>{step.role}</strong>{' '}
                  <span style={{ opacity: 0.6 }}>{step.tool ?? step.kind}</span>
                  {step.mutating ? <span style={{ color: '#f0868e' }}> ⚡</span> : null}{' '}
                  {step.summary}
                </div>
              ))}
            </div>
          )}
        </div>

        {report && (
          <div className="card">
            <h3 style={{ marginTop: 0 }}>Report</h3>
            <pre style={{ whiteSpace: 'pre-wrap', fontSize: 13 }}>{report}</pre>
          </div>
        )}
      </div>
    </div>
  );
}
