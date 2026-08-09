/**
 * Engagement view — the paperwork the engine enforces, plus the readiness check.
 *
 * Preflight is the top of the page on purpose. The failures it catches (an
 * expired CA, an empty scope, a browser that never trusted the certificate) all
 * look identical from the operator's chair: a session that seems to work and
 * finds nothing. Putting the graded answer where you cannot miss it is the point
 * of the feature.
 */

import React, { useCallback, useEffect, useState } from 'react';
import { api } from '../api.js';
import { useStore } from '../store.js';
import { scopeRulesFromProposal, type ScopeProposal } from '@engine/engagement/scopeProposal.js';
import type { DocScanResult } from '@engine/engagement/docScan.js';
import type { ScopeConfig, ScopeRule } from '@shared/scope.js';
import {
  defaultEngagementProfile,
  type EngagementProfile,
  type PreflightCheck,
  type PreflightReport,
} from '@shared/engagement.js';

const SEVERITY_COLOR: Record<PreflightCheck['severity'], string> = {
  blocker: '#f0868e',
  warning: '#d6a860',
  ok: '#7bd88f',
};

const SEVERITY_LABEL: Record<PreflightCheck['severity'], string> = {
  blocker: 'BLOCKER',
  warning: 'warning',
  ok: 'ok',
};

export function EngagementView(): JSX.Element {
  const setToast = useStore().setToast;
  const [profile, setProfile] = useState<EngagementProfile>(defaultEngagementProfile());
  const [report, setReport] = useState<PreflightReport | undefined>(undefined);
  const [busy, setBusy] = useState(false);
  const [proposal, setProposal] = useState<ScopeProposal | undefined>(undefined);
  const [scanning, setScanning] = useState(false);
  const [scanError, setScanError] = useState<string | undefined>(undefined);
  const [picked, setPicked] = useState<Set<string>>(new Set());
  const [scan, setScan] = useState<DocScanResult | undefined>(undefined);

  const refresh = useCallback(async (): Promise<void> => {
    try {
      setReport(await api.getPreflight());
    } catch (err) {
      setToast(`Preflight failed: ${err instanceof Error ? err.message : String(err)}`);
    }
  }, [setToast]);

  const readProposal = useCallback(async (): Promise<void> => {
    setScanning(true);
    setScanError(undefined);
    try {
      const found = await api.proposeScopeFromWorkspace();
      setProposal(found);
      // Same trigger as the proposal: both describe the folder in use, so they
      // must never disagree about which folder that is.
      api
        .scanEngagementDocs()
        .then(setScan)
        .catch(() => setScan(undefined));
      // Pre-tick only the hosts the documents call in-scope; the operator still
      // confirms. Excluded and ambiguous hosts are never pre-selected.
      setPicked(new Set(found.include.map((c) => c.host)));
    } catch (err) {
      // Say why. Silently showing nothing is indistinguishable from "your
      // folder has no scope in it", which sends the operator looking in the
      // wrong place.
      setProposal(undefined);
      setScanError(err instanceof Error ? err.message : String(err));
    } finally {
      setScanning(false);
    }
  }, []);

  useEffect(() => {
    void api
      .getEngagementProfile()
      .then(setProfile)
      .catch(() => undefined);
    void refresh();
    // The CA and the profile both change from outside this page — most sharply
    // when the mesh is granted cert ops and rotates or revokes the CA mid-run.
    // Both events were emitted and nothing in the renderer listened, so the
    // readiness card kept grading an interception setup that no longer existed.
    return api.onEvent((e) => {
      if (e.type === 'ca-changed') void refresh();
      else if (e.type === 'engagement-changed') setProfile(e.payload);
    });
  }, [refresh]);

  /**
   * Re-read the folder whenever the root actually changes.
   *
   * Switching folders — by the suggestion button, by "Choose…", or by typing a
   * path — used to leave the Proposed-scope card showing its PRE-switch result
   * under the POST-switch path, because save() refreshed preflight but never
   * re-read the proposal. The operator clicked the button that was supposed to
   * find their scope and the card still said it had found nothing.
   */
  useEffect(() => {
    if (report?.workspace.root) void readProposal();
  }, [report?.workspace.root, readProposal]);

  const save = async (next: EngagementProfile): Promise<void> => {
    setProfile(next);
    try {
      const stored = await api.setEngagementProfile(next);
      setProfile(stored);
      await refresh();
    } catch (err) {
      // The engine refuses an invalid profile outright — surface exactly why.
      setToast(err instanceof Error ? err.message : String(err));
    }
  };

  /**
   * Add the ticked hosts to project scope.
   *
   * The rule construction lives in the engine (`scopeRulesFromProposal`) and is
   * tested against the real evaluator, because it decides what the safety gate
   * will permit — in particular it translates a policy's `*.host` into a rule
   * that matches subdomains at any depth without silently widening to the apex.
   */
  const addSelectedToScope = async (): Promise<void> => {
    if (!proposal || picked.size === 0) return;
    setBusy(true);
    try {
      const current: ScopeConfig = await api.getScope();
      const { include, exclude } = scopeRulesFromProposal(proposal, picked, current);
      await api.setScope({
        include: [...current.include, ...(include as unknown as ScopeRule[])],
        exclude: [...current.exclude, ...(exclude as unknown as ScopeRule[])],
      });
      setToast(
        `Added ${include.length} host(s) to scope` +
          (exclude.length ? ` and ${exclude.length} exclusion(s)` : '') +
          '. Verify each against the program page.',
      );
      await refresh();
    } catch (err) {
      setToast(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  const chooseWorkspace = async (): Promise<void> => {
    const dir = await api.pickWorkspaceDirectory();
    if (dir) await save({ ...profile, workspaceDir: dir });
  };

  const rotate = async (): Promise<void> => {
    const reason = window.prompt('Why are you issuing a new CA? (recorded in the audit log)');
    if (reason === null) return;
    setBusy(true);
    try {
      await api.rotateCa(reason);
      setToast('New CA issued. Install it in your test browser — the old one no longer works.');
      await refresh();
    } catch (err) {
      setToast(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  const revoke = async (): Promise<void> => {
    const reason = window.prompt(
      'Revoking destroys this project’s CA. HTTPS stops being captured until you issue a new one. Why?',
    );
    if (reason === null) return;
    setBusy(true);
    try {
      await api.revokeCa(reason);
      setToast('CA revoked. TLS interception is off; HTTPS tunnels now pass through unread.');
      await refresh();
    } catch (err) {
      setToast(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  const ua = profile.userAgent;

  return (
    <div className="view">
      <div className="scrolly">
        {/* ---- readiness ---- */}
        <div className="card">
          <div className="row" style={{ justifyContent: 'space-between', alignItems: 'center' }}>
            <h3 style={{ margin: 0 }}>
              Preflight{' '}
              {report && (
                <span style={{ color: report.ready ? '#7bd88f' : '#f0868e' }}>
                  · {report.ready ? 'ready to test' : 'not ready'}
                </span>
              )}
            </h3>
            <button className="ghost" onClick={() => void refresh()}>
              Re-check
            </button>
          </div>
          {!report && <p style={{ opacity: 0.7 }}>checking…</p>}
          {report && (
            <table className="grid" style={{ marginTop: 10 }}>
              <tbody>
                {report.checks.map((check) => (
                  <tr key={check.id}>
                    <td style={{ color: SEVERITY_COLOR[check.severity], whiteSpace: 'nowrap' }}>
                      {SEVERITY_LABEL[check.severity]}
                    </td>
                    <td>
                      <strong>{check.title}</strong>
                      <div style={{ fontSize: 12, opacity: 0.8 }}>{check.detail}</div>
                      {check.remedy && (
                        <div style={{ fontSize: 12, opacity: 0.6 }}>→ {check.remedy}</div>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>

        {/* ---- scope read out of the engagement folder ---- */}
        <div className="card">
          <div className="row" style={{ justifyContent: 'space-between', alignItems: 'center' }}>
            <h3 style={{ margin: 0 }}>Proposed scope (from the engagement folder)</h3>
            <button className="ghost" disabled={scanning} onClick={() => void readProposal()}>
              {scanning ? 'Searching…' : 'Re-read folder'}
            </button>
          </div>

          <p className="mono" style={{ fontSize: 12, opacity: 0.85 }}>
            {scanning
              ? `Searching ${report?.workspace.root ?? 'the engagement folder'} for scope…`
              : scanError
                ? `Could not read the engagement folder: ${scanError}`
                : proposal
                  ? `Read ${proposal.filesRead} document(s) in ${report?.workspace.root ?? 'the engagement folder'} — ` +
                    `${proposal.include.length} in scope, ${proposal.exclude.length} excluded, ${proposal.unclear.length} unclear.`
                  : 'not read yet'}
          </p>

          {proposal && (
            <>
              {proposal.notes.map((note, i) => (
                <p key={i} style={{ fontSize: 12, opacity: 0.75 }}>
                  {note}
                </p>
              ))}

              {proposal.include.length + proposal.unclear.length > 0 && (
                <>
                  <table className="grid" style={{ marginTop: 10 }}>
                    <thead>
                      <tr>
                        <th style={{ width: 28 }} />
                        <th>Host</th>
                        <th>Reading</th>
                        <th>Found in</th>
                      </tr>
                    </thead>
                    <tbody>
                      {[...proposal.include, ...proposal.unclear].map((c) => (
                        <tr key={c.host}>
                          <td>
                            <input
                              type="checkbox"
                              checked={picked.has(c.host)}
                              onChange={(e) => {
                                const next = new Set(picked);
                                if (e.target.checked) next.add(c.host);
                                else next.delete(c.host);
                                setPicked(next);
                              }}
                            />
                          </td>
                          <td className="mono">{c.host}</td>
                          <td
                            style={{
                              fontSize: 12,
                              color: c.disposition === 'include' ? '#7bd88f' : '#d6a860',
                            }}
                          >
                            {c.disposition === 'include' ? 'in scope' : 'unclear'} — {c.reason}
                          </td>
                          <td style={{ fontSize: 11, opacity: 0.8 }}>
                            {c.evidence.slice(0, 2).map((e, i) => (
                              <div key={i} className="mono">
                                {e.file}:{e.line} · {e.text.slice(0, 90)}
                              </div>
                            ))}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>

                  <div className="row" style={{ gap: 8, marginTop: 10 }}>
                    <button
                      className="primary"
                      disabled={busy || picked.size === 0}
                      onClick={() => void addSelectedToScope()}
                    >
                      Add {picked.size} selected to scope
                    </button>
                  </div>
                  <p style={{ fontSize: 12, opacity: 0.7 }}>
                    Check each host against the program page before adding it. These were read out
                    of your documents — a document is a claim about authorization, not authorization
                    itself, and scope is what decides whether a request is legitimate. Hosts your
                    documents mark out-of-scope are added as exclusions automatically.
                  </p>
                </>
              )}

              {proposal.exclude.length > 0 && (
                <>
                  <h4 style={{ marginBottom: 4 }}>Documents say these are OUT of scope</h4>
                  <p className="mono" style={{ fontSize: 12, color: '#f0868e' }}>
                    {proposal.exclude.map((c) => c.host).join(', ')}
                  </p>
                </>
              )}
            </>
          )}
        </div>

        {/* ---- program + authorization ---- */}
        <div className="card">
          <h3 style={{ marginTop: 0 }}>Engagement</h3>
          <div className="row" style={{ flexWrap: 'wrap', gap: 16 }}>
            <label className="row" style={{ gap: 6 }}>
              Program
              <input
                style={{ width: 220 }}
                value={profile.program}
                onChange={(e) => setProfile({ ...profile, program: e.target.value })}
                onBlur={() => void save(profile)}
              />
            </label>
            <label className="row" style={{ gap: 6 }}>
              Platform
              <input
                style={{ width: 150 }}
                placeholder="hackerone"
                value={profile.platform}
                onChange={(e) => setProfile({ ...profile, platform: e.target.value })}
                onBlur={() => void save(profile)}
              />
            </label>
            <label className="row" style={{ gap: 6 }}>
              Handle
              <input
                style={{ width: 150 }}
                value={profile.handle}
                onChange={(e) => setProfile({ ...profile, handle: e.target.value })}
                onBlur={() => void save(profile)}
              />
            </label>
          </div>
          <label className="row" style={{ gap: 6, marginTop: 10 }}>
            Authorization reference
            <input
              style={{ width: 460 }}
              placeholder="program URL, engagement ticket, or signed scope document"
              value={profile.authorizationRef}
              onChange={(e) => setProfile({ ...profile, authorizationRef: e.target.value })}
              onBlur={() => void save(profile)}
            />
          </label>
          <p style={{ fontSize: 12, opacity: 0.7 }}>
            Preflight treats a missing authorization reference as a blocker. A finding produced
            without one cannot be defended after the fact.
          </p>
        </div>

        {/* ---- identity ---- */}
        <div className="card">
          <h3 style={{ marginTop: 0 }}>Traffic identity</h3>
          <div className="row" style={{ flexWrap: 'wrap', gap: 16 }}>
            <label className="row" style={{ gap: 6 }}>
              Required User-Agent
              <input
                className="mono"
                style={{ width: 380 }}
                placeholder="e.g. greynoc-research (h1: greynoc)"
                value={ua.required}
                onChange={(e) =>
                  setProfile({ ...profile, userAgent: { ...ua, required: e.target.value } })
                }
                onBlur={() => void save(profile)}
              />
            </label>
            <label className="row" style={{ gap: 6 }}>
              <input
                type="checkbox"
                checked={ua.enforce}
                onChange={(e) =>
                  void save({ ...profile, userAgent: { ...ua, enforce: e.target.checked } })
                }
              />
              Enforce on every generated request
            </label>
          </div>

          <table className="grid" style={{ marginTop: 12 }}>
            <thead>
              <tr>
                <th>Identity header</th>
                <th>Value</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {profile.identityHeaders.map((header, index) => (
                <tr key={index}>
                  <td>
                    <input
                      className="mono"
                      style={{ width: 200 }}
                      value={header.name}
                      onChange={(e) => {
                        const next = [...profile.identityHeaders];
                        next[index] = { ...header, name: e.target.value };
                        setProfile({ ...profile, identityHeaders: next });
                      }}
                      onBlur={() => void save(profile)}
                    />
                  </td>
                  <td>
                    <input
                      className="mono"
                      style={{ width: 260 }}
                      value={header.value}
                      onChange={(e) => {
                        const next = [...profile.identityHeaders];
                        next[index] = { ...header, value: e.target.value };
                        setProfile({ ...profile, identityHeaders: next });
                      }}
                      onBlur={() => void save(profile)}
                    />
                  </td>
                  <td>
                    <button
                      className="ghost"
                      onClick={() =>
                        void save({
                          ...profile,
                          identityHeaders: profile.identityHeaders.filter((_, i) => i !== index),
                        })
                      }
                    >
                      Remove
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          <button
            className="ghost"
            style={{ marginTop: 8 }}
            onClick={() =>
              setProfile({
                ...profile,
                identityHeaders: [...profile.identityHeaders, { name: '', value: '' }],
              })
            }
          >
            Add header
          </button>
          <p style={{ fontSize: 12, opacity: 0.7 }}>
            When enforcement is on, the Repeater and the Variation engine rewrite every request they
            generate to carry these. Traffic captured through the proxy is never rewritten — your
            browser’s User-Agent is not ours to change.
          </p>
        </div>

        {/* ---- workspace ---- */}
        <div className="card">
          <h3 style={{ marginTop: 0 }}>Engagement folder</h3>
          <div className="row" style={{ gap: 8 }}>
            <input
              className="mono"
              style={{ width: 460 }}
              placeholder="(the project directory)"
              value={profile.workspaceDir}
              onChange={(e) => setProfile({ ...profile, workspaceDir: e.target.value })}
              onBlur={() => void save(profile)}
            />
            <button className="ghost" onClick={() => void chooseWorkspace()}>
              Choose…
            </button>
          </div>
          <p style={{ fontSize: 12, opacity: 0.7 }}>
            Where the program policy, scope document, prior reports, and your notes live. Recon
            reads it before anything is planned. Access is read-only and confined to this folder,
            and the project’s own database, blobs, and secrets are never served — but everything
            else in it is sent to the model provider during a run, so point it at a folder you are
            willing to expose.
          </p>
          {report?.workspace.notableFiles.length ? (
            <p className="mono" style={{ fontSize: 12, opacity: 0.8 }}>
              {report.workspace.fileCount} document(s) · {report.workspace.notableFiles.join(', ')}
            </p>
          ) : null}
          {scan && scan.filesSeen > 0 ? (
            <div style={{ marginTop: 12 }}>
              <div className="row" style={{ gap: 10, flexWrap: 'wrap', fontSize: 12 }}>
                {(['scope', 'engagement', 'report', 'recon', 'notes', 'other'] as const).map((k) =>
                  scan.byKind[k] ? (
                    <span key={k} className="chip">
                      {scan.byKind[k]} {k}
                    </span>
                  ) : null,
                )}
              </div>
              <p style={{ fontSize: 12, opacity: 0.7, margin: '8px 0 4px' }}>
                Read {scan.filesRead} of {scan.filesSeen}, most relevant first. Classification is
                deterministic and never authorizes anything — scope still comes from the card below,
                and you still tick each host.
              </p>
              <table className="grid">
                <tbody>
                  {scan.docs.slice(0, 12).map((d) => (
                    <tr key={d.path}>
                      <td style={{ whiteSpace: 'nowrap', opacity: 0.85 }}>{d.kind}</td>
                      <td>
                        <span className="mono">{d.path}</span>
                        <div style={{ fontSize: 11, opacity: 0.65 }}>
                          {d.reasons.slice(0, 3).join(' · ')}
                          {d.nameOnly ? ' · filename only (not read)' : ''}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {scan.notes.map((n) => (
                <p key={n} style={{ fontSize: 11, opacity: 0.6, margin: '6px 0 0' }}>
                  {n}
                </p>
              ))}
            </div>
          ) : null}
          {report?.workspace.suggestedRoot ? (
            <div className="warn-box" style={{ marginTop: 10 }}>
              <div>
                Nothing to read here — this folder holds the project database and no documents. The
                project sits inside <span className="mono">{report.workspace.suggestedRoot}</span>,
                which has {report.workspace.suggestedFileCount ?? 0} document(s) in it. That is
                almost certainly where your engagement material is.
              </div>
              <div style={{ fontSize: 12, opacity: 0.8, marginTop: 6 }}>
                Everything in that folder becomes readable by the AI and is sent to the model
                provider during a run. Check what is in it before switching.
              </div>
              <button
                className="ghost"
                style={{ marginTop: 8 }}
                onClick={() =>
                  void save({ ...profile, workspaceDir: report.workspace.suggestedRoot as string })
                }
              >
                Use that folder
              </button>
            </div>
          ) : null}
        </div>

        {/* ---- certificate lifecycle ---- */}
        <div className="card">
          <h3 style={{ marginTop: 0 }}>Interception certificate</h3>
          {report && (
            <p className="mono" style={{ fontSize: 12, opacity: 0.85 }}>
              {report.ca.interceptionEnabled
                ? report.ca.certificate
                  ? `${report.ca.certificate.subject} · ${report.ca.certificate.daysRemaining} day(s) left · SHA-256 ${report.ca.certificate.fingerprint}`
                  : 'active'
                : `REVOKED${report.ca.revokedReason ? ` — ${report.ca.revokedReason}` : ''} · HTTPS is passing through unread`}
              {' · '}
              {report.ca.observedHttpsExchanges} decrypted HTTPS exchange(s) captured
            </p>
          )}
          <div className="row" style={{ gap: 8 }}>
            <button className="ghost" disabled={busy} onClick={() => void rotate()}>
              Issue new CA
            </button>
            <button className="ghost" disabled={busy} onClick={() => void revoke()}>
              Revoke CA
            </button>
          </div>
          <p style={{ fontSize: 12, opacity: 0.7 }}>
            Issuing a new CA invalidates the one your browser trusts — you must install the new
            certificate before HTTPS capture works again. Revoking turns interception off entirely
            until you issue one. Both are written to the audit log.
          </p>
          {report?.ca.history.length ? (
            <table className="grid" style={{ marginTop: 10 }}>
              <thead>
                <tr>
                  <th>When</th>
                  <th>Action</th>
                  <th>Reason</th>
                  <th>Fingerprint</th>
                </tr>
              </thead>
              <tbody>
                {report.ca.history.slice(0, 10).map((entry) => (
                  <tr key={`${entry.fingerprint}-${entry.revokedAt}`}>
                    <td>{new Date(entry.revokedAt).toLocaleString()}</td>
                    <td>{entry.action}</td>
                    <td>{entry.reason || '—'}</td>
                    <td className="mono" style={{ fontSize: 11 }}>
                      {entry.fingerprint.slice(0, 23)}…
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : null}
        </div>
      </div>
    </div>
  );
}
