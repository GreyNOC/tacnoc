/**
 * Guided program setup.
 *
 * Deliberately not a second opinion about readiness: it renders `getPreflight()`
 * — the same report the mesh refuses to run against — ordered worst-first and
 * with each item wired to the place that fixes it. EngagementView shows the same
 * checks as reference detail beside the profile form; this is the one that tells
 * you what to do next, and it is where a new project lands.
 */

import React, { useCallback, useEffect, useState } from 'react';
import { api } from '../api.js';
import { useStore } from '../store.js';
import { destinationForCheck, type SetupDestination } from '@shared/guide.js';
import type { PreflightCheck, PreflightReport } from '@shared/engagement.js';

const SEVERITY_ORDER: Record<PreflightCheck['severity'], number> = {
  blocker: 0,
  warning: 1,
  ok: 2,
};

const SEVERITY_LABEL: Record<PreflightCheck['severity'], string> = {
  blocker: 'BLOCKER',
  warning: 'WARNING',
  ok: 'OK',
};

const ACTION_LABEL: Record<Exclude<SetupDestination, 'none'>, string> = {
  engagement: 'Open Engagement',
  scope: 'Open Scope',
  certificate: 'Open Certificate',
  history: 'Open HTTP History',
  proxy: 'Start the proxy',
};

export function SetupView(): JSX.Element {
  const s = useStore();
  const [report, setReport] = useState<PreflightReport | undefined>(undefined);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback((): void => {
    void api
      .getPreflight()
      .then((r) => {
        setReport(r);
        setError(null);
      })
      .catch((e) => setError(String(e instanceof Error ? e.message : e)));
  }, []);

  // Re-run whenever something that preflight measures could have moved: the
  // proxy starting, scope changing, a CA appearing, traffic arriving.
  useEffect(load, [load, s.proxy.running, s.exchangeTick, s.project]);

  const act = async (destination: SetupDestination): Promise<void> => {
    if (destination === 'none') return;
    if (destination === 'proxy') {
      setBusy(true);
      setError(null);
      try {
        await api.startProxy();
        load();
      } catch (e) {
        setError(String(e instanceof Error ? e.message : e));
      } finally {
        setBusy(false);
      }
      return;
    }
    s.setView(destination);
  };

  if (!report) {
    return (
      <div className="view">
        <div className="toolbar">
          <strong>Setup</strong>
        </div>
        <div className="card">{error ?? 'Reading the engagement…'}</div>
      </div>
    );
  }

  const checks = [...report.checks].sort(
    (a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity],
  );
  const blockers = checks.filter((c) => c.severity === 'blocker').length;
  const warnings = checks.filter((c) => c.severity === 'warning').length;

  return (
    <div className="view">
      <div className="toolbar">
        <strong>Setup</strong>
        <span className="hint">
          the same preflight the engine gates on — green here means it agrees you are ready
        </span>
        <span className="spacer" style={{ flex: 1 }} />
        <button className="ghost" onClick={s.startTour}>
          Take the walkthrough
        </button>
        <button className="ghost" onClick={load} disabled={busy}>
          Re-check
        </button>
      </div>

      <div className="setup-scroll">
        {report.ready ? (
          <div className="setup-banner ready">
            <strong>Ready to test.</strong> Nothing is blocking.{' '}
            {warnings > 0 ? `${warnings} ` : ''}
            {warnings === 1 ? 'warning is' : warnings > 1 ? 'warnings are' : 'No warnings are'}{' '}
            outstanding — worth reading, but they do not stop you.
          </div>
        ) : (
          <div className="setup-banner blocked">
            <strong>
              {blockers} {blockers === 1 ? 'blocker' : 'blockers'} to clear.
            </strong>{' '}
            Automated work stays fail-closed until these are done — the scope gate refuses
            everything rather than defaulting to permissive.
          </div>
        )}

        {error && <div className="danger-box">{error}</div>}

        <ol className="setup-list">
          {checks.map((check) => {
            const destination = destinationForCheck(check.id);
            return (
              <li key={`${check.id}-${check.title}`} className={`setup-item ${check.severity}`}>
                <div className="setup-item-head">
                  <span className={`setup-sev ${check.severity}`}>
                    {SEVERITY_LABEL[check.severity]}
                  </span>
                  <strong>{check.title}</strong>
                </div>
                <p className="setup-detail">{check.detail}</p>
                {check.remedy && <p className="setup-remedy">{check.remedy}</p>}
                {destination !== 'none' && check.severity !== 'ok' && (
                  <button onClick={() => void act(destination)} disabled={busy}>
                    {ACTION_LABEL[destination]}
                  </button>
                )}
              </li>
            );
          })}
        </ol>
      </div>
    </div>
  );
}
