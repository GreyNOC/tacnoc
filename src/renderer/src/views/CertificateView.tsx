/**
 * CA Certificate — the guided, optional setup for HTTPS interception.
 *
 * This is the step people get wrong, and getting it wrong is silent: the proxy
 * runs, the browser browses, and no HTTPS is ever captured. The old screen was a
 * fingerprint, a warning, and a paragraph of prose the operator had to translate
 * into a sequence of dialogs — with nothing anywhere confirming it had worked.
 *
 * So this screen is four steps that each say what to do and, at the end, one
 * that checks. The check reads DECRYPTED PROXY TRAFFIC, not configuration:
 * whether the browser trusts this CA is a fact about the browser, and the only
 * honest evidence is an HTTPS exchange the proxy actually decrypted.
 *
 * It is also genuinely optional, and says so first. Plain HTTP is captured with
 * no certificate at all, and a project is perfectly usable without ever
 * installing one — so the guide can be dismissed, and it collapses itself once
 * interception is verified rather than nagging an operator who is already set up.
 *
 * The app still never touches the OS trust store. Each step hands over a command
 * to run, quoted for the operator's own shell by the engine; the operator runs
 * it, and the removal command sits next to the install command throughout.
 */

import React, { useCallback, useEffect, useState } from 'react';
import { api } from '../api.js';
import { useStore } from '../store.js';
import type { CaInfoDto } from '@shared/ipc.js';
import type { CaInstallGuide, CaInstallStep } from '@engine/ca/installInstructions.js';

/** Poll interval while the operator is sitting on the verify step, waiting. */
const VERIFY_POLL_MS = 3000;

export function CertificateView(): JSX.Element {
  const s = useStore();
  const [ca, setCa] = useState<CaInfoDto | null>(null);
  const [guide, setGuide] = useState<CaInstallGuide | null>(null);
  const [acknowledged, setAcknowledged] = useState(false);
  const [savedPath, setSavedPath] = useState<string | null>(null);
  const [dismissed, setDismissed] = useState(false);
  /** Operator asked to see the steps even though nothing is prompting them to. */
  const [forceShow, setForceShow] = useState(false);
  const [showDetails, setShowDetails] = useState(false);
  const [checking, setChecking] = useState(false);

  const refresh = useCallback(async (): Promise<void> => {
    const info = await api.getCaInfo();
    setCa(info);
    // Only adopt the generic guide when we have not already rendered one for a
    // real saved path — re-fetching CA info must not throw away the command the
    // operator is in the middle of copying.
    setGuide((prev) => prev ?? info.installGuide);
  }, []);

  // Re-read on 'ca-changed'. The CA can be replaced or destroyed from outside
  // this view — Engagement rotates and revokes it, and the mesh can too when
  // cert ops are granted. Without this the page kept presenting a fingerprint
  // and a PEM for a certificate that no longer existed.
  useEffect(() => {
    void refresh();
    return api.onEvent((e) => {
      if (e.type === 'ca-changed') {
        // A new CA invalidates the one the browser trusts, so the guide starts
        // over: the saved file is stale and the old install no longer works.
        setSavedPath(null);
        setGuide(null);
        setDismissed(false);
        setForceShow(false);
        void refresh();
      } else if (e.type === 'proxy-state') {
        void refresh();
      }
    });
  }, [refresh]);

  const verified = (ca?.interceptedHttpsExchanges ?? 0) > 0;
  /**
   * Stand the guide down when it has nothing to ask for — already working, or
   * explicitly skipped — unless the operator asked to see it anyway.
   */
  const collapsed = (dismissed || verified) && !forceShow;

  /**
   * While the operator is on the verify step and it has not passed yet, poll.
   *
   * Bounded deliberately: it stops the moment interception is verified, and it
   * never runs when the guide is dismissed or the CA is revoked. An unbounded
   * re-read keyed on captured traffic is what made two other views re-fetch on
   * every proxied request.
   */
  useEffect(() => {
    if (verified || dismissed || !ca || !ca.certPem) return;
    const t = setInterval(() => void refresh(), VERIFY_POLL_MS);
    return () => clearInterval(t);
  }, [verified, dismissed, ca, refresh]);

  /**
   * The moment interception starts working, the guide has nothing left to ask
   * for — so stand it down even if it was opened by hand.
   *
   * Keyed on `verified` alone, deliberately: it fires when interception first
   * succeeds, and does NOT fire again when the operator clicks "Show the steps
   * anyway" afterwards, so that button still works.
   */
  useEffect(() => {
    if (verified) setForceShow(false);
  }, [verified]);

  const save = async (): Promise<void> => {
    try {
      const p = await api.saveCaCertificate();
      if (p) {
        setSavedPath(p);
        // Re-render the commands against the real path, quoted for this shell.
        setGuide(await api.getCaInstallGuide(p));
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

  const checkNow = async (): Promise<void> => {
    setChecking(true);
    try {
      await refresh();
    } finally {
      setChecking(false);
    }
  };

  if (!ca) return <div className="empty">Loading CA…</div>;

  // A revoked project has no certificate. Say so where the fingerprint would be,
  // rather than rendering an empty PEM pane under an enabled Save button.
  const revoked = !ca.certPem;
  const proxyTarget = ca.proxyRunning ? `${ca.proxyHost}:${ca.proxyPort}` : '127.0.0.1:8080';

  return (
    <div className="view">
      <div className="scrolly">
        {/* ---- what this is for, and that you can skip it ---- */}
        <div className="card">
          <div
            className="row"
            style={{ justifyContent: 'space-between', alignItems: 'flex-start' }}
          >
            <div>
              <h3 style={{ marginTop: 0, marginBottom: 4 }}>Read HTTPS traffic (optional)</h3>
              <p className="hint" style={{ margin: 0, maxWidth: 720 }}>
                TACNOC captures plain <span className="mono">http://</span> traffic with no setup at
                all. To read <span className="mono">https://</span> as well, your test browser has
                to trust this project&rsquo;s certificate. That is what the steps below do — about a
                minute, and reversible with one command.
              </p>
            </div>
            <span className={`chip ${verified ? 'on' : 'off'}`}>
              <span className="dot" />
              {verified ? 'HTTPS interception working' : 'HTTPS not set up'}
            </span>
          </div>

          {verified && (
            <div className="ok-box" style={{ marginTop: 10 }}>
              <strong>This is done.</strong> {ca.interceptedHttpsExchanges} HTTPS exchange(s) have
              been decrypted through the proxy in this project, so the browser you tested with does
              trust this CA. Nothing here needs doing again unless you issue a new CA.
            </div>
          )}
        </div>

        {revoked && (
          <div className="card">
            <div className="danger-box" style={{ margin: 0 }}>
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
              , then come back and run these steps.
            </div>
          </div>
        )}

        {/* ---- the guide ---- */}
        {!revoked &&
          (collapsed ? (
            <div className="card">
              <div className="row" style={{ justifyContent: 'space-between' }}>
                <span className="hint">
                  {verified
                    ? 'Setup steps are hidden because interception is already working.'
                    : 'Setup skipped. HTTP is still captured; HTTPS is not.'}
                </span>
                <button
                  onClick={() => {
                    setDismissed(false);
                    // An explicit override, because `verified` does not go away
                    // when the operator asks to see the steps again — without it
                    // the button announced itself and then did nothing.
                    setForceShow(true);
                  }}
                >
                  {verified ? 'Show the steps anyway' : 'Set up HTTPS interception'}
                </button>
              </div>
            </div>
          ) : (
            <>
              <Step
                index={1}
                done={!!savedPath}
                title="Save the certificate to a file"
                body={
                  <>
                    <p className="hint" style={{ marginTop: 0 }}>
                      This is the public certificate only — it is meant to be shared. The private
                      key stays where it is: {ca.backendName}
                      {ca.secureBackend ? '.' : ' — NOT encrypted on this install.'}
                    </p>
                    <div className="danger-box">
                      <strong>Trusting this CA is powerful.</strong> Any site whose certificate is
                      signed by it will be trusted by whatever you install it into — including a
                      real attacker holding this key. Install it <em>only</em> into the browser or
                      profile you use for this authorized engagement, and remove it when you are
                      finished. TACNOC never modifies your operating system trust store for you.
                    </div>
                    <label className="row" style={{ gap: 6, margin: '10px 0' }}>
                      <input
                        type="checkbox"
                        checked={acknowledged}
                        onChange={(e) => setAcknowledged(e.target.checked)}
                      />
                      I understand the risk and am authorized to intercept traffic in this
                      environment.
                    </label>
                    <button className="primary" disabled={!acknowledged} onClick={save}>
                      Save CA certificate to file…
                    </button>
                    {savedPath && <p className="hint mono">Saved to {savedPath}</p>}
                  </>
                }
              />

              <Step
                index={2}
                done={false}
                pending={!savedPath}
                title={`Trust it — ${guide?.platformLabel ?? 'your platform'}`}
                body={
                  !savedPath ? (
                    <p className="hint" style={{ margin: 0 }}>
                      Save the certificate first; the command below needs its path.
                    </p>
                  ) : (
                    <>
                      <p className="hint" style={{ marginTop: 0 }}>
                        Run this in {guide?.shell ?? 'a terminal'}. TACNOC does not run it for you —
                        changing what your machine trusts is your decision to make deliberately.
                      </p>
                      {guide?.steps.map((step, i) => (
                        <GuideStep key={i} step={step} onCopy={(t) => copy(t, s.setToast)} />
                      ))}
                      {guide && (
                        <div className="warn-box">
                          <strong>Undo, whenever you want:</strong> {guide.removal.detail}
                          <CommandRow
                            command={guide.removal.command ?? ''}
                            onCopy={(t) => copy(t, s.setToast)}
                          />
                        </div>
                      )}
                      {guide?.separateTrustStoreNote && (
                        <p className="hint">{guide.separateTrustStoreNote}</p>
                      )}
                    </>
                  )
                }
              />

              <Step
                index={3}
                done={ca.proxyRunning}
                title="Point your browser at the proxy"
                body={
                  <>
                    <p className="hint" style={{ marginTop: 0 }}>
                      Set your test browser&rsquo;s HTTP <em>and</em> HTTPS proxy to{' '}
                      <span className="mono">{proxyTarget}</span>. A browser that only proxies HTTP
                      will never send the <span className="mono">CONNECT</span> that HTTPS
                      interception depends on.
                    </p>
                    {ca.proxyRunning ? (
                      <p className="hint">
                        The proxy is running on <span className="mono">{proxyTarget}</span>.
                      </p>
                    ) : (
                      <div className="row" style={{ gap: 8 }}>
                        <span className="hint">The proxy is not running.</span>
                        <button
                          onClick={() => {
                            void api
                              .startProxy()
                              .then(() => {
                                s.refreshProxy();
                                return refresh();
                              })
                              .catch((err: unknown) =>
                                s.setToast(
                                  `Could not start the proxy: ${err instanceof Error ? err.message : String(err)}`,
                                ),
                              );
                          }}
                        >
                          Start the proxy
                        </button>
                      </div>
                    )}
                  </>
                }
              />

              <Step
                index={4}
                done={verified}
                title="Check that it worked"
                body={
                  <>
                    <p className="hint" style={{ marginTop: 0 }}>
                      Visit any <span className="mono">https://</span> page in that browser. This
                      counts HTTPS exchanges the proxy actually decrypted — traffic the Repeater or
                      Variation sends does not count, because the engine sends that over its own TLS
                      and it would succeed whether or not anything trusts this CA.
                    </p>
                    <div className={verified ? 'ok-box' : 'warn-box'}>
                      {verified ? (
                        <>
                          <strong>Working.</strong> {ca.interceptedHttpsExchanges} decrypted HTTPS
                          exchange(s) captured through the proxy.
                        </>
                      ) : (
                        <>
                          <strong>No decrypted HTTPS yet.</strong> If you have already browsed an
                          HTTPS page through the proxy, the usual causes are: the browser was not
                          restarted after the certificate was installed, the browser keeps its own
                          certificate store (Firefox does), or only the HTTP proxy was set.
                        </>
                      )}
                    </div>
                    <button onClick={() => void checkNow()} disabled={checking}>
                      {checking ? 'Checking…' : 'Check again'}
                    </button>
                  </>
                }
              />

              <div className="card">
                <div className="row" style={{ justifyContent: 'space-between' }}>
                  <span className="hint">
                    Not now? HTTP traffic is captured either way, and you can come back to this at
                    any time.
                  </span>
                  <button
                    className="ghost"
                    onClick={() => {
                      setDismissed(true);
                      setForceShow(false);
                    }}
                  >
                    Skip for now
                  </button>
                </div>
              </div>
            </>
          ))}

        {/* ---- reference: always reachable, never in the way ---- */}
        <div className="card">
          <div className="row" style={{ justifyContent: 'space-between' }}>
            <h3 style={{ margin: 0 }}>Certificate details</h3>
            <button className="ghost" onClick={() => setShowDetails((v) => !v)}>
              {showDetails ? 'Hide' : 'Show'}
            </button>
          </div>
          {showDetails && (
            <>
              <dl className="kv" style={{ marginTop: 12 }}>
                <dt>SHA-256 fingerprint</dt>
                <dd>{revoked ? 'none — this project’s CA was revoked' : ca.fingerprint}</dd>
                <dt>Key protection</dt>
                <dd>{ca.backendName}</dd>
                <dt>Decrypted HTTPS captured</dt>
                <dd>{ca.interceptedHttpsExchanges}</dd>
              </dl>
              <p className="hint">{ca.installInstructions}</p>
              {!revoked && (
                <>
                  <div className="pane-title" style={{ marginTop: 8 }}>
                    Certificate (PEM)
                  </div>
                  <pre className="message" style={{ maxHeight: 220 }}>
                    {ca.certPem}
                  </pre>
                </>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  );
}

/** One numbered step in the guide. */
function Step(props: {
  index: number;
  title: string;
  done: boolean;
  pending?: boolean;
  body: React.ReactNode;
}): JSX.Element {
  return (
    <div
      className={`card step ${props.done ? 'step-done' : ''} ${props.pending ? 'step-pending' : ''}`}
    >
      <div className="row" style={{ gap: 10, alignItems: 'center' }}>
        <span className="step-badge">{props.done ? '✓' : props.index}</span>
        <h3 style={{ margin: 0 }}>{props.title}</h3>
      </div>
      <div style={{ marginTop: 10 }}>{props.body}</div>
    </div>
  );
}

function GuideStep(props: { step: CaInstallStep; onCopy: (text: string) => void }): JSX.Element {
  const { step } = props;
  return (
    <div style={{ marginBottom: 12 }}>
      <strong>{step.title}</strong>
      <p className="hint" style={{ margin: '4px 0' }}>
        {step.detail}
      </p>
      {step.command && <CommandRow command={step.command} onCopy={props.onCopy} />}
      {step.commandNote && (
        <p className="hint" style={{ margin: '4px 0 0' }}>
          {step.commandNote}
        </p>
      )}
    </div>
  );
}

function CommandRow(props: {
  command: string;
  onCopy: (text: string) => void;
}): JSX.Element | null {
  if (!props.command) return null;
  return (
    <div className="command-row">
      <code className="mono">{props.command}</code>
      <button className="ghost" onClick={() => props.onCopy(props.command)}>
        Copy
      </button>
    </div>
  );
}

/**
 * Copy to the clipboard, and say so — including when it fails.
 *
 * A copy button that silently does nothing is worse than no copy button: the
 * operator pastes whatever was already on the clipboard into a shell.
 */
function copy(text: string, setToast: (m?: string) => void): void {
  void navigator.clipboard
    .writeText(text)
    .then(() => setToast('Command copied to the clipboard.'))
    .catch(() => setToast('Could not copy — select the command and copy it manually.'));
}
