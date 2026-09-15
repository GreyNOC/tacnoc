import React, { useEffect, useState } from 'react';
import { useStore, type ViewId } from './store.js';
import { Welcome } from './views/Welcome.js';
import { HistoryView } from './views/HistoryView.js';
import { InterceptView } from './views/InterceptView.js';
import { RepeaterView } from './views/RepeaterView.js';
import { FindingsView } from './views/FindingsView.js';
import { ScopeView } from './views/ScopeView.js';
import { VariationView } from './views/VariationView.js';
import { EncoderView } from './views/EncoderView.js';
import { CompareView } from './views/CompareView.js';
import { CertificateView } from './views/CertificateView.js';
import { ExtensionsView } from './views/ExtensionsView.js';
import { AuditView } from './views/AuditView.js';
import { SettingsView } from './views/SettingsView.js';
import { TargetView } from './views/TargetView.js';
import { SequencerView } from './views/SequencerView.js';
import { AiMeshView } from './views/AiMeshView.js';
import { EngagementView } from './views/EngagementView.js';
import { api } from './api.js';
import { OwlMark } from './components/OwlMark.js';

const NAV: { group: string; items: { id: ViewId; label: string }[] }[] = [
  {
    group: 'Traffic',
    items: [
      { id: 'target', label: 'Target Map' },
      { id: 'history', label: 'HTTP History' },
      { id: 'intercept', label: 'Intercept' },
    ],
  },
  {
    group: 'Workbench',
    items: [
      { id: 'repeater', label: 'Repeater' },
      { id: 'variation', label: 'Variation' },
      { id: 'sequencer', label: 'Sequencer' },
      { id: 'encoder', label: 'Encoder / Decoder' },
      { id: 'compare', label: 'Compare' },
    ],
  },
  {
    group: 'AI',
    items: [{ id: 'ai', label: 'AI Mesh' }],
  },
  {
    group: 'Analysis',
    items: [
      { id: 'findings', label: 'Findings' },
      { id: 'scope', label: 'Scope' },
      { id: 'audit', label: 'Audit Log' },
    ],
  },
  {
    group: 'Project',
    items: [
      { id: 'engagement', label: 'Engagement' },
      { id: 'certificate', label: 'CA Certificate' },
      { id: 'extensions', label: 'Extensions' },
      { id: 'settings', label: 'Settings' },
    ],
  },
];

/**
 * Minimise / maximise / close for the frameless window.
 *
 * Only rendered where the OS chrome is actually gone. On macOS the native
 * traffic lights are still there (the title bar is hidden, not removed), and
 * drawing a second set of controls beside them would be both redundant and
 * wrong-handed.
 */
function WindowControls(): JSX.Element | null {
  const [show, setShow] = useState(false);
  const [maximized, setMaximized] = useState(false);

  useEffect(() => {
    void api
      .windowUsesCustomControls()
      .then(setShow)
      .catch(() => setShow(false));
    void api
      .windowIsMaximized()
      .then(setMaximized)
      .catch(() => undefined);
  }, []);

  if (!show) return null;
  return (
    <div className="window-controls no-drag">
      <button
        className="win-btn"
        aria-label="Minimize"
        title="Minimize"
        onClick={() => void api.windowMinimize()}
      >
        <svg viewBox="0 0 10 10" aria-hidden="true">
          <path d="M0 5h10" stroke="currentColor" strokeWidth="1" />
        </svg>
      </button>
      <button
        className="win-btn"
        aria-label={maximized ? 'Restore' : 'Maximize'}
        title={maximized ? 'Restore' : 'Maximize'}
        onClick={() => void api.windowToggleMaximize().then(setMaximized)}
      >
        <svg viewBox="0 0 10 10" aria-hidden="true">
          {maximized ? (
            <path
              d="M2.5 2.5h5v5h-5zM0.5 7.5v-7h7"
              fill="none"
              stroke="currentColor"
              strokeWidth="1"
            />
          ) : (
            <rect x="0.5" y="0.5" width="9" height="9" fill="none" stroke="currentColor" />
          )}
        </svg>
      </button>
      <button
        className="win-btn close"
        aria-label="Close"
        title="Close"
        onClick={() => void api.windowClose()}
      >
        <svg viewBox="0 0 10 10" aria-hidden="true">
          <path d="M0 0l10 10M10 0L0 10" stroke="currentColor" strokeWidth="1" />
        </svg>
      </button>
    </div>
  );
}

function TopBar(): JSX.Element {
  const s = useStore();
  const pendingCount = s.pendingRequests.length + s.pendingResponses.length;
  const activeJobs = s.jobs.filter((j) => j.status === 'running' || j.status === 'paused').length;

  /**
   * The only control that starts the proxy, so its failures have to be visible.
   *
   * Both calls reject for ordinary reasons — the port is already taken, or no
   * project is open (this bar renders on the welcome screen too). Neither was
   * caught, so the click produced an unhandled rejection, the chip stayed on
   * "Proxy off", and nothing anywhere said why.
   */
  const toggleProxy = async (): Promise<void> => {
    try {
      if (s.proxy.running) await api.stopProxy();
      else await api.startProxy();
    } catch (err) {
      s.setToast(
        `Could not ${s.proxy.running ? 'stop' : 'start'} the proxy: ${
          err instanceof Error ? err.message : String(err)
        }`,
      );
    } finally {
      s.refreshProxy();
    }
  };

  // The window is frameless, so this bar is the title bar: it is the drag
  // region, and every interactive child opts back out with `no-drag` or it
  // cannot be clicked.
  return (
    <div className="topbar drag">
      <div className="brand">
        <OwlMark className="logo" />
        <span>TACNOC</span>
        <small>authorized testing</small>
      </div>
      {s.project && <span className="chip">{s.project.name}</span>}
      <div className="spacer" />

      <button
        className={`chip ${s.proxy.running ? 'on' : 'off'}`}
        onClick={toggleProxy}
        title="Toggle proxy"
      >
        <span className="dot" />
        {s.proxy.running ? `Proxy ${s.proxy.host}:${s.proxy.port}` : 'Proxy off'}
      </button>
      {s.proxy.running && !s.proxy.loopbackOnly && (
        <span className="chip warn" title="Listener is not loopback-only">
          non-loopback bind
        </span>
      )}
      {/* Either direction counts. Keyed on requests alone, the chip read
          "Intercept off (1)" while a response sat held in the queue. */}
      <span
        className={`chip ${
          s.intercept.interceptRequests || s.intercept.interceptResponses ? 'on' : 'off'
        }`}
      >
        <span className="dot" />
        Intercept {s.intercept.interceptRequests || s.intercept.interceptResponses ? 'on' : 'off'}
        {pendingCount > 0 ? ` (${pendingCount})` : ''}
      </span>
      <span className={`chip ${activeJobs ? 'on' : 'off'}`}>
        <span className="dot" />
        Jobs {activeJobs}
      </span>
      <button className="estop" onClick={s.emergencyStop} title="Halt all automated work">
        ■ EMERGENCY STOP
      </button>
      <button className="ghost" onClick={s.toggleTheme} title="Toggle theme">
        {s.theme === 'dark' ? '☾' : '☀'}
      </button>
      <WindowControls />
    </div>
  );
}

function Sidebar(): JSX.Element {
  const s = useStore();
  return (
    <nav className="sidebar" aria-label="Primary">
      {NAV.map((grp) => (
        <div key={grp.group}>
          <div className="nav-group-title">{grp.group}</div>
          {grp.items.map((it) => {
            const badge =
              it.id === 'findings' && s.findingsCount > 0
                ? s.findingsCount
                : it.id === 'intercept' && s.pendingRequests.length + s.pendingResponses.length > 0
                  ? s.pendingRequests.length + s.pendingResponses.length
                  : undefined;
            return (
              <button
                key={it.id}
                className={`nav-item ${s.view === it.id ? 'active' : ''}`}
                onClick={() => s.setView(it.id)}
                aria-current={s.view === it.id ? 'page' : undefined}
              >
                {it.label}
                {badge !== undefined && <span className="count">{badge}</span>}
              </button>
            );
          })}
        </div>
      ))}
    </nav>
  );
}

function ActiveView(): JSX.Element {
  const { view } = useStore();
  switch (view) {
    case 'target':
      return <TargetView />;
    case 'history':
      return <HistoryView />;
    case 'intercept':
      return <InterceptView />;
    case 'repeater':
      return <RepeaterView />;
    case 'findings':
      return <FindingsView />;
    case 'scope':
      return <ScopeView />;
    case 'variation':
      return <VariationView />;
    case 'sequencer':
      return <SequencerView />;
    case 'ai':
      return <AiMeshView />;
    case 'encoder':
      return <EncoderView />;
    case 'compare':
      return <CompareView />;
    case 'engagement':
      return <EngagementView />;
    case 'certificate':
      return <CertificateView />;
    case 'extensions':
      return <ExtensionsView />;
    case 'audit':
      return <AuditView />;
    case 'settings':
      return <SettingsView />;
    default:
      return <HistoryView />;
  }
}

function Toast(): JSX.Element | null {
  const s = useStore();
  // Keyed on the message, not the store: the store value changes on every
  // captured exchange, which restarted this timer each time and left the toast
  // pinned on screen for as long as traffic kept arriving.
  const { toast, setToast } = s;
  useEffect(() => {
    if (!toast) return;
    const t = setTimeout(() => setToast(undefined), 4000);
    return () => clearTimeout(t);
  }, [toast, setToast]);
  if (!s.toast) return null;
  return (
    <div style={{ position: 'fixed', bottom: 16, right: 16, zIndex: 50 }}>
      <div className="warn-box" role="status">
        {s.toast}
      </div>
    </div>
  );
}

export function App(): JSX.Element {
  const s = useStore();
  if (!s.project) {
    return (
      <div className="app">
        <TopBar />
        <Welcome />
        <Toast />
      </div>
    );
  }
  return (
    <div className="app">
      <TopBar />
      <div className="body">
        <Sidebar />
        <main className="main">
          <ActiveView />
        </main>
      </div>
      <Toast />
    </div>
  );
}
