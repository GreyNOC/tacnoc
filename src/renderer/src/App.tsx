import React, { useEffect } from 'react';
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
import { api } from './api.js';

function Logo(): JSX.Element {
  return (
    <svg className="logo" viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <path
        d="M12 2 3 6.5V12c0 5 3.8 8.4 9 10 5.2-1.6 9-5 9-10V6.5L12 2Z"
        stroke="var(--accent)"
        strokeWidth="1.6"
      />
      <path d="M8 12h8M12 8v8" stroke="var(--accent)" strokeWidth="1.6" strokeLinecap="round" />
    </svg>
  );
}

const NAV: { group: string; items: { id: ViewId; label: string }[] }[] = [
  {
    group: 'Traffic',
    items: [
      { id: 'history', label: 'HTTP History' },
      { id: 'intercept', label: 'Intercept' },
    ],
  },
  {
    group: 'Workbench',
    items: [
      { id: 'repeater', label: 'Repeater' },
      { id: 'variation', label: 'Variation' },
      { id: 'encoder', label: 'Encoder / Decoder' },
      { id: 'compare', label: 'Compare' },
    ],
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
      { id: 'certificate', label: 'CA Certificate' },
      { id: 'extensions', label: 'Extensions' },
    ],
  },
];

function TopBar(): JSX.Element {
  const s = useStore();
  const pendingCount = s.pendingRequests.length + s.pendingResponses.length;
  const activeJobs = s.jobs.filter((j) => j.status === 'running' || j.status === 'paused').length;

  const toggleProxy = async (): Promise<void> => {
    if (s.proxy.running) await api.stopProxy();
    else await api.startProxy();
    s.refreshProxy();
  };

  return (
    <div className="topbar">
      <div className="brand">
        <Logo />
        <span>GreyNOC Belcher</span>
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
      <span className={`chip ${s.intercept.interceptRequests ? 'on' : 'off'}`}>
        <span className="dot" />
        Intercept {s.intercept.interceptRequests ? 'on' : 'off'}
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
    case 'encoder':
      return <EncoderView />;
    case 'compare':
      return <CompareView />;
    case 'certificate':
      return <CertificateView />;
    case 'extensions':
      return <ExtensionsView />;
    case 'audit':
      return <AuditView />;
    default:
      return <HistoryView />;
  }
}

function Toast(): JSX.Element | null {
  const s = useStore();
  useEffect(() => {
    if (!s.toast) return;
    const t = setTimeout(() => s.setToast(undefined), 4000);
    return () => clearTimeout(t);
  }, [s]);
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
