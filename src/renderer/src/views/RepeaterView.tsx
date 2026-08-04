import React, { useEffect, useState } from 'react';
import { api } from '../api.js';
import { useStore } from '../store.js';
import type { RepeaterResult } from '@shared/repeater.js';
import type { ExchangeDetail } from '@shared/detail.js';
import type { SavedRequest } from '@shared/project.js';
import type { StoredCookie } from '@engine/repeater/cookieJar.js';
import { MessageViewer } from './MessageViewer.js';
import { bytesHuman } from '../lib/format.js';

const DEFAULT_RAW =
  'GET / HTTP/1.1\r\nHost: example.test\r\nUser-Agent: TACNOC\r\nAccept: */*\r\n\r\n';

export function RepeaterView(): JSX.Element {
  const s = useStore();
  const [scheme, setScheme] = useState('https');
  const [host, setHost] = useState('example.test');
  const [port, setPort] = useState(443);
  const [raw, setRaw] = useState(DEFAULT_RAW);
  const [followRedirects, setFollowRedirects] = useState(false);
  const [useCookieJar, setUseCookieJar] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<RepeaterResult | null>(null);
  const [detail, setDetail] = useState<ExchangeDetail | undefined>(undefined);
  const [saved, setSaved] = useState<SavedRequest[]>([]);
  const [cookies, setCookies] = useState<StoredCookie[]>([]);
  const [showCookies, setShowCookies] = useState(false);

  const loadSaved = (): void => void api.listSavedRequests().then(setSaved);
  const refreshCookies = (): void => void api.listCookies().then(setCookies);

  useEffect(() => {
    loadSaved();
    refreshCookies();
  }, []);

  useEffect(() => {
    if (s.repeaterSeed) {
      setScheme(s.repeaterSeed.scheme);
      setHost(s.repeaterSeed.host);
      setPort(s.repeaterSeed.port);
      setRaw(s.repeaterSeed.raw);
    }
  }, [s.repeaterSeed]);

  const send = async (): Promise<void> => {
    setBusy(true);
    setError(null);
    try {
      const res = await api.sendRepeater(
        { scheme, host, port, raw },
        { followRedirects, maxRedirects: 10, timeoutMs: 20000, useCookieJar },
      );
      setResult(res);
      const d = await api.getExchangeDetail(res.exchange.id);
      setDetail(d);
      if (useCookieJar) refreshCookies();
    } catch (e) {
      setError(String(e instanceof Error ? e.message : e));
    } finally {
      setBusy(false);
    }
  };

  const save = async (): Promise<void> => {
    await api.saveRequest({
      id: crypto.randomUUID(),
      name: `${host}${new Date().toISOString().slice(11, 19)}`,
      createdAt: Date.now(),
      scheme,
      host,
      port,
      raw,
    });
    s.setToast('Request saved.');
    loadSaved();
  };

  const loadRequest = (id: string): void => {
    const req = saved.find((r) => r.id === id);
    if (!req) return;
    setScheme(req.scheme);
    setHost(req.host);
    setPort(req.port);
    setRaw(req.raw);
  };

  const clearCookies = async (): Promise<void> => {
    await api.clearCookies();
    refreshCookies();
    s.setToast('Cookie jar cleared.');
  };

  return (
    <div className="view">
      <div className="toolbar">
        <select value={scheme} onChange={(e) => setScheme(e.target.value)} aria-label="Scheme">
          <option value="https">https</option>
          <option value="http">http</option>
        </select>
        <input
          style={{ width: 220 }}
          value={host}
          onChange={(e) => setHost(e.target.value)}
          placeholder="host"
        />
        <input
          type="number"
          style={{ width: 80 }}
          value={port}
          onChange={(e) => setPort(Number(e.target.value))}
          aria-label="port"
        />
        <label className="row" style={{ gap: 4 }}>
          <input
            type="checkbox"
            checked={followRedirects}
            onChange={(e) => setFollowRedirects(e.target.checked)}
          />
          follow redirects
        </label>
        <label className="row" style={{ gap: 4 }}>
          <input
            type="checkbox"
            checked={useCookieJar}
            onChange={(e) => setUseCookieJar(e.target.checked)}
          />
          cookie jar
        </label>
        <button className="ghost" onClick={() => setShowCookies((v) => !v)}>
          Cookies ({cookies.length})
        </button>
        <span className="spacer" style={{ flex: 1 }} />
        <select
          aria-label="Load saved request"
          value=""
          onChange={(e) => {
            if (e.target.value) loadRequest(e.target.value);
          }}
        >
          <option value="">Load saved…</option>
          {saved.map((r) => (
            <option key={r.id} value={r.id}>
              {r.name}
            </option>
          ))}
        </select>
        <button className="ghost" onClick={save}>
          Save
        </button>
        <button className="primary" onClick={send} disabled={busy}>
          {busy ? 'Sending…' : 'Send ▶'}
        </button>
      </div>

      {showCookies && (
        <div className="warn-box" style={{ margin: 8 }}>
          <div className="row">
            <strong>Cookie jar</strong>
            <span className="hint">
              {cookies.length} cookie(s) — applied to same-host requests when “cookie jar” is on
            </span>
            <span className="spacer" style={{ flex: 1 }} />
            <button className="ghost" onClick={refreshCookies}>
              Refresh
            </button>
            <button className="ghost" onClick={clearCookies} disabled={cookies.length === 0}>
              Clear jar
            </button>
          </div>
          {cookies.length > 0 && (
            <table className="grid" style={{ marginTop: 8 }}>
              <thead>
                <tr>
                  <th>Host</th>
                  <th>Name</th>
                  <th>Value</th>
                </tr>
              </thead>
              <tbody>
                {cookies.map((c, i) => (
                  <tr key={`${c.host}-${c.name}-${i}`}>
                    <td className="mono">{c.host}</td>
                    <td className="mono">{c.name}</td>
                    <td className="mono reveal-mask" title="cookie value (hidden)">
                      {c.value.length > 40 ? `${c.value.slice(0, 40)}…` : c.value}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}

      {error && (
        <div className="danger-box" style={{ margin: 8 }}>
          {error}
        </div>
      )}

      <div className="split h" style={{ flex: 1 }}>
        <div className="pane">
          <div className="pane-title">Request</div>
          <textarea
            style={{ flex: 1, border: 'none', borderRadius: 0 }}
            value={raw}
            onChange={(e) => setRaw(e.target.value)}
            spellCheck={false}
          />
        </div>
        <div className="pane">
          {result && (
            <div className="pane-title">
              <span className="mono">
                {result.exchange.response?.statusCode ?? 'ERR'} ·{' '}
                {bytesHuman(result.exchange.response?.body.size ?? 0)} · {result.totalMs}ms
              </span>
              {result.tls && (
                <span className="hint" style={{ marginLeft: 8 }}>
                  TLS {result.tls.protocol} {result.tls.cipherName} ·{' '}
                  {result.tls.authorized ? 'valid' : 'UNVERIFIED'}
                </span>
              )}
              {result.redirects.length > 0 && (
                <span className="hint" style={{ marginLeft: 8 }}>
                  {result.redirects.length} redirect(s)
                </span>
              )}
            </div>
          )}
          <MessageViewer
            title="Response"
            message={
              detail?.response
                ? {
                    headline: `${detail.response.httpVersion} ${detail.response.statusCode} ${detail.response.statusMessage}`,
                    ...detail.response,
                  }
                : undefined
            }
          />
        </div>
      </div>
    </div>
  );
}
