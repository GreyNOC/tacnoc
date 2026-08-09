import React, { useEffect, useState } from 'react';
import { api } from '../api.js';
import { useStore } from '../store.js';
import type { HttpHeader } from '@shared/model.js';
import type { InterceptedRequestView, InterceptedResponseView } from '@shared/intercept.js';
import { b64ToText, textToB64 } from '../lib/format.js';

function reqToRaw(v: InterceptedRequestView): string {
  const headers = v.headers.map((h) => `${h.name}: ${h.value}`).join('\r\n');
  return `${v.method} ${v.target} ${v.httpVersion}\r\n${headers}\r\n\r\n${b64ToText(v.bodyBase64)}`;
}

function parseRaw(raw: string): {
  method: string;
  target: string;
  headers: HttpHeader[];
  bodyBase64: string;
} {
  const normalized = raw.replace(/\r\n/g, '\n');
  const idx = normalized.indexOf('\n\n');
  const head = idx === -1 ? normalized : normalized.slice(0, idx);
  const body = idx === -1 ? '' : normalized.slice(idx + 2);
  const lines = head.split('\n');
  const requestLine = lines.shift() ?? '';
  const parts = requestLine.split(/\s+/);
  const headers: HttpHeader[] = [];
  for (const line of lines) {
    const c = line.indexOf(':');
    if (c > 0) headers.push({ name: line.slice(0, c).trim(), value: line.slice(c + 1).trim() });
  }
  return {
    method: parts[0] ?? 'GET',
    target: parts[1] ?? '/',
    headers,
    bodyBase64: textToB64(body),
  };
}

export function InterceptView(): JSX.Element {
  const s = useStore();
  const [selected, setSelected] = useState<string | null>(null);
  const [draft, setDraft] = useState('');
  const [kind, setKind] = useState<'request' | 'response'>('request');

  // Depend on the callback, not the whole store. The store value is a new object
  // on every captured exchange, so keying this on `s` fired three IPC round-trips
  // per request the proxy handled — for state that already arrives by event.
  const refreshIntercept = s.refreshIntercept;
  useEffect(() => {
    refreshIntercept();
  }, [refreshIntercept]);

  const openRequest = (v: InterceptedRequestView): void => {
    setKind('request');
    setSelected(v.id);
    setDraft(reqToRaw(v));
  };
  const openResponse = (v: InterceptedResponseView): void => {
    setKind('response');
    setSelected(v.id);
    const headers = v.headers.map((h) => `${h.name}: ${h.value}`).join('\r\n');
    setDraft(
      `${v.httpVersion} ${v.statusCode} ${v.statusMessage}\r\n${headers}\r\n\r\n${b64ToText(v.bodyBase64)}`,
    );
  };

  const forward = async (): Promise<void> => {
    if (!selected) return;
    if (kind === 'request') {
      const edit = parseRaw(draft);
      await api.resolveRequest(selected, { action: 'forward', edit });
    } else {
      // Response edits: parse status line + headers + body
      const normalized = draft.replace(/\r\n/g, '\n');
      const idx = normalized.indexOf('\n\n');
      const head = idx === -1 ? normalized : normalized.slice(0, idx);
      const body = idx === -1 ? '' : normalized.slice(idx + 2);
      const lines = head.split('\n');
      const statusLine = lines.shift() ?? '';
      const m = /HTTP\/\d(?:\.\d)?\s+(\d+)\s*(.*)/.exec(statusLine);
      const headers: HttpHeader[] = [];
      for (const line of lines) {
        const c = line.indexOf(':');
        if (c > 0) headers.push({ name: line.slice(0, c).trim(), value: line.slice(c + 1).trim() });
      }
      await api.resolveResponse(selected, {
        action: 'forward',
        edit: {
          ...(m ? { statusCode: Number(m[1]), statusMessage: m[2] ?? '' } : {}),
          headers,
          bodyBase64: textToB64(body),
        },
      });
    }
    setSelected(null);
    setDraft('');
    s.refreshIntercept();
  };

  const drop = async (): Promise<void> => {
    if (!selected) return;
    if (kind === 'request') await api.resolveRequest(selected, { action: 'drop' });
    else await api.resolveResponse(selected, { action: 'drop' });
    setSelected(null);
    setDraft('');
    s.refreshIntercept();
  };

  return (
    <div className="view">
      <div className="toolbar">
        <label className="row" style={{ gap: 4 }}>
          <input
            type="checkbox"
            checked={s.intercept.interceptRequests}
            onChange={(e) =>
              void api
                .setInterceptState({ interceptRequests: e.target.checked })
                .then(s.refreshIntercept)
            }
          />
          Intercept requests
        </label>
        <label className="row" style={{ gap: 4 }}>
          <input
            type="checkbox"
            checked={s.intercept.interceptResponses}
            onChange={(e) =>
              void api
                .setInterceptState({ interceptResponses: e.target.checked })
                .then(s.refreshIntercept)
            }
          />
          Intercept responses
        </label>
        <span className="spacer" style={{ flex: 1 }} />
        <span className="hint">
          {s.pendingRequests.length} held request(s), {s.pendingResponses.length} held response(s)
        </span>
      </div>

      <div className="split h" style={{ flex: 1 }}>
        <div className="pane">
          <div className="pane-title">Held queue</div>
          <div className="scrolly">
            {s.pendingRequests.length === 0 && s.pendingResponses.length === 0 && (
              <div className="empty">
                No held messages. Enable interception, then generate traffic through the proxy.
              </div>
            )}
            {s.pendingRequests.map((v) => (
              <button
                key={v.id}
                className={`nav-item ${selected === v.id ? 'active' : ''}`}
                onClick={() => openRequest(v)}
              >
                <span className="badge">REQ</span>
                <span className="mono">{v.method}</span> {v.host}
                {v.target}
                <span
                  className={`badge ${v.inScope ? 'scope-in' : 'scope-out'}`}
                  style={{ marginLeft: 'auto' }}
                >
                  {v.inScope ? 'in' : 'out'}
                </span>
              </button>
            ))}
            {s.pendingResponses.map((v) => (
              <button
                key={v.id}
                className={`nav-item ${selected === v.id ? 'active' : ''}`}
                onClick={() => openResponse(v)}
              >
                <span className="badge">RES</span>
                <span className="mono">{v.statusCode}</span> {v.host}
                {v.target}
              </button>
            ))}
          </div>
        </div>

        <div className="pane">
          <div className="pane-title">
            <span>Editor ({kind})</span>
            <span className="spacer" style={{ flex: 1 }} />
            <button className="primary" disabled={!selected} onClick={forward}>
              Forward
            </button>
            <button className="danger" disabled={!selected} onClick={drop}>
              Drop
            </button>
          </div>
          {selected ? (
            <textarea
              className="grow"
              style={{ flex: 1, border: 'none', borderRadius: 0 }}
              value={draft}
              onChange={(e) => setDraft(e.target.value)}
              spellCheck={false}
            />
          ) : (
            <div className="empty">Select a held message to edit, then forward or drop it.</div>
          )}
        </div>
      </div>
    </div>
  );
}
