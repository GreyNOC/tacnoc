import React, { useCallback, useEffect, useState } from 'react';
import { api } from '../api.js';
import { useStore } from '../store.js';
import type { ExchangeSummary, HistoryFilter } from '@shared/query.js';
import type { ExchangeDetail } from '@shared/detail.js';
import type { WsMessage } from '@shared/websocket.js';
import { MessageViewer } from './MessageViewer.js';
import { statusClass, b64ToText, timeShort } from '../lib/format.js';

export function detailToRaw(d: ExchangeDetail): {
  scheme: string;
  host: string;
  port: number;
  raw: string;
} {
  const req = d.request;
  const headerBlock = req.headers.map((h) => `${h.name}: ${h.value}`).join('\r\n');
  const body = b64ToText(req.bodyBase64);
  const raw = `${req.method} ${req.target} ${req.httpVersion}\r\n${headerBlock}\r\n\r\n${body}`;
  return { scheme: d.scheme, host: d.host, port: d.port, raw };
}

export function HistoryView(): JSX.Element {
  const s = useStore();
  const [rows, setRows] = useState<ExchangeSummary[]>([]);
  const [total, setTotal] = useState(0);
  const [selected, setSelected] = useState<string | null>(null);
  const [detail, setDetail] = useState<ExchangeDetail | undefined>(undefined);
  const [wsMessages, setWsMessages] = useState<WsMessage[]>([]);
  const [notesDraft, setNotesDraft] = useState('');
  const [tagsDraft, setTagsDraft] = useState('');

  const [text, setText] = useState('');
  const [method, setMethod] = useState('');
  const [statusClassFilter, setStatusClassFilter] = useState('');
  const [mime, setMime] = useState('');
  const [source, setSource] = useState('');
  const [inScopeOnly, setInScopeOnly] = useState(false);

  const load = useCallback(() => {
    const filter: HistoryFilter = { limit: 500, sort: 'desc' };
    if (text) filter.text = text;
    if (method) filter.method = method;
    if (statusClassFilter) filter.statusClass = Number(statusClassFilter);
    if (mime) filter.mime = mime;
    if (source) filter.source = source as HistoryFilter['source'];
    if (inScopeOnly) filter.inScopeOnly = true;
    void api.queryHistory(filter).then((page) => {
      setRows(page.rows);
      setTotal(page.total);
    });
  }, [text, method, statusClassFilter, mime, source, inScopeOnly]);

  useEffect(() => {
    load();
  }, [load, s.exchangeTick]);

  const select = (id: string): void => {
    setSelected(id);
    setWsMessages([]);
    void api.getExchangeDetail(id).then((d) => {
      setDetail(d);
      if (d?.tags.includes('websocket')) void api.listWsMessages(id).then(setWsMessages);
    });
  };

  // Live-refresh WS frames for the selected socket as they arrive.
  useEffect(() => {
    if (!selected || !detail?.tags.includes('websocket')) return;
    return api.onEvent((e) => {
      if (e.type === 'ws-message' && e.payload.exchangeId === selected) {
        void api.listWsMessages(selected).then(setWsMessages);
      }
    });
  }, [selected, detail]);

  // Keep the notes/tags editor in sync with the selected exchange.
  useEffect(() => {
    setNotesDraft(detail?.notes ?? '');
    setTagsDraft((detail?.tags ?? []).join(', '));
  }, [detail]);

  const sendToRepeater = (): void => {
    if (detail) s.seedRepeater(detailToRaw(detail));
  };

  const saveNotesTags = async (): Promise<void> => {
    if (!selected) return;
    const tags = tagsDraft
      .split(',')
      .map((t) => t.trim())
      .filter(Boolean);
    await api.updateNotesTags(selected, notesDraft.trim() ? notesDraft : null, tags);
    const d = await api.getExchangeDetail(selected);
    setDetail(d);
    s.setToast('Notes and tags saved.');
  };

  return (
    <div className="view">
      <div className="toolbar">
        <input
          placeholder="Search url/host/method…"
          value={text}
          onChange={(e) => setText(e.target.value)}
        />
        <select value={method} onChange={(e) => setMethod(e.target.value)} aria-label="Method">
          <option value="">Any method</option>
          {['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'].map((m) => (
            <option key={m}>{m}</option>
          ))}
        </select>
        <select
          value={statusClassFilter}
          onChange={(e) => setStatusClassFilter(e.target.value)}
          aria-label="Status"
        >
          <option value="">Any status</option>
          <option value="2">2xx</option>
          <option value="3">3xx</option>
          <option value="4">4xx</option>
          <option value="5">5xx</option>
        </select>
        <input
          placeholder="MIME"
          style={{ width: 110 }}
          value={mime}
          onChange={(e) => setMime(e.target.value)}
        />
        <select value={source} onChange={(e) => setSource(e.target.value)} aria-label="Source">
          <option value="">Any source</option>
          <option value="proxy">proxy</option>
          <option value="repeater">repeater</option>
          <option value="variation">variation</option>
          <option value="import">import</option>
        </select>
        <label className="row" style={{ gap: 4 }}>
          <input
            type="checkbox"
            checked={inScopeOnly}
            onChange={(e) => setInScopeOnly(e.target.checked)}
          />
          in-scope only
        </label>
        <span className="spacer" style={{ flex: 1 }} />
        <span className="hint">{total} exchanges</span>
        <button className="ghost" onClick={() => void api.clearHistory().then(load)}>
          Clear
        </button>
      </div>

      <div className="split v">
        <div className="pane">
          <div className="table-wrap">
            <table className="grid">
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Src</th>
                  <th>Method</th>
                  <th>Host</th>
                  <th>Path</th>
                  <th>Status</th>
                  <th>Len</th>
                  <th>Scope</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((r) => (
                  <tr
                    key={r.id}
                    className={selected === r.id ? 'selected' : ''}
                    onClick={() => select(r.id)}
                  >
                    <td className="mono">{timeShort(r.createdAt)}</td>
                    <td>{r.automated ? <span className="badge auto">auto</span> : r.source}</td>
                    <td className="mono">{r.method}</td>
                    <td>{r.host}</td>
                    <td className="mono">{r.path}</td>
                    <td className={`mono ${statusClass(r.statusCode)}`}>
                      {r.statusCode ?? (r.error ? 'ERR' : '…')}
                    </td>
                    <td className="mono">{r.responseLength}</td>
                    <td>
                      <span className={`badge ${r.inScope ? 'scope-in' : 'scope-out'}`}>
                        {r.inScope ? 'in' : 'out'}
                      </span>
                    </td>
                  </tr>
                ))}
                {rows.length === 0 && (
                  <tr>
                    <td colSpan={8} className="empty">
                      No traffic yet. Start the proxy and point a browser at it.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>

        <div className="pane">
          <div className="pane-title">
            <span>Inspector</span>
            <span className="spacer" style={{ flex: 1 }} />
            <button disabled={!detail} onClick={sendToRepeater}>
              Send to Repeater →
            </button>
          </div>
          {detail && (
            <div className="row" style={{ gap: 8, padding: '6px 10px', flexWrap: 'wrap' }}>
              <input
                style={{ flex: 2, minWidth: 160 }}
                placeholder="Notes for this exchange…"
                value={notesDraft}
                onChange={(e) => setNotesDraft(e.target.value)}
                aria-label="Exchange notes"
              />
              <input
                style={{ flex: 1, minWidth: 120 }}
                placeholder="tags (comma-separated)"
                value={tagsDraft}
                onChange={(e) => setTagsDraft(e.target.value)}
                aria-label="Exchange tags"
              />
              <button onClick={saveNotesTags}>Save notes/tags</button>
            </div>
          )}
          <div className="split h" style={{ flex: 1 }}>
            <MessageViewer
              title="Request"
              message={
                detail
                  ? {
                      headline: `${detail.request.method} ${detail.request.target} ${detail.request.httpVersion}`,
                      ...detail.request,
                    }
                  : undefined
              }
            />
            {detail?.tags.includes('websocket') ? (
              <WebSocketPanel messages={wsMessages} />
            ) : (
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
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

function WebSocketPanel({ messages }: { messages: WsMessage[] }): JSX.Element {
  return (
    <div className="pane">
      <div className="pane-title">
        <span>WebSocket frames</span>
        <span className="spacer" style={{ flex: 1 }} />
        <span className="hint">{messages.length} captured</span>
      </div>
      <div className="table-wrap">
        <table className="grid">
          <thead>
            <tr>
              <th>#</th>
              <th>Dir</th>
              <th>Kind</th>
              <th>Len</th>
              <th>Payload</th>
            </tr>
          </thead>
          <tbody>
            {messages.map((m) => (
              <tr key={m.id}>
                <td className="mono">{m.seq}</td>
                <td>
                  <span className="badge">{m.direction === 'c2s' ? '↑ c→s' : '↓ s→c'}</span>
                </td>
                <td className="mono">{m.kind}</td>
                <td className="mono">
                  {m.size}
                  {m.truncated ? '*' : ''}
                </td>
                <td className="mono" style={{ maxWidth: 320 }}>
                  {m.kind === 'text' || m.kind === 'binary'
                    ? b64ToText(m.payloadBase64).slice(0, 200)
                    : ''}
                </td>
              </tr>
            ))}
            {messages.length === 0 && (
              <tr>
                <td colSpan={5} className="empty">
                  No frames captured yet on this socket.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
