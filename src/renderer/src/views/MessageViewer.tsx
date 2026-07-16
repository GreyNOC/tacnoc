import React, { useMemo, useState } from 'react';
import type { HttpHeader } from '@shared/model.js';
import type { SensitivitySummary } from '@shared/detail.js';
import { b64ToBytes, b64ToText, hexdump, tryPrettyJson, bytesHuman } from '../lib/format.js';

export interface ViewerMessage {
  headline: string; // request line or status line
  headers: HttpHeader[];
  bodyBase64: string;
  bodySize: number;
  bodyTruncated: boolean;
  truncatedForView: boolean;
  contentEncoding?: string;
  sensitive: SensitivitySummary;
}

type Tab = 'raw' | 'headers' | 'body' | 'hex';

export function MessageViewer({
  title,
  message,
}: {
  title: string;
  message?: ViewerMessage;
}): JSX.Element {
  const [tab, setTab] = useState<Tab>('raw');
  const [revealed, setRevealed] = useState(false);

  const bodyText = useMemo(() => (message ? b64ToText(message.bodyBase64) : ''), [message]);
  const pretty = useMemo(() => tryPrettyJson(bodyText), [bodyText]);
  const hex = useMemo(() => (message ? hexdump(b64ToBytes(message.bodyBase64)) : ''), [message]);

  if (!message) {
    return (
      <div className="pane">
        <div className="pane-title">{title}</div>
        <div className="empty">Nothing selected.</div>
      </div>
    );
  }

  const isSensitive =
    message.sensitive.hasCookies ||
    message.sensitive.hasAuthorization ||
    message.sensitive.hasTokens;
  const masked = isSensitive && !revealed;

  const headerBlock = message.headers.map((h) => `${h.name}: ${h.value}`).join('\n');
  const rawText = `${message.headline}\n${headerBlock}\n\n${bodyText}`;

  return (
    <div className="pane">
      <div className="pane-title">
        <span>{title}</span>
        <div className="tabs" role="tablist">
          {(['raw', 'headers', 'body', 'hex'] as Tab[]).map((t) => (
            <button
              key={t}
              role="tab"
              aria-selected={tab === t}
              className={`tab ${tab === t ? 'active' : ''}`}
              onClick={() => setTab(t)}
            >
              {t === 'body' && pretty ? 'JSON' : t.toUpperCase()}
            </button>
          ))}
        </div>
        <span className="spacer" style={{ flex: 1 }} />
        <span className="hint">
          {bytesHuman(message.bodySize)}
          {message.bodyTruncated ? ' (capped)' : ''}
          {message.contentEncoding ? ` · ${message.contentEncoding}` : ''}
        </span>
      </div>

      {isSensitive && (
        <div className="warn-box" style={{ margin: 8 }}>
          ⚠ Contains likely credentials ({message.sensitive.fields.join(', ') || 'sensitive data'}).
          <button
            className="ghost"
            style={{ marginLeft: 8 }}
            onClick={() => setRevealed((r) => !r)}
          >
            {revealed ? 'Hide' : 'Reveal'}
          </button>
        </div>
      )}

      {message.truncatedForView && (
        <div className="hint" style={{ padding: '4px 10px' }}>
          Body truncated for display; full bytes are stored.
        </div>
      )}

      {tab === 'raw' && (
        <pre
          className={`message ${masked ? 'reveal-mask' : ''}`}
          onClick={() => masked && setRevealed(true)}
        >
          {rawText}
        </pre>
      )}
      {tab === 'headers' && (
        <pre
          className={`message ${masked ? 'reveal-mask' : ''}`}
          onClick={() => masked && setRevealed(true)}
        >
          {message.headline}
          {'\n'}
          {headerBlock}
        </pre>
      )}
      {tab === 'body' && (
        <pre
          className={`message ${masked ? 'reveal-mask' : ''}`}
          onClick={() => masked && setRevealed(true)}
        >
          {pretty ?? (bodyText || '(empty body)')}
        </pre>
      )}
      {tab === 'hex' && <pre className="message hex">{hex || '(empty body)'}</pre>}
    </div>
  );
}
