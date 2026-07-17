/** Persistence for captured WebSocket messages (payloads encrypted at rest). */

import type { WsMessage } from '../../shared/websocket.js';
import type { Database } from './database.js';
import type { ContentCipher } from '../crypto/contentCipher.js';

interface WsRow {
  id: string;
  exchange_id: string;
  seq: number;
  direction: string;
  kind: string;
  size: number;
  truncated: number;
  payload: Uint8Array | null;
  created_at: number;
}

export class WsMessageRepo {
  constructor(
    private readonly db: Database,
    private readonly cipher?: ContentCipher,
  ) {}

  insert(msg: {
    id: string;
    exchangeId: string;
    seq: number;
    direction: string;
    kind: string;
    size: number;
    truncated: boolean;
    payload: Uint8Array;
    createdAt: number;
  }): void {
    const stored = this.cipher ? this.cipher.seal(msg.payload) : Buffer.from(msg.payload);
    this.db.run(
      `INSERT INTO ws_messages (id, exchange_id, seq, direction, kind, size, truncated, payload, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      msg.id,
      msg.exchangeId,
      msg.seq,
      msg.direction,
      msg.kind,
      msg.size,
      msg.truncated ? 1 : 0,
      stored,
      msg.createdAt,
    );
  }

  // Default retrieval limit is above the proxy's per-connection capture ceiling
  // (WS_MAX_MESSAGES = 5000) so stored frames are never silently hidden.
  listByExchange(exchangeId: string, limit = 6000): WsMessage[] {
    const rows = this.db.all<WsRow>(
      'SELECT * FROM ws_messages WHERE exchange_id = ? ORDER BY seq ASC LIMIT ?',
      exchangeId,
      limit,
    );
    return rows.map((r) => this.rowToMessage(r));
  }

  /** Page through ALL captured WS messages (used by project export). */
  listAll(limit: number, offset: number): WsMessage[] {
    const rows = this.db.all<WsRow>(
      'SELECT * FROM ws_messages ORDER BY created_at ASC, exchange_id ASC, seq ASC LIMIT ? OFFSET ?',
      limit,
      offset,
    );
    return rows.map((r) => this.rowToMessage(r));
  }

  countAll(): number {
    return this.db.get<{ n: number }>('SELECT COUNT(*) AS n FROM ws_messages')?.n ?? 0;
  }

  countByExchange(exchangeId: string): number {
    return (
      this.db.get<{ n: number }>(
        'SELECT COUNT(*) AS n FROM ws_messages WHERE exchange_id = ?',
        exchangeId,
      )?.n ?? 0
    );
  }

  private rowToMessage(r: WsRow): WsMessage {
    const payload = r.payload
      ? this.cipher
        ? this.cipher.open(r.payload)
        : Buffer.from(r.payload)
      : Buffer.alloc(0);
    return {
      id: r.id,
      exchangeId: r.exchange_id,
      seq: r.seq,
      direction: r.direction as WsMessage['direction'],
      kind: r.kind as WsMessage['kind'],
      size: r.size,
      truncated: r.truncated === 1,
      payloadBase64: payload.toString('base64'),
      createdAt: r.created_at,
    };
  }
}
