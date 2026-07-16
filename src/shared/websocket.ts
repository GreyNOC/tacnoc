/** Captured WebSocket message (shared engine/UI type). */

export type WsDirection = 'c2s' | 's2c';
export type WsMessageKind = 'text' | 'binary' | 'ping' | 'pong' | 'close';

export interface WsMessage {
  id: string;
  exchangeId: string;
  seq: number;
  direction: WsDirection;
  kind: WsMessageKind;
  /** Full payload size seen on the wire. */
  size: number;
  truncated: boolean;
  /** Base64 of the captured (possibly truncated) payload. */
  payloadBase64: string;
  createdAt: number;
}
