/**
 * Streaming RFC 6455 WebSocket frame parser (observation only).
 *
 * The proxy tees each direction of a WebSocket tunnel through one of these; the
 * bytes are still forwarded unchanged. The parser reassembles fragmented data
 * messages, unmasks client→server frames, surfaces control frames, and stays
 * wire-aligned even for oversized frames it declines to fully buffer (it drains
 * the excess so subsequent frames still parse). Capture is bounded per message.
 */

export type WsMessageKind = 'text' | 'binary' | 'ping' | 'pong' | 'close';

export interface WsCapturedMessage {
  kind: WsMessageKind;
  /** Captured (possibly truncated) unmasked payload. */
  payload: Buffer;
  /** Full payload size seen on the wire. */
  size: number;
  /** True if capture hit the per-message cap. */
  truncated: boolean;
}

interface FrameState {
  fin: boolean;
  opcode: number;
  masked: boolean;
  maskKey: Buffer;
  remaining: number; // payload bytes still to consume
  totalLen: number; // full payload length
  payloadIndex: number; // absolute index within the payload (for unmasking)
  captured: Buffer[];
  capturedLen: number;
}

const OP_CONTINUATION = 0x0;
const OP_TEXT = 0x1;
const OP_BINARY = 0x2;
const OP_CLOSE = 0x8;
const OP_PING = 0x9;
const OP_PONG = 0xa;

export class WsFrameParser {
  private buf: Buffer = Buffer.alloc(0);
  private frame?: FrameState;

  // Fragmented data-message reassembly.
  private fragOpcode = 0;
  private fragParts: Buffer[] = [];
  private fragLen = 0;
  private fragTotal = 0;
  private fragTruncated = false;
  private inFragment = false;

  constructor(private readonly maxMessageBytes = 64 * 1024) {}

  private broken = false;

  /** Feed observed bytes; returns any messages completed by this chunk. */
  push(chunk: Buffer): WsCapturedMessage[] {
    if (this.broken) return []; // stop capturing after a protocol violation
    this.buf = this.buf.length ? Buffer.concat([this.buf, chunk]) : chunk;
    const out: WsCapturedMessage[] = [];
    try {
      // eslint-disable-next-line no-constant-condition
      while (true) {
        if (this.frame) {
          if (!this.consumePayload(out)) break;
        } else if (!this.parseHeader()) {
          break;
        }
      }
    } catch {
      // Malformed/abusive framing: give up capture for this connection (the
      // proxy keeps tunneling the raw bytes regardless) and release the buffer.
      this.broken = true;
      this.buf = Buffer.alloc(0);
      this.frame = undefined;
    }
    return out;
  }

  /** Try to parse a frame header from the front of the buffer. */
  private parseHeader(): boolean {
    if (this.buf.length < 2) return false;
    const b0 = this.buf[0] as number;
    const b1 = this.buf[1] as number;
    const fin = (b0 & 0x80) !== 0;
    const opcode = b0 & 0x0f;
    const masked = (b1 & 0x80) !== 0;
    let len = b1 & 0x7f;
    let offset = 2;

    if (len === 126) {
      if (this.buf.length < offset + 2) return false;
      len = this.buf.readUInt16BE(offset);
      offset += 2;
    } else if (len === 127) {
      if (this.buf.length < offset + 8) return false;
      const hi = this.buf.readUInt32BE(offset);
      const lo = this.buf.readUInt32BE(offset + 4);
      // RFC 6455: the most-significant bit MUST be 0, and lengths must stay a
      // safe integer. Reject anything larger (protocol violation / abuse) — the
      // caller tears down the connection rather than tracking a bogus length.
      if (hi > 0x1fffff) throw new Error('websocket frame length exceeds safe bound');
      len = hi * 2 ** 32 + lo;
      offset += 8;
    }

    let maskKey: Buffer = Buffer.alloc(0);
    if (masked) {
      if (this.buf.length < offset + 4) return false;
      maskKey = this.buf.subarray(offset, offset + 4);
      offset += 4;
    }

    this.buf = this.buf.subarray(offset);
    this.frame = {
      fin,
      opcode,
      masked,
      maskKey: Buffer.from(maskKey),
      remaining: len,
      totalLen: len,
      payloadIndex: 0,
      captured: [],
      capturedLen: 0,
    };
    return true;
  }

  /** Consume available payload bytes for the current frame. */
  private consumePayload(out: WsCapturedMessage[]): boolean {
    const f = this.frame!;
    if (f.remaining > 0) {
      if (this.buf.length === 0) return false;
      const take = Math.min(f.remaining, this.buf.length);
      const slice = this.buf.subarray(0, take);
      this.buf = this.buf.subarray(take);

      // Capture up to the cap, unmasking as we go.
      if (f.capturedLen < this.maxMessageBytes) {
        const room = this.maxMessageBytes - f.capturedLen;
        const capN = Math.min(room, take);
        const piece = Buffer.allocUnsafe(capN);
        for (let i = 0; i < capN; i++) {
          const byte = slice[i] as number;
          piece[i] = f.masked ? byte ^ (f.maskKey[(f.payloadIndex + i) % 4] as number) : byte;
        }
        f.captured.push(piece);
        f.capturedLen += capN;
      }
      f.payloadIndex += take;
      f.remaining -= take;
      if (f.remaining > 0) return false; // need more bytes
    }

    // Frame fully consumed.
    const payload = Buffer.concat(f.captured, f.capturedLen);
    const truncated = f.totalLen > f.capturedLen;
    this.frame = undefined;
    this.finishFrame(f.fin, f.opcode, payload, f.totalLen, truncated, out);
    return true;
  }

  private finishFrame(
    fin: boolean,
    opcode: number,
    payload: Buffer,
    totalLen: number,
    truncated: boolean,
    out: WsCapturedMessage[],
  ): void {
    // Control frames are standalone and never fragmented.
    if (opcode === OP_CLOSE || opcode === OP_PING || opcode === OP_PONG) {
      out.push({
        kind: opcode === OP_CLOSE ? 'close' : opcode === OP_PING ? 'ping' : 'pong',
        payload,
        size: totalLen,
        truncated,
      });
      return;
    }

    if (opcode === OP_TEXT || opcode === OP_BINARY) {
      if (fin) {
        out.push({
          kind: opcode === OP_TEXT ? 'text' : 'binary',
          payload,
          size: totalLen,
          truncated,
        });
      } else {
        this.inFragment = true;
        this.fragOpcode = opcode;
        this.fragParts = [payload];
        this.fragLen = payload.length;
        this.fragTotal = totalLen;
        this.fragTruncated = truncated;
      }
      return;
    }

    if (opcode === OP_CONTINUATION && this.inFragment) {
      if (this.fragLen < this.maxMessageBytes) {
        const room = this.maxMessageBytes - this.fragLen;
        const piece = payload.subarray(0, room);
        this.fragParts.push(piece);
        this.fragLen += piece.length;
      }
      this.fragTotal += totalLen;
      this.fragTruncated = this.fragTruncated || truncated || this.fragLen < this.fragTotal;
      if (fin) {
        out.push({
          kind: this.fragOpcode === OP_TEXT ? 'text' : 'binary',
          payload: Buffer.concat(this.fragParts, this.fragLen),
          size: this.fragTotal,
          truncated: this.fragTruncated,
        });
        this.inFragment = false;
        this.fragParts = [];
        this.fragLen = 0;
        this.fragTotal = 0;
        this.fragTruncated = false;
      }
    }
    // else: unexpected continuation without a start — ignore (stay aligned).
  }
}
