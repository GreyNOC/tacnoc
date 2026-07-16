import { describe, it, expect } from 'vitest';
import { WsFrameParser } from '../../src/engine/proxy/wsFrame.js';

function frame(
  opcode: number,
  payload: Buffer,
  opts: { fin?: boolean; mask?: boolean } = {},
): Buffer {
  const fin = opts.fin ?? true;
  const mask = opts.mask ?? false;
  const b0 = (fin ? 0x80 : 0) | (opcode & 0x0f);
  const len = payload.length;
  const header: number[] = [b0];
  let lenBytes: Buffer;
  if (len < 126) {
    header.push((mask ? 0x80 : 0) | len);
    lenBytes = Buffer.alloc(0);
  } else if (len < 65536) {
    header.push((mask ? 0x80 : 0) | 126);
    lenBytes = Buffer.alloc(2);
    lenBytes.writeUInt16BE(len);
  } else {
    header.push((mask ? 0x80 : 0) | 127);
    lenBytes = Buffer.alloc(8);
    lenBytes.writeUInt32BE(Math.floor(len / 2 ** 32), 0);
    lenBytes.writeUInt32BE(len >>> 0, 4);
  }
  const parts = [Buffer.from(header), lenBytes];
  if (mask) {
    const key = Buffer.from([0x12, 0x34, 0x56, 0x78]);
    const masked = Buffer.allocUnsafe(len);
    for (let i = 0; i < len; i++) masked[i] = (payload[i] as number) ^ (key[i % 4] as number);
    parts.push(key, masked);
  } else {
    parts.push(payload);
  }
  return Buffer.concat(parts);
}

describe('WebSocket frame parser', () => {
  it('parses an unmasked server text frame', () => {
    const p = new WsFrameParser();
    const msgs = p.push(frame(0x1, Buffer.from('hello server')));
    expect(msgs).toHaveLength(1);
    expect(msgs[0]?.kind).toBe('text');
    expect(msgs[0]?.payload.toString()).toBe('hello server');
  });

  it('unmasks a masked client text frame', () => {
    const p = new WsFrameParser();
    const msgs = p.push(frame(0x1, Buffer.from('client speaks'), { mask: true }));
    expect(msgs[0]?.payload.toString()).toBe('client speaks');
  });

  it('handles binary frames', () => {
    const p = new WsFrameParser();
    const bytes = Buffer.from([0, 1, 2, 255, 254]);
    const msgs = p.push(frame(0x2, bytes, { mask: true }));
    expect(msgs[0]?.kind).toBe('binary');
    expect(msgs[0]?.payload.equals(bytes)).toBe(true);
  });

  it('reassembles a fragmented message (text + continuation)', () => {
    const p = new WsFrameParser();
    const a = frame(0x1, Buffer.from('Hello, '), { fin: false });
    const b = frame(0x0, Buffer.from('world!'), { fin: true });
    expect(p.push(a)).toHaveLength(0);
    const msgs = p.push(b);
    expect(msgs).toHaveLength(1);
    expect(msgs[0]?.payload.toString()).toBe('Hello, world!');
  });

  it('surfaces control frames (ping/close)', () => {
    const p = new WsFrameParser();
    expect(p.push(frame(0x9, Buffer.from('pingdata')))[0]?.kind).toBe('ping');
    expect(p.push(frame(0x8, Buffer.from([0x03, 0xe8])))[0]?.kind).toBe('close');
  });

  it('parses frames split across chunk boundaries', () => {
    const p = new WsFrameParser();
    const full = frame(0x1, Buffer.from('split across chunks'), { mask: true });
    let msgs = p.push(full.subarray(0, 3));
    expect(msgs).toHaveLength(0);
    msgs = p.push(full.subarray(3, 9));
    expect(msgs).toHaveLength(0);
    msgs = p.push(full.subarray(9));
    expect(msgs[0]?.payload.toString()).toBe('split across chunks');
  });

  it('parses two frames in one chunk', () => {
    const p = new WsFrameParser();
    const two = Buffer.concat([frame(0x1, Buffer.from('one')), frame(0x1, Buffer.from('two'))]);
    const msgs = p.push(two);
    expect(msgs.map((m) => m.payload.toString())).toEqual(['one', 'two']);
  });

  it('truncates oversized payloads but stays wire-aligned for the next frame', () => {
    const p = new WsFrameParser(16); // 16-byte capture cap
    const big = frame(0x2, Buffer.alloc(1000, 0x41));
    const next = frame(0x1, Buffer.from('after-big'));
    const msgs = p.push(Buffer.concat([big, next]));
    expect(msgs).toHaveLength(2);
    expect(msgs[0]?.truncated).toBe(true);
    expect(msgs[0]?.size).toBe(1000);
    expect(msgs[0]?.payload.length).toBe(16);
    // Crucially, the following frame still parses correctly.
    expect(msgs[1]?.payload.toString()).toBe('after-big');
  });

  it('fails safe on an abusive 64-bit length (stops capturing, no throw)', () => {
    const p = new WsFrameParser();
    // opcode 2 (binary), 127 length marker, then an 8-byte length with the high
    // word set (exceeds the safe bound) → parser must not throw or track it.
    const bogus = Buffer.concat([
      Buffer.from([0x82, 0x7f]),
      Buffer.from([0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00]),
    ]);
    expect(() => p.push(bogus)).not.toThrow();
    expect(p.push(bogus)).toHaveLength(0);
    // A subsequent well-formed frame is NOT captured (parser gave up for safety).
    expect(p.push(frame(0x1, Buffer.from('after')))).toHaveLength(0);
  });

  it('handles a 16-bit extended length frame', () => {
    const p = new WsFrameParser(70000);
    const payload = Buffer.alloc(300, 0x42);
    const msgs = p.push(frame(0x2, payload, { mask: true }));
    expect(msgs[0]?.size).toBe(300);
    expect(msgs[0]?.payload.length).toBe(300);
  });
});
