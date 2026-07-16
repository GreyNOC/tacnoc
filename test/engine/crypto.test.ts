import { describe, it, expect } from 'vitest';
import { createHash } from 'node:crypto';
import { ContentCipher, DEK_BYTES } from '../../src/engine/crypto/contentCipher.js';

describe('ContentCipher', () => {
  it('round-trips bytes and text', () => {
    const c = new ContentCipher(ContentCipher.generateKey());
    const bytes = new Uint8Array([0, 1, 2, 255, 128, 64]);
    expect(Buffer.from(c.open(c.seal(bytes))).equals(Buffer.from(bytes))).toBe(true);
    expect(c.openText(c.sealText('héllo 🔒'))).toBe('héllo 🔒');
  });

  it('produces different ciphertext each time (fresh iv) but same plaintext', () => {
    const c = new ContentCipher(ContentCipher.generateKey());
    const a = c.seal(Buffer.from('same'));
    const b = c.seal(Buffer.from('same'));
    expect(a.equals(b)).toBe(false);
    expect(c.open(a).toString()).toBe('same');
    expect(c.open(b).toString()).toBe('same');
  });

  it('detects tampering (GCM auth tag)', () => {
    const c = new ContentCipher(ContentCipher.generateKey());
    const sealed = c.seal(Buffer.from('important'));
    const last = sealed.length - 1;
    sealed[last] = (sealed[last] ?? 0) ^ 0xff; // flip a tag byte
    expect(() => c.open(sealed)).toThrow();
  });

  it('rejects the wrong key', () => {
    const a = new ContentCipher(ContentCipher.generateKey());
    const b = new ContentCipher(ContentCipher.generateKey());
    expect(() => b.open(a.seal(Buffer.from('x')))).toThrow();
  });

  it('rejects a malformed key length', () => {
    expect(() => new ContentCipher(Buffer.alloc(DEK_BYTES - 1))).toThrow();
  });

  it('content ids are keyed (not the plaintext hash) and key-specific', () => {
    const bytes = Buffer.from('a known credential blob');
    const plainHash = createHash('sha256').update(bytes).digest('hex');
    const a = new ContentCipher(ContentCipher.generateKey());
    const b = new ContentCipher(ContentCipher.generateKey());

    // Not equal to the plaintext SHA-256 → no known-plaintext confirmation oracle.
    expect(a.contentId(bytes)).not.toBe(plainHash);
    // Different keys → different ids (attacker without the key cannot compute it).
    expect(a.contentId(bytes)).not.toBe(b.contentId(bytes));
    // Same key + bytes → same id (in-project dedup preserved).
    expect(a.contentId(bytes)).toBe(a.contentId(Buffer.from('a known credential blob')));
    // Streaming id hasher matches the one-shot id.
    const h = a.createIdHasher();
    h.update(bytes.subarray(0, 5));
    h.update(bytes.subarray(5));
    expect(h.digest('hex')).toBe(a.contentId(bytes));
  });

  it('streaming seal produces the same [iv|ct|tag] layout as seal()', () => {
    const c = new ContentCipher(ContentCipher.generateKey());
    const { iv, cipher } = c.beginStream();
    const parts = [iv, cipher.update(Buffer.from('hello ')), cipher.update(Buffer.from('world'))];
    parts.push(cipher.final());
    parts.push(cipher.getAuthTag());
    const sealed = Buffer.concat(parts);
    expect(c.open(sealed).toString()).toBe('hello world');
  });
});
