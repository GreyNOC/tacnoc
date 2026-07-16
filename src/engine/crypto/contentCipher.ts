/**
 * At-rest content encryption (AES-256-GCM).
 *
 * Wire format for a sealed value: [iv(12) | ciphertext | tag(16)].
 * The key is a per-project 32-byte data-encryption key (DEK) held in the
 * project SecretStore (OS secure storage in the app). See THREAT_MODEL.md and
 * docs/project-format.md for what is and isn't encrypted at rest.
 *
 * Content-addressing (blob ids) is computed over the PLAINTEXT so identical
 * bodies still de-duplicate even though each sealed copy uses a fresh iv.
 */

import * as crypto from 'node:crypto';

const IV_LEN = 12;
const TAG_LEN = 16;
export const DEK_BYTES = 32;

export class ContentCipher {
  /** Separate subkey for content-id HMAC (never the encryption key directly). */
  private readonly idKey: Buffer;

  constructor(private readonly key: Buffer) {
    if (key.length !== DEK_BYTES) {
      throw new Error(`data-encryption key must be ${DEK_BYTES} bytes`);
    }
    this.idKey = crypto.createHmac('sha256', key).update('belcher-blob-id').digest();
  }

  /**
   * Keyed content id (HMAC-SHA256 under a DEK-derived subkey). Used instead of a
   * plaintext SHA-256 so a keyless attacker who copies the project folder cannot
   * compute or confirm blob ids from candidate plaintext (no known-plaintext
   * oracle). In-project dedup is preserved (same key + bytes → same id).
   */
  contentId(bytes: Uint8Array): string {
    return crypto.createHmac('sha256', this.idKey).update(bytes).digest('hex');
  }

  /** Streaming keyed content-id hasher (matches contentId()). */
  createIdHasher(): crypto.Hmac {
    return crypto.createHmac('sha256', this.idKey);
  }

  static generateKey(): Buffer {
    return crypto.randomBytes(DEK_BYTES);
  }

  /** Seal a whole buffer → [iv|ct|tag]. */
  seal(plain: Uint8Array): Buffer {
    const iv = crypto.randomBytes(IV_LEN);
    const cipher = crypto.createCipheriv('aes-256-gcm', this.key, iv);
    const ct = Buffer.concat([cipher.update(plain), cipher.final()]);
    return Buffer.concat([iv, ct, cipher.getAuthTag()]);
  }

  /** Open a [iv|ct|tag] buffer → plaintext. Throws on tamper/wrong key. */
  open(sealed: Uint8Array): Buffer {
    const buf = Buffer.from(sealed);
    if (buf.length < IV_LEN + TAG_LEN) throw new Error('sealed value too short');
    const iv = buf.subarray(0, IV_LEN);
    const tag = buf.subarray(buf.length - TAG_LEN);
    const ct = buf.subarray(IV_LEN, buf.length - TAG_LEN);
    const decipher = crypto.createDecipheriv('aes-256-gcm', this.key, iv);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ct), decipher.final()]);
  }

  /** Seal a UTF-8 string, returning base64 of the sealed bytes (for TEXT columns). */
  sealText(plain: string): string {
    return this.seal(Buffer.from(plain, 'utf8')).toString('base64');
  }

  openText(sealedB64: string): string {
    return this.open(Buffer.from(sealedB64, 'base64')).toString('utf8');
  }

  /**
   * Begin a streaming seal. The caller writes `iv` first, then each
   * `cipher.update(chunk)` output, then `final()` + `getAuthTag()` at the end,
   * yielding the same [iv|ct|tag] on-disk layout.
   */
  beginStream(): { iv: Buffer; cipher: crypto.CipherGCM } {
    const iv = crypto.randomBytes(IV_LEN);
    const cipher = crypto.createCipheriv('aes-256-gcm', this.key, iv) as crypto.CipherGCM;
    return { iv, cipher };
  }

  static get ivLen(): number {
    return IV_LEN;
  }
  static get tagLen(): number {
    return TAG_LEN;
  }
}
