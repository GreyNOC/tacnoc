/**
 * Content-addressed blob store for HTTP bodies.
 *
 * Bodies are stored by SHA-256 of their PLAINTEXT bytes (dedup + small DB), and
 * — when a ContentCipher is provided — encrypted at rest with AES-256-GCM. Large
 * bodies are streamed to disk (and encrypted on the fly) rather than held in
 * memory. On-disk layout of a stored blob: [iv | ciphertext | tag] (or raw
 * bytes when no cipher is configured, e.g. in low-level tests).
 *
 * Path layout: <root>/<aa>/<bb>/<sha256-of-plaintext>
 */

import { promises as fs, createReadStream } from 'node:fs';
import type { ReadStream } from 'node:fs';
import * as path from 'node:path';
import * as crypto from 'node:crypto';
import * as os from 'node:os';
import type { ContentCipher } from '../crypto/contentCipher.js';

export interface BlobRef {
  id: string;
  size: number;
}

export class BlobStore {
  constructor(
    private readonly root: string,
    private readonly cipher?: ContentCipher,
  ) {}

  private pathFor(id: string): string {
    return path.join(this.root, id.slice(0, 2), id.slice(2, 4), id);
  }

  async has(id: string): Promise<boolean> {
    try {
      await fs.access(this.pathFor(id));
      return true;
    } catch {
      return false;
    }
  }

  /** Store bytes (encrypted at rest if a cipher is set) and return their id. */
  async putBytes(bytes: Uint8Array): Promise<BlobRef> {
    // Keyed id when encrypting (no known-plaintext oracle); plaintext hash only
    // for the unencrypted low-level path (tests).
    const id = this.cipher
      ? this.cipher.contentId(bytes)
      : crypto.createHash('sha256').update(bytes).digest('hex');
    const dest = this.pathFor(id);
    if (!(await this.has(id))) {
      await fs.mkdir(path.dirname(dest), { recursive: true });
      const onDisk = this.cipher ? this.cipher.seal(bytes) : bytes;
      const tmp = path.join(os.tmpdir(), `blob-${crypto.randomBytes(8).toString('hex')}.tmp`);
      await fs.writeFile(tmp, onDisk);
      await this.moveInto(tmp, dest);
    }
    return { id, size: bytes.byteLength };
  }

  async readBytes(id: string): Promise<Buffer> {
    const raw = await fs.readFile(this.pathFor(id));
    return this.cipher ? this.cipher.open(raw) : raw;
  }

  /** Raw on-disk stream (ciphertext when encrypted). Prefer readBytes(). */
  createReadStream(id: string): ReadStream {
    return createReadStream(this.pathFor(id));
  }

  /** Begin a streaming write for a body of unknown size (encrypts on the fly). */
  async beginWrite(): Promise<BlobWriteSession> {
    await fs.mkdir(this.root, { recursive: true });
    const tmp = path.join(this.root, `.staging-${crypto.randomBytes(8).toString('hex')}.tmp`);
    const handle = await fs.open(tmp, 'w');
    const idHasher = this.cipher ? this.cipher.createIdHasher() : crypto.createHash('sha256');
    const session = new BlobWriteSession(this, tmp, handle, idHasher, this.cipher);
    await session.initHeader();
    return session;
  }

  /** @internal used by BlobWriteSession to finalize a staged file. */
  async finalizeStaged(tmpPath: string, id: string): Promise<void> {
    const dest = this.pathFor(id);
    if (await this.has(id)) {
      await fs.rm(tmpPath, { force: true });
      return;
    }
    await fs.mkdir(path.dirname(dest), { recursive: true });
    await this.moveInto(tmpPath, dest);
  }

  private async moveInto(from: string, to: string): Promise<void> {
    try {
      await fs.rename(from, to);
    } catch {
      // Cross-device or racing rename: fall back to copy+unlink.
      await fs.copyFile(from, to);
      await fs.rm(from, { force: true });
    }
  }
}

/** A streaming write into the blob store. Hashes plaintext; encrypts on the fly. */
export class BlobWriteSession {
  private size = 0;
  private closed = false;
  private stream?: { iv: Buffer; cipher: crypto.CipherGCM };

  constructor(
    private readonly store: BlobStore,
    private readonly tmpPath: string,
    private readonly handle: import('node:fs/promises').FileHandle,
    private readonly hash: crypto.Hash | crypto.Hmac,
    private readonly cipher?: ContentCipher,
  ) {}

  /** @internal write the iv header before any chunk when encrypting. */
  async initHeader(): Promise<void> {
    if (this.cipher) {
      const { iv, cipher } = this.cipher.beginStream();
      this.stream = { iv, cipher };
      await this.handle.write(iv);
    }
  }

  async write(chunk: Uint8Array): Promise<void> {
    if (this.closed) throw new Error('write after commit/abort');
    this.hash.update(chunk);
    this.size += chunk.byteLength;
    if (this.stream) {
      await this.handle.write(this.stream.cipher.update(chunk));
    } else {
      await this.handle.write(chunk);
    }
  }

  async commit(): Promise<BlobRef> {
    if (this.closed) throw new Error('already closed');
    this.closed = true;
    if (this.stream) {
      await this.handle.write(this.stream.cipher.final());
      await this.handle.write(this.stream.cipher.getAuthTag());
    }
    await this.handle.close();
    const id = this.hash.digest('hex');
    await this.store.finalizeStaged(this.tmpPath, id);
    return { id, size: this.size };
  }

  async abort(): Promise<void> {
    if (this.closed) return;
    this.closed = true;
    await this.handle.close();
    await fs.rm(this.tmpPath, { force: true });
  }
}
