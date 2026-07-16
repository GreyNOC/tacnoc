/**
 * BodyCollector observes body bytes as they flow through the proxy (a "tee")
 * and produces a MessageBody for storage:
 *   - Small bodies stay inline (in memory).
 *   - Once a body exceeds `spillToDiskAfterBytes`, it is streamed to the blob
 *     store instead of accumulating in memory.
 *   - Storage stops at `maxCapturedBytes` and the body is marked `truncated`.
 *     The proxy still forwards ALL bytes to the peer — truncation only bounds
 *     the STORED copy, so we never break the proxied stream.
 *
 * `write()` is async so the caller can apply backpressure while spilling.
 */

import type { MessageBody } from '../../shared/model.js';
import type { BodyLimits } from '../../shared/config.js';
import { BlobStore, BlobWriteSession } from './blobStore.js';

export class BodyCollector {
  private inlineChunks: Buffer[] = [];
  private storedBytes = 0;
  private totalBytes = 0;
  private truncated = false;
  private session?: BlobWriteSession;
  private finished = false;

  constructor(
    private readonly limits: BodyLimits,
    private readonly blobStore: BlobStore,
    private readonly contentEncoding?: string,
  ) {}

  /** Feed one chunk that passed through the proxy. */
  async write(chunk: Buffer): Promise<void> {
    if (this.finished) throw new Error('BodyCollector already finished');
    this.totalBytes += chunk.byteLength;

    if (this.storedBytes >= this.limits.maxCapturedBytes) {
      this.truncated = true;
      return;
    }

    // Clamp to the hard cap.
    let toStore = chunk;
    if (this.storedBytes + chunk.byteLength > this.limits.maxCapturedBytes) {
      toStore = chunk.subarray(0, this.limits.maxCapturedBytes - this.storedBytes);
      this.truncated = true;
    }

    if (this.session) {
      await this.session.write(toStore);
      this.storedBytes += toStore.byteLength;
      return;
    }

    // Would this push us past the in-memory threshold? If so, spill.
    if (this.storedBytes + toStore.byteLength > this.limits.spillToDiskAfterBytes) {
      this.session = await this.blobStore.beginWrite();
      for (const buffered of this.inlineChunks) {
        await this.session.write(buffered);
      }
      this.inlineChunks = [];
      await this.session.write(toStore);
      this.storedBytes += toStore.byteLength;
      return;
    }

    this.inlineChunks.push(toStore);
    this.storedBytes += toStore.byteLength;
  }

  async finish(): Promise<MessageBody> {
    if (this.finished) throw new Error('BodyCollector already finished');
    this.finished = true;

    const base: MessageBody = {
      size: this.storedBytes,
      truncated: this.truncated,
      ...(this.contentEncoding ? { contentEncoding: this.contentEncoding } : {}),
    };

    if (this.storedBytes === 0) {
      return base;
    }
    if (this.session) {
      const ref = await this.session.commit();
      return { ...base, blobId: ref.id };
    }
    return { ...base, inline: Buffer.concat(this.inlineChunks, this.storedBytes) };
  }

  /** Total bytes seen (including any beyond the cap). */
  get seenBytes(): number {
    return this.totalBytes;
  }
}

/**
 * Materialize a body's bytes for viewing/transforms. Returns an empty buffer for
 * empty bodies. For blob-backed bodies, reads from the store.
 */
export async function readBodyBytes(body: MessageBody, blobStore: BlobStore): Promise<Buffer> {
  if (body.inline) return Buffer.from(body.inline);
  if (body.blobId) return blobStore.readBytes(body.blobId);
  return Buffer.alloc(0);
}

/**
 * Build a MessageBody from a complete in-memory buffer, spilling to the blob
 * store when larger than the in-memory threshold. Used when a body is fully
 * known (edited-and-forwarded requests, repeater/variation responses).
 */
export async function bytesToBody(
  bytes: Uint8Array,
  limits: BodyLimits,
  blobStore: BlobStore,
  contentEncoding?: string,
): Promise<MessageBody> {
  let stored = bytes;
  let truncated = false;
  if (bytes.byteLength > limits.maxCapturedBytes) {
    stored = bytes.subarray(0, limits.maxCapturedBytes);
    truncated = true;
  }
  const body: MessageBody = { size: stored.byteLength, truncated };
  if (contentEncoding) body.contentEncoding = contentEncoding;
  if (stored.byteLength === 0) return body;
  if (stored.byteLength > limits.spillToDiskAfterBytes) {
    const ref = await blobStore.putBytes(stored);
    body.blobId = ref.id;
  } else {
    body.inline = Buffer.from(stored);
  }
  return body;
}
