/**
 * Secret storage abstraction.
 *
 * The CA private key and other secrets are held behind this interface. In the
 * Electron app the concrete implementation is backed by the OS secure store
 * (`safeStorage` → DPAPI / Keychain / libsecret; see src/main). For headless
 * tests and CI we provide:
 *   - InMemorySecretStore  — ephemeral, nothing touches disk.
 *   - FileSecretStore      — AES-256-GCM at rest under a local key file. This is
 *                            OBFUSCATION-GRADE ONLY (the key sits next to the
 *                            data) and is explicitly NOT equivalent to OS secure
 *                            storage. `isSecure()` returns false for it.
 */

import { promises as fs } from 'node:fs';
import * as path from 'node:path';
import * as crypto from 'node:crypto';

export interface SecretStore {
  get(key: string): Promise<string | null>;
  set(key: string, value: string): Promise<void>;
  delete(key: string): Promise<void>;
  /** True when backed by OS-level secure storage. */
  isSecure(): boolean;
  /** Human-readable backend name for the UI/diagnostics. */
  backendName(): string;
}

export class InMemorySecretStore implements SecretStore {
  private readonly map = new Map<string, string>();
  async get(key: string): Promise<string | null> {
    return this.map.has(key) ? (this.map.get(key) as string) : null;
  }
  async set(key: string, value: string): Promise<void> {
    this.map.set(key, value);
  }
  async delete(key: string): Promise<void> {
    this.map.delete(key);
  }
  isSecure(): boolean {
    return false;
  }
  backendName(): string {
    return 'in-memory (ephemeral)';
  }
}

interface SealedRecord {
  iv: string;
  tag: string;
  data: string;
}

/**
 * File-backed store. Values are individually sealed with AES-256-GCM using a key
 * derived (scrypt) from a locally-stored random master secret. Because the
 * master secret lives on the same disk, this protects against casual disclosure
 * only. Use OS secure storage for real protection.
 */
export class FileSecretStore implements SecretStore {
  private readonly dataFile: string;
  private readonly keyFile: string;
  private keyPromise?: Promise<Buffer>;

  constructor(directory: string) {
    this.dataFile = path.join(directory, 'secrets.json');
    this.keyFile = path.join(directory, 'secrets.key');
  }

  isSecure(): boolean {
    return false;
  }
  backendName(): string {
    return 'file (AES-GCM, obfuscation-grade)';
  }

  private async masterKey(): Promise<Buffer> {
    if (!this.keyPromise) {
      this.keyPromise = (async () => {
        await fs.mkdir(path.dirname(this.keyFile), { recursive: true });
        try {
          const raw = await fs.readFile(this.keyFile);
          if (raw.length >= 32) return raw.subarray(0, 32);
        } catch {
          /* generate below */
        }
        const material = crypto.randomBytes(32);
        await fs.writeFile(this.keyFile, material, { mode: 0o600 });
        return material;
      })();
    }
    return this.keyPromise;
  }

  private async readAll(): Promise<Record<string, SealedRecord>> {
    try {
      const raw = await fs.readFile(this.dataFile, 'utf8');
      return JSON.parse(raw) as Record<string, SealedRecord>;
    } catch {
      return {};
    }
  }

  private async writeAll(records: Record<string, SealedRecord>): Promise<void> {
    await fs.mkdir(path.dirname(this.dataFile), { recursive: true });
    await fs.writeFile(this.dataFile, JSON.stringify(records, null, 2), { mode: 0o600 });
  }

  async get(key: string): Promise<string | null> {
    const records = await this.readAll();
    const rec = records[key];
    if (!rec) return null;
    const mk = await this.masterKey();
    const derived = crypto.scryptSync(mk, 'belcher-secret-store', 32);
    const decipher = crypto.createDecipheriv('aes-256-gcm', derived, Buffer.from(rec.iv, 'base64'));
    decipher.setAuthTag(Buffer.from(rec.tag, 'base64'));
    const out = Buffer.concat([decipher.update(Buffer.from(rec.data, 'base64')), decipher.final()]);
    return out.toString('utf8');
  }

  async set(key: string, value: string): Promise<void> {
    const mk = await this.masterKey();
    const derived = crypto.scryptSync(mk, 'belcher-secret-store', 32);
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', derived, iv);
    const data = Buffer.concat([cipher.update(Buffer.from(value, 'utf8')), cipher.final()]);
    const tag = cipher.getAuthTag();
    const records = await this.readAll();
    records[key] = {
      iv: iv.toString('base64'),
      tag: tag.toString('base64'),
      data: data.toString('base64'),
    };
    await this.writeAll(records);
  }

  async delete(key: string): Promise<void> {
    const records = await this.readAll();
    delete records[key];
    await this.writeAll(records);
  }
}
