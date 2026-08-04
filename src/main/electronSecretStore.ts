/**
 * SecretStore backed by Electron `safeStorage` (DPAPI on Windows, Keychain on
 * macOS, libsecret on Linux). Ciphertext is stored in a file inside the project
 * directory; the encryption key never leaves the OS credential store.
 *
 * If OS encryption is unavailable, `isSecure()` returns false and the values are
 * stored obfuscated only — the UI surfaces this so the researcher can decide.
 */

import { app, safeStorage } from 'electron';
import { promises as fs } from 'node:fs';
import * as path from 'node:path';
import type { SecretStore } from '../engine/ca/secretStore.js';

export class ElectronSecretStore implements SecretStore {
  private readonly file: string;

  constructor(directory: string) {
    this.file = path.join(directory, 'secrets.enc.json');
  }

  isSecure(): boolean {
    try {
      return safeStorage.isEncryptionAvailable();
    } catch {
      return false;
    }
  }

  backendName(): string {
    return this.isSecure()
      ? 'OS secure storage (safeStorage)'
      : 'safeStorage (unencrypted fallback)';
  }

  private async readAll(): Promise<Record<string, string>> {
    try {
      return JSON.parse(await fs.readFile(this.file, 'utf8')) as Record<string, string>;
    } catch {
      return {};
    }
  }

  private async writeAll(map: Record<string, string>): Promise<void> {
    await fs.mkdir(path.dirname(this.file), { recursive: true });
    await fs.writeFile(this.file, JSON.stringify(map, null, 2), { mode: 0o600 });
  }

  async get(key: string): Promise<string | null> {
    const map = await this.readAll();
    const enc = map[key];
    if (enc === undefined) return null;
    const buf = Buffer.from(enc, 'base64');
    try {
      return this.isSecure() ? safeStorage.decryptString(buf) : buf.toString('utf8');
    } catch (err) {
      // The entry EXISTS but could not be decrypted — e.g. the project folder was
      // copied to a different OS user or machine, so DPAPI/Keychain cannot unwrap
      // it. This is NOT the same as "absent": returning null here would make
      // CertificateAuthority.loadOrCreate regenerate and OVERWRITE the still-present
      // CA key (permanent loss), and loadOrCreateDek silently drop at-rest
      // encryption. Fail loud so callers fail closed. Mirrors FileSecretStore,
      // which throws on a GCM auth-tag mismatch.
      throw new Error(
        `Secret "${key}" is present but could not be decrypted, so this project cannot be ` +
          `opened. The most likely cause is that it was created by a DIFFERENT BUILD of this ` +
          `app on this same machine: safeStorage keeps its master key under the app's userData ` +
          `directory, so a project sealed by one identity cannot be read by another. This ` +
          `process is "${app.getName()}", using ${app.getPath('userData')}. Check for sibling ` +
          `directories next to it — a project created by the packaged build cannot be opened ` +
          `by a dev launch, or vice versa, and re-launching under the original identity is the ` +
          `fix. Failing that, the folder was copied from another OS user or machine. Nothing ` +
          `is lost either way: the app will not regenerate keys over existing ones. ` +
          `(${String(err)})`,
      );
    }
  }

  async set(key: string, value: string): Promise<void> {
    const map = await this.readAll();
    const buf = this.isSecure() ? safeStorage.encryptString(value) : Buffer.from(value, 'utf8');
    map[key] = buf.toString('base64');
    await this.writeAll(map);
  }

  async delete(key: string): Promise<void> {
    const map = await this.readAll();
    delete map[key];
    await this.writeAll(map);
  }
}
