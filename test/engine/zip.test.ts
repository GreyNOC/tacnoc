/**
 * The ZIP container under evidence bundles.
 *
 * The writer is verified three ways: against its own reader (structure and
 * CRCs), against `zlib.crc32` (the checksum), and against an extractor this
 * project did not write — Windows' Expand-Archive or `unzip` — so a bundle a
 * recipient cannot open fails here, not on their desk.
 */

import { describe, expect, it } from 'vitest';
import * as os from 'node:os';
import * as path from 'node:path';
import * as zlib from 'node:zlib';
import { promises as fs } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { buildZip, checkZipPath, crc32, listZip, readZip } from '../../src/engine/evidence/zip.js';

const text = 'The quick brown fox jumps over the lazy dog.\n'.repeat(200);
const random = randomBytes(4096);

const entries = [
  { path: 'manifest.json', data: JSON.stringify({ ok: true }) },
  { path: 'exchanges/0001.http', data: text },
  { path: 'attachments/blob.bin', data: random },
  { path: 'empty.txt', data: '' },
  { path: 'notes/résumé.md', data: '# notes\n' },
];

const bytesOf = (data: Buffer | string): Buffer =>
  typeof data === 'string' ? Buffer.from(data, 'utf8') : data;

describe('zip writer and reader', () => {
  it('round-trips every entry byte for byte', () => {
    const zip = buildZip(entries, { mtime: new Date(2026, 0, 2, 3, 4, 6) });
    const back = readZip(zip);
    expect([...back.keys()]).toEqual(entries.map((e) => e.path));
    for (const e of entries) {
      const got = back.get(e.path);
      expect(got !== undefined && got.equals(bytesOf(e.data)), e.path).toBe(true);
    }
  });

  it('deflates what compresses and stores what does not', () => {
    const by = new Map(listZip(buildZip(entries)).map((l) => [l.path, l]));
    expect(by.get('exchanges/0001.http')?.method).toBe(8);
    expect(by.get('exchanges/0001.http')?.compressedSize).toBeLessThan(text.length);
    expect(by.get('attachments/blob.bin')?.method).toBe(0);
    expect(by.get('attachments/blob.bin')?.compressedSize).toBe(random.length);
    expect(by.get('empty.txt')?.method).toBe(0);
  });

  it('computes the same CRC-32 as zlib', () => {
    const z = (zlib as unknown as { crc32?: (b: Buffer) => number }).crc32;
    if (typeof z !== 'function') return; // Node before 22.2 has no zlib.crc32
    for (const buf of [Buffer.alloc(0), Buffer.from('a'), random, Buffer.from(text)]) {
      expect(crc32(buf)).toBe(z(buf) >>> 0);
    }
  });

  it('is deterministic for the same input and timestamp', () => {
    const at = new Date(2026, 5, 6, 7, 8, 10);
    expect(buildZip(entries, { mtime: at }).equals(buildZip(entries, { mtime: at }))).toBe(true);
  });

  it('refuses names an extractor could write outside the destination', () => {
    // A real NUL in a path, built rather than escaped so the source file
    // stays plain ASCII and git treats it as text.
    const NUL_NAME = 'a' + String.fromCharCode(0) + 'b';
    for (const bad of ['../x', '/abs', 'a\\b', 'a//b', './a', 'a/./b', 'a/../b', '', NUL_NAME]) {
      expect(() => checkZipPath(bad), JSON.stringify(bad)).toThrow();
    }
    expect(() =>
      buildZip([
        { path: 'a', data: '1' },
        { path: 'a', data: '2' },
      ]),
    ).toThrow(/duplicate/);
  });

  it('detects a corrupted or truncated archive instead of returning partial data', () => {
    const zip = buildZip(entries);
    const target = listZip(zip).find((l) => l.path === 'exchanges/0001.http');
    if (!target) throw new Error('entry missing');
    const corrupt = Buffer.from(zip);
    corrupt.writeUInt8(corrupt.readUInt8(target.dataOffset) ^ 0xff, target.dataOffset);
    expect(() => readZip(corrupt)).toThrow();
    expect(() => readZip(zip.subarray(0, zip.length - 30))).toThrow();
    expect(() => readZip(Buffer.from('not a zip at all'))).toThrow(/not a zip/);
  });

  it('opens in an extractor this project did not write', async () => {
    // Resolved for the same reason as in huntFolderLayout.test.ts: macOS tmpdir is a symlink.
    const dir = await fs.realpath(await fs.mkdtemp(path.join(os.tmpdir(), 'tacnoc-zip-')));
    try {
      const zipPath = path.join(dir, 'bundle.zip');
      const out = path.join(dir, 'out');
      await fs.writeFile(zipPath, buildZip(entries));
      if (process.platform === 'win32') {
        const r = spawnSync(
          'powershell',
          [
            '-NoProfile',
            '-NonInteractive',
            '-Command',
            `Expand-Archive -LiteralPath '${zipPath}' -DestinationPath '${out}' -Force`,
          ],
          { encoding: 'utf8' },
        );
        expect(r.status, r.stderr).toBe(0);
      } else {
        const r = spawnSync('unzip', ['-o', '-q', zipPath, '-d', out], { encoding: 'utf8' });
        if (r.error && (r.error as NodeJS.ErrnoException).code === 'ENOENT') return; // no unzip here
        expect(r.status, r.stderr).toBe(0);
      }
      for (const e of entries) {
        const rel = e.path.split('/');
        const expected = bytesOf(e.data);
        let got: Buffer | undefined;
        try {
          got = await fs.readFile(path.join(out, ...rel));
        } catch {
          // Info-ZIP's `unzip` does not reliably honour the UTF-8 name flag
          // (bit 11), so a non-ASCII entry can land under a different spelling.
          // The archive is correct either way - our own reader round-trips the
          // name exactly, which the round-trip test asserts - so match this
          // entry by content within its directory rather than by filename.
          // What this test is for is whether a foreign extractor can open the
          // archive at all, not how Info-ZIP transliterates names.
          const dir = path.join(out, ...rel.slice(0, -1));
          for (const name of await fs.readdir(dir)) {
            const candidate = await fs.readFile(path.join(dir, name));
            if (candidate.equals(expected)) {
              got = candidate;
              break;
            }
          }
        }
        expect(got !== undefined && got.equals(expected), e.path).toBe(true);
      }
    } finally {
      await fs.rm(dir, { recursive: true, force: true });
    }
  });
});
