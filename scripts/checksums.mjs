#!/usr/bin/env node
/**
 * Compute SHA-256 checksums for the release artifacts in dist/ and write a
 * per-OS manifest (SHA256SUMS-<os>.txt). Self-contained, no dependencies.
 *
 * The filename is platform-specific on purpose: the release job downloads every
 * OS matrix leg's artifacts into one flat set, so a single `SHA256SUMS.txt`
 * from three OSes would collide (only one basename survives the upload). A
 * per-OS name keeps all three manifests.
 */

import { readdirSync, statSync, readFileSync, writeFileSync, existsSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import * as path from 'node:path';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const dist = path.join(root, 'dist');

if (!existsSync(dist)) {
  console.error('dist/ not found — run `npm run dist` first.');
  process.exit(1);
}

const OS_LABEL = { win32: 'windows', darwin: 'macos', linux: 'linux' }[process.platform] ?? process.platform;
const OUT_NAME = `SHA256SUMS-${OS_LABEL}.txt`;

// Only the installers/archives we actually distribute. electron-builder also
// emits an auto-update feed (latest*.yml) and .blockmap deltas; this app ships
// no auto-updater, so those are NOT distributed and must not appear in a
// checksum manifest for files no one can download.
const ARTIFACT = /\.(exe|dmg|zip|AppImage|tar\.gz|deb|rpm)$/i;
const SKIP = /^(builder-debug|builder-effective-config)/i;

const lines = [];
for (const name of readdirSync(dist).sort()) {
  const full = path.join(dist, name);
  if (!statSync(full).isFile()) continue;
  if (!ARTIFACT.test(name) || SKIP.test(name)) continue;
  const hash = createHash('sha256').update(readFileSync(full)).digest('hex');
  lines.push(`${hash}  ${name}`);
}

if (lines.length === 0) {
  console.error('No distributable artifacts found in dist/.');
  process.exit(1);
}

const out = path.join(dist, OUT_NAME);
writeFileSync(out, lines.join('\n') + '\n');
console.log(`Wrote ${path.relative(root, out)}:\n${lines.join('\n')}`);
