#!/usr/bin/env node
/**
 * Compute SHA-256 checksums for release artifacts in dist/ and write
 * dist/SHA256SUMS.txt. Self-contained, no dependencies.
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

// Artifact extensions we checksum (installers/archives + the auto-update feed),
// excluding electron-builder's debug/effective-config intermediates.
const ARTIFACT = /\.(exe|dmg|zip|AppImage|tar\.gz|deb|rpm|blockmap|yml|yaml)$/i;
const SKIP = /^(builder-debug|builder-effective-config)/i;

const lines = [];
for (const name of readdirSync(dist).sort()) {
  const full = path.join(dist, name);
  if (!statSync(full).isFile()) continue;
  if (!ARTIFACT.test(name) || name === 'SHA256SUMS.txt' || SKIP.test(name)) continue;
  const hash = createHash('sha256').update(readFileSync(full)).digest('hex');
  lines.push(`${hash}  ${name}`);
}

if (lines.length === 0) {
  console.error('No artifacts found in dist/.');
  process.exit(1);
}

const out = path.join(dist, 'SHA256SUMS.txt');
writeFileSync(out, lines.join('\n') + '\n');
console.log(`Wrote ${path.relative(root, out)}:\n${lines.join('\n')}`);
