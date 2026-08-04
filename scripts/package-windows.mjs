#!/usr/bin/env node
/**
 * Package TACNOC for Windows: a **portable** single-file `.exe` and an
 * **NSIS installer** `.exe`, in one step.
 *
 *   1. Deletes every previous release from `dist/` (build output; gitignored).
 *   2. Builds the app bundles (typecheck + electron-vite).
 *   3. Runs electron-builder for both Windows targets (nsis + portable).
 *   4. Writes the SHA-256 manifest — these builds are UNSIGNED by design
 *      (see RELEASE.md), so a checksum is the integrity backstop.
 *
 * Usage:  npm run dist:win   (or: node scripts/package-windows.mjs)
 *
 * Windows-only targets (portable/nsis). Run on Windows; on other OSes
 * electron-builder would need Wine and this script refuses rather than guess.
 */

import { rmSync, existsSync, readdirSync, statSync, readFileSync, writeFileSync } from 'node:fs';
import { execSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import * as path from 'node:path';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const dist = path.join(root, 'dist');

if (process.platform !== 'win32') {
  console.error(
    `This script builds Windows portable/NSIS targets and must run on Windows ` +
      `(current platform: ${process.platform}). Use the release.yml matrix for cross-OS builds.`,
  );
  process.exit(1);
}

/** Run a command, streaming its output; throw (and abort the script) on failure. */
function run(step, cmd) {
  console.log(`\n▶ ${step}\n  $ ${cmd}`);
  execSync(cmd, { cwd: root, stdio: 'inherit' });
}

/**
 * electron-builder can REWRITE the project's package.json in place during
 * packaging — it computes a production-trimmed manifest, and when the app
 * directory is the project root it has been observed writing that over the
 * source file, deleting `scripts` and `devDependencies` outright. That leaves
 * the repository broken in a way nothing else notices until the next
 * `npm run <anything>` fails, and it is exactly the sort of damage that gets
 * committed by accident during a release.
 *
 * So: snapshot the manifest before packaging and put it back afterwards, on
 * success or failure.
 */
function withManifestGuard(fn) {
  const manifest = path.join(root, 'package.json');
  const before = readFileSync(manifest, 'utf8');
  try {
    return fn();
  } finally {
    const after = readFileSync(manifest, 'utf8');
    if (after !== before) {
      writeFileSync(manifest, before, 'utf8');
      console.warn(
        'electron-builder modified package.json during packaging; the original has been restored.',
      );
    }
  }
}

const mib = (bytes) => `${(bytes / 1024 / 1024).toFixed(1)} MiB`;

// 1) Delete previous releases. dist/ is 100% build output (gitignored), so
//    removing the whole directory is the clean, reproducible reset.
if (existsSync(dist)) {
  const previous = readdirSync(dist);
  if (previous.length) {
    console.log(`Deleting ${previous.length} previous release item(s) from dist/:`);
    for (const name of previous.sort()) console.log(`  ✗ ${name}`);
  }
  rmSync(dist, { recursive: true, force: true });
} else {
  console.log('No previous dist/ to clean.');
}

// 2) Build the app (main/preload/renderer bundles); packaging reads out/.
run('Build app bundles', 'npm run build');

// 3) Package both Windows targets. Explicit target list so the script's intent
//    holds even if electron-builder.yml is later edited.
withManifestGuard(() =>
  run('Package portable + installer', 'npx --no-install electron-builder --win nsis portable'),
);

// 4) Checksums for the (unsigned) distributables.
run('Write SHA-256 manifest', 'node scripts/checksums.mjs');

// Summary: the two artifacts we set out to produce.
const exes = readdirSync(dist)
  .filter((name) => name.toLowerCase().endsWith('.exe'))
  .sort();
console.log(`\n✔ Done. Windows artifacts in dist/:`);
for (const name of exes) {
  const kind = /portable/i.test(name) ? 'portable' : /setup/i.test(name) ? 'installer' : 'exe';
  console.log(`  • ${name}  (${mib(statSync(path.join(dist, name)).size)}, ${kind})`);
}
if (exes.length < 2) {
  console.error('\nExpected both a portable and an installer .exe — check electron-builder output above.');
  process.exit(1);
}
