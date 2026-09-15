#!/usr/bin/env node
/**
 * Package TACNOC for Linux as a **portable tar.gz** — extract and run.
 *
 *   1. Builds the app bundles (typecheck + electron-vite).
 *   2. Runs electron-builder for the Linux x64 `tar.gz` target.
 *   3. Prints the artifact and how to run it.
 *
 * Usage:  npm run dist:linux   (or: node scripts/package-linux.mjs)
 *
 * Why only tar.gz, and why this can run on Windows:
 *
 * electron-builder cross-builds Linux `tar.gz` from any host — it downloads the
 * Linux Electron binary and repackages the app directory, with no Linux-only
 * tooling involved. **AppImage cannot be built from Windows**: packaging one
 * creates symlinks inside the image, and Windows refuses those without Developer
 * Mode or elevation, so the build fails with `EPERM`. Rather than emit a broken
 * artifact or a confusing stack trace, this script builds the target that works
 * and says so. Build AppImage on Linux (`npx electron-builder --linux AppImage`)
 * or through the release.yml matrix.
 *
 * The output is UNSIGNED by design (see RELEASE.md); `npm run checksums` writes
 * the SHA-256 manifest that is the integrity backstop.
 */

import { existsSync, readdirSync, statSync, readFileSync, writeFileSync } from 'node:fs';
import { execSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import * as path from 'node:path';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const dist = path.join(root, 'dist');

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

if (process.platform === 'win32') {
  console.log(
    'Note: building the Linux tar.gz from Windows. AppImage is skipped — it needs\n' +
      'symlink support Windows does not grant unelevated. See RELEASE.md.',
  );
}

run('Build app bundles', 'npm run build');
withManifestGuard(() =>
  run('Package Linux tar.gz (x64)', 'npx electron-builder --linux tar.gz --x64'),
);

const artifacts = existsSync(dist)
  ? readdirSync(dist).filter((f) => f.endsWith('.tar.gz'))
  : [];

if (!artifacts.length) {
  console.error('\nNo .tar.gz produced in dist/. The build did not complete as expected.');
  process.exit(1);
}

console.log('\nLinux artifact:');
for (const name of artifacts) {
  console.log(`  ${name}  (${mib(statSync(path.join(dist, name)).size)})`);
}
// The Linux executable is named from the package `name`, NOT the `productName`
// — so it is `greynoc-tacnoc`, not `tacnoc`. This message used to print
// `./tacnoc`, which names a file that is not in the archive: anyone following it
// got "No such file or directory" from the very first thing they were told to
// run. Read it out of the built payload rather than hardcoding it again.
const EXE_FALLBACK = 'greynoc-tacnoc';
const unpacked = path.join(dist, 'linux-unpacked');
const exeName = existsSync(unpacked)
  ? (readdirSync(unpacked).find((f) => f === EXE_FALLBACK) ?? EXE_FALLBACK)
  : EXE_FALLBACK;

console.log(
  '\nRun it on a Linux x64 host:\n' +
    `  tar -xzf ${artifacts[0]}\n` +
    `  cd TACNOC-*/ && ./${exeName}\n` +
    '\nElectron needs a display and the usual desktop libraries (GTK, NSS, libX11).\n' +
    `On a headless box: xvfb-run ./${exeName} — or use --no-sandbox only if your\n` +
    'container lacks user namespaces, understanding that it lowers isolation.',
);
