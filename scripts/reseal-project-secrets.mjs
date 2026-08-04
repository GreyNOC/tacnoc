/**
 * Re-seal a project's secrets under the app's current identity.
 *
 * WHY THIS EXISTS. Electron's `safeStorage` keeps its master key in
 * `<userData>/Local State`, and Electron derives userData from the app name —
 * which used to depend on how the process was started. A project created by one
 * launch mode could not be opened by another, and the failure read as "sealed by
 * a different OS user account or machine". `app.setName('TACNOC')` in the main
 * process stops new projects from landing in that state; this migrates the ones
 * that already did.
 *
 * Nothing is decrypted to disk. The plaintext crosses a pipe between two Electron
 * processes and the original file is copied aside before anything is written.
 *
 *   node scripts/reseal-project-secrets.mjs <projectDir> <oldUserDataDir>
 *
 * Find <oldUserDataDir> under %APPDATA% (Windows), ~/Library/Application Support
 * (macOS), or ~/.config (Linux) — it is the directory named for whichever build
 * created the project.
 */

import { spawn } from 'node:child_process';
import * as net from 'node:net';
import * as crypto from 'node:crypto';
import { promises as fs } from 'node:fs';
import * as path from 'node:path';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';

const require = createRequire(import.meta.url);
// fileURLToPath, not URL.pathname: the repo path contains a space, and a raw
// pathname leaves it percent-encoded and the leading slash on.
const HELPER = path.join(path.dirname(fileURLToPath(import.meta.url)), 'secret-helper.cjs');
const MARKER = '@@RESEAL@@';

const [projectDir, oldUserData] = process.argv.slice(2);
if (!projectDir || !oldUserData) {
  console.error('usage: node scripts/reseal-project-secrets.mjs <projectDir> <oldUserDataDir>');
  process.exit(2);
}

const secretsFile = path.join(projectDir, 'secrets.enc.json');

/**
 * Serve one payload to one caller over loopback, then shut the door.
 *
 * The helper cannot be fed over stdin — Electron's Windows binary is a GUI
 * subsystem process and never gets one. A temp file or an environment variable
 * would both put a CA private key somewhere it can be read after the fact.
 */
async function servePayload(payload) {
  const token = crypto.randomBytes(24).toString('hex');
  const server = net.createServer((socket) => {
    let seen = '';
    socket.setEncoding('utf8');
    socket.on('data', (c) => {
      seen += c;
      if (!seen.includes('\n')) return;
      const presented = seen.split('\n')[0];
      // Constant-time compare, and the server accepts exactly one caller.
      const ok =
        presented.length === token.length &&
        crypto.timingSafeEqual(Buffer.from(presented), Buffer.from(token));
      server.close();
      if (ok) socket.end(payload);
      else socket.destroy();
    });
    socket.on('error', () => undefined);
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  return { port: server.address().port, token, close: () => server.close() };
}

/** Run the helper under a given identity; returns its parsed result. */
function runHelper(mode, userDataDir, transfer) {
  return new Promise((resolve, reject) => {
    const args = [HELPER];
    if (userDataDir) args.push(`--user-data-dir=${userDataDir}`);
    if (transfer) args.push(`--payload-port=${transfer.port}`, `--payload-token=${transfer.token}`);
    args.push(mode, secretsFile);
    const child = spawn(require('electron'), args, { stdio: ['ignore', 'pipe', 'pipe'] });
    let out = '';
    child.stdout.on('data', (c) => (out += c));
    child.stderr.on('data', () => {}); // Electron is noisy on Windows; the marker is what matters
    child.on('error', reject);
    child.on('close', () => {
      const at = out.lastIndexOf(MARKER);
      if (at < 0) return reject(new Error(`helper produced no result (mode=${mode})`));
      try {
        resolve(JSON.parse(out.slice(at + MARKER.length).trim()));
      } catch (e) {
        reject(new Error(`helper result was not JSON (mode=${mode}): ${String(e)}`));
      }
    });
  });
}

const backup = `${secretsFile}.bak-${Date.now()}`;
await fs.copyFile(secretsFile, backup);
console.log(`Backed up  ${path.basename(backup)}`);

const read = await runHelper('decrypt', oldUserData);
if (!read.ok) {
  console.error(`\nCould not decrypt under ${oldUserData}:\n  ${read.error}`);
  console.error('That is not the identity this project was sealed with. Try another directory.');
  process.exit(1);
}
console.log(`Decrypted  ${Object.keys(read.secrets).length} secret(s) as "${read.identity}"`);

const transfer = await servePayload(JSON.stringify(read.secrets));
const wrote = await runHelper('encrypt', undefined, transfer);
transfer.close();
if (!wrote.ok) {
  console.error(`\nRe-sealing failed: ${wrote.error}`);
  console.error(`The original secret store is untouched at ${backup}`);
  process.exit(1);
}
console.log(`Re-sealed  ${wrote.keys.join(', ')} as "${wrote.identity}"`);
console.log(`           ${wrote.userData}`);

// Prove it round-trips under the new identity rather than claiming success.
const verify = await runHelper('decrypt', undefined);
if (!verify.ok || Object.keys(verify.secrets).length !== Object.keys(read.secrets).length) {
  console.error('\nVerification FAILED — restoring the original secret store.');
  await fs.copyFile(backup, secretsFile);
  process.exit(1);
}
for (const [k, v] of Object.entries(read.secrets)) {
  if (verify.secrets[k] !== v) {
    console.error(`\nVerification FAILED on "${k}" — restoring the original secret store.`);
    await fs.copyFile(backup, secretsFile);
    process.exit(1);
  }
}
console.log('Verified   every secret round-trips under the new identity.');
console.log(`\nDone. The project opens with this build now. Backup kept at:\n  ${backup}`);
