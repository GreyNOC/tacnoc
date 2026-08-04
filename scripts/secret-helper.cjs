/**
 * Electron helper for re-sealing a project's secrets. Not a user-facing tool —
 * driven by scripts/reseal-project-secrets.mjs, which launches it twice.
 *
 * safeStorage's master key lives under the app's userData directory, so a value
 * sealed by one app identity can only be unsealed by a process running with that
 * same identity. Migrating therefore takes two processes: one launched with the
 * OLD --user-data-dir to decrypt, one with the NEW one to encrypt.
 *
 * Plaintext moves between them over a pipe (stdout -> parent -> stdin). It is
 * never written to disk: the whole point of the exercise is a CA private key, and
 * dropping it in a temp file to save a few lines would be indefensible.
 *
 *   electron secret-helper.cjs decrypt <secrets.enc.json>   -> JSON on stdout
 *   electron secret-helper.cjs encrypt <secrets.enc.json>   <- JSON on stdin
 */

const { app, safeStorage } = require('electron');
const fs = require('fs');

// The same pin the main process applies. Without it this helper runs as
// "Electron" and would re-seal into a fourth identity the app never reads —
// migrating the project from one unopenable state into another.
// A --user-data-dir flag still overrides this, which is how the OLD identity is
// targeted for the read side.
app.setName('TACNOC');

const argOf = (name) => {
  const hit = process.argv.find((a) => a.startsWith(`--${name}=`));
  return hit ? hit.slice(name.length + 3) : undefined;
};
const mode = process.argv[process.argv.length - 2];
const file = process.argv[process.argv.length - 1];

const done = (payload, code) => {
  process.stdout.write('\n@@RESEAL@@' + JSON.stringify(payload) + '\n', () => app.exit(code));
};

/**
 * Fetch the plaintext from the parent over loopback.
 *
 * Not stdin: Electron's Windows binary is a GUI-subsystem process and never
 * receives one, so a piped payload silently arrived empty. Not a temp file and
 * not an environment variable either — this is a CA private key in transit, and
 * neither the disk nor the process table is an acceptable place for it. The
 * parent binds 127.0.0.1 on an ephemeral port and hands over exactly once, to a
 * caller presenting the one-time token passed in argv.
 */
function fetchPayload(port, token) {
  return new Promise((resolve, reject) => {
    const socket = require('net').connect(Number(port), '127.0.0.1', () => socket.end(token + '\n'));
    let raw = '';
    socket.setEncoding('utf8');
    socket.on('data', (c) => (raw += c));
    socket.on('end', () => resolve(raw));
    socket.on('error', reject);
  });
}

app.whenReady().then(() => {
  if (!safeStorage.isEncryptionAvailable()) {
    return done({ ok: false, error: 'safeStorage reports encryption is unavailable' }, 1);
  }
  try {
    if (mode === 'decrypt') {
      const map = JSON.parse(fs.readFileSync(file, 'utf8'));
      const out = {};
      for (const [k, v] of Object.entries(map)) {
        out[k] = safeStorage.decryptString(Buffer.from(v, 'base64'));
      }
      return done({ ok: true, identity: app.getName(), userData: app.getPath('userData'), secrets: out }, 0);
    }

    if (mode === 'encrypt') {
      void fetchPayload(argOf('payload-port'), argOf('payload-token')).then((raw) => {
        try {
          const secrets = JSON.parse(raw);
          const map = {};
          for (const [k, v] of Object.entries(secrets)) {
            map[k] = safeStorage.encryptString(v).toString('base64');
          }
          // Write beside the target and rename, so an interrupted run cannot
          // leave a half-written secret store where a whole one used to be.
          fs.writeFileSync(file + '.new', JSON.stringify(map, null, 2), { mode: 0o600 });
          fs.renameSync(file + '.new', file);
          done({ ok: true, identity: app.getName(), userData: app.getPath('userData'), keys: Object.keys(map) }, 0);
        } catch (e) {
          done({ ok: false, error: String(e) }, 1);
        }
      });
      return undefined;
    }

    return done({ ok: false, error: 'unknown mode: ' + mode }, 1);
  } catch (e) {
    return done({ ok: false, error: String(e) }, 1);
  }
});
