import { describe, it, expect, afterAll } from 'vitest';
import * as tls from 'node:tls';
import * as os from 'node:os';
import * as path from 'node:path';
import { promises as fs } from 'node:fs';
import { CertificateAuthority } from '../../src/engine/ca/certificateAuthority.js';
import { InMemorySecretStore } from '../../src/engine/ca/secretStore.js';

const tmpDir = path.join(os.tmpdir(), `tacnoc-ca-${process.pid}`);

afterAll(async () => {
  await fs.rm(tmpDir, { recursive: true, force: true });
});

describe('CertificateAuthority', () => {
  it('generates a CA and persists the key to the secret store', async () => {
    const secrets = new InMemorySecretStore();
    const certPath = path.join(tmpDir, 'ca.pem');
    const ca = await CertificateAuthority.loadOrCreate(certPath, secrets);

    expect(ca.certificatePem).toContain('BEGIN CERTIFICATE');
    expect(ca.fingerprint).toMatch(/^([0-9A-F]{2}:){31}[0-9A-F]{2}$/);
    expect(await secrets.get('tls-ca-private-key')).toContain('PRIVATE KEY');
    // CA cert written to disk for the user to trust.
    expect(await fs.readFile(certPath, 'utf8')).toContain('BEGIN CERTIFICATE');
  });

  it('reloads the same CA from disk + secret store', async () => {
    const secrets = new InMemorySecretStore();
    const certPath = path.join(tmpDir, 'ca-reload.pem');
    const first = await CertificateAuthority.loadOrCreate(certPath, secrets);
    const second = await CertificateAuthority.loadOrCreate(certPath, secrets);
    expect(second.fingerprint).toBe(first.fingerprint);
  });

  it('mints leaf certs that validate against the CA over a real TLS handshake', async () => {
    const secrets = new InMemorySecretStore();
    const ca = await CertificateAuthority.loadOrCreate(path.join(tmpDir, 'ca2.pem'), secrets);

    const server = tls.createServer(
      {
        ...ca.leafPemFor('localhost'),
        SNICallback: (name, cb) => cb(null, ca.secureContextFor(name)),
      },
      (socket) => {
        socket.end('ok');
      },
    );

    // A pipe, not a loopback TCP port.
    //
    // This is the same real handshake either way — same certificates, same SNI,
    // same verification against the CA. Over TCP it was also a test of the OS
    // ephemeral-port pool, and it lost: about 1 run in 25 failed with a
    // transient socket error while the certificates themselves were fine. Two
    // probes established that: 199 of 200 handshakes verified (the one failure
    // being the client socket disconnecting mid-handshake, not a bad chain),
    // and 60 of 60 verified against freshly minted CAs. It failed the v0.5.6
    // release on Windows, where the gate had only just started running.
    //
    // A pipe has no port to recycle and nothing in TIME_WAIT.
    const unique = `${process.pid}-${Date.now()}`;
    const pipe =
      process.platform === 'win32'
        ? '\\\\.\\pipe\\tacnoc-ca-' + unique
        : path.join(tmpDir, 'ca-' + unique + '.sock');
    await fs.mkdir(tmpDir, { recursive: true });
    await new Promise<void>((resolve) => server.listen(pipe, resolve));

    const authorized = await new Promise<boolean>((resolve, reject) => {
      const client = tls.connect(
        { path: pipe, servername: 'example.test', ca: ca.certificatePem },
        () => {
          const ok = client.authorized;
          client.end();
          resolve(ok);
        },
      );
      client.on('error', reject);
    });
    server.close();
    expect(authorized).toBe(true);
  });

  it('issues distinct certs per host but reuses the leaf key', async () => {
    const secrets = new InMemorySecretStore();
    const ca = await CertificateAuthority.loadOrCreate(path.join(tmpDir, 'ca3.pem'), secrets);
    const a = ca.leafPemFor('a.example.test');
    const b = ca.leafPemFor('b.example.test');
    expect(a.cert).not.toBe(b.cert);
    expect(a.key).toBe(b.key);
  });
});
