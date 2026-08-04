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
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const port = (server.address() as { port: number }).port;

    const authorized = await new Promise<boolean>((resolve, reject) => {
      const client = tls.connect(
        { host: '127.0.0.1', port, servername: 'example.test', ca: ca.certificatePem },
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
