import { describe, it, expect, afterAll } from 'vitest';
import * as tls from 'node:tls';
import * as forge from 'node-forge';
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

  // --- serial numbers must be valid DER INTEGERs -------------------------
  //
  // These are regressions for a defect that broke real interception, not a
  // cosmetic one. The serial was `'00' + 15 random bytes`: positive, but
  // node-forge strips exactly one leading zero when it writes the DER, so if
  // the first random byte was also 0x00 and the next had its high bit clear,
  // the encoding kept a redundant leading zero. OpenSSL 3 then refused the
  // certificate from `tls.createSecureContext` with
  // `asn1 encoding routines::illegal padding` — roughly 1 leaf in 512, so that
  // host's HTTPS interception failed outright, and a new CA was unusable at the
  // same rate. It surfaced as an intermittent macOS release failure.

  it('mints serials that survive a DER round trip without a stripped byte', async () => {
    const secrets = new InMemorySecretStore();
    const ca = await CertificateAuthority.loadOrCreate(path.join(tmpDir, 'ca-serial.pem'), secrets);

    // Re-reading the PEM is the check: forge normalises away any leading zero
    // it wrote, so a serial that comes back SHORTER than the 16 bytes minted is
    // exactly the non-minimal encoding OpenSSL rejects. The old generator
    // produced one about half the time.
    const seen = new Set<string>();
    for (let i = 0; i < 64; i++) {
      const pem = ca.leafPemFor(`h${i}.serial.test`).cert;
      const sn = forge.pki.certificateFromPem(pem).serialNumber;
      expect(sn, `leaf ${i}`).toMatch(/^[0-9a-f]{32}$/);
      // No leading zero byte AT ALL. A leading zero is sometimes legitimate
      // (it is what keeps a high-bit-set integer positive), but the generator
      // avoids ever needing one, so seeing one here means it is back to
      // prefixing - and prefixing is what produced the non-minimal encodings.
      expect(
        sn.startsWith('00'),
        `leaf ${i} starts with a zero byte; the generator must emit 0x01..0x7f so ` +
          `there is never a leading zero to strip`,
      ).toBe(false);
      expect(parseInt(sn.slice(0, 2), 16), `leaf ${i} is not positive`).toBeLessThan(0x80);
      seen.add(sn);
    }
    expect(seen.size, 'serials must not repeat').toBe(64);

    // The CA's own certificate goes through the same generator.
    const caSn = forge.pki.certificateFromPem(ca.certificatePem).serialNumber;
    expect(caSn).toMatch(/^[0-9a-f]{32}$/);
    expect(caSn.startsWith('00')).toBe(false);
  });

  it('is rejected by OpenSSL when the serial is non-minimal — the actual failure', () => {
    // Pinning the mechanism, so a future "tidy-up" of the generator that
    // reintroduces a leading zero fails here with an explanation rather than
    // intermittently in CI.
    const keys = forge.pki.rsa.generateKeyPair(2048);
    const attrs = [{ name: 'commonName', value: 'serial.test' }];
    const keyPem = forge.pki.privateKeyToPem(keys.privateKey);

    const certWith = (serialNumber: string): string => {
      const cert = forge.pki.createCertificate();
      cert.publicKey = keys.publicKey;
      cert.serialNumber = serialNumber;
      cert.validity.notBefore = new Date(Date.now() - 86_400_000);
      cert.validity.notAfter = new Date(Date.now() + 86_400_000);
      cert.setSubject(attrs);
      cert.setIssuer(attrs);
      cert.setExtensions([{ name: 'basicConstraints', cA: false }]);
      cert.sign(keys.privateKey, forge.md.sha256.create());
      return forge.pki.certificateToPem(cert);
    };

    // Two leading zero bytes: forge strips one, the other is redundant.
    expect(() =>
      tls.createSecureContext({ key: keyPem, cert: certWith('00000d8b2b83238bb48494136ac60b51') }),
    ).toThrow(/illegal padding/);

    // What the generator now produces: first byte 0x01..0x7f, nothing to strip.
    expect(() =>
      tls.createSecureContext({ key: keyPem, cert: certWith('3d27c23f6445ad3665430c653e1dee10') }),
    ).not.toThrow();
  }, 30_000);

  it('issues distinct certs per host but reuses the leaf key', async () => {
    const secrets = new InMemorySecretStore();
    const ca = await CertificateAuthority.loadOrCreate(path.join(tmpDir, 'ca3.pem'), secrets);
    const a = ca.leafPemFor('a.example.test');
    const b = ca.leafPemFor('b.example.test');
    expect(a.cert).not.toBe(b.cert);
    expect(a.key).toBe(b.key);
  });
});
