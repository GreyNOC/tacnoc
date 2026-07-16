/**
 * Local TLS interception Certificate Authority.
 *
 * Generates a project-scoped CA locally (never fetched, never shared). The CA
 * private key is held in the injected SecretStore (OS secure storage in the
 * app). Per-host leaf certificates are minted on demand, signed by the CA, and
 * cached in memory. A single shared leaf key pair is reused across hosts for
 * speed — only the certificate differs per host.
 *
 * Safety notes:
 *  - The CA is only useful to a client that has been explicitly told to trust it
 *    (see docs/certificate-management.md). We never modify OS trust stores from
 *    the engine.
 *  - Leaf certs are short-lived (≈397 days) and constrained by SAN to the host.
 */

import * as tls from 'node:tls';
import { promises as fs } from 'node:fs';
import * as path from 'node:path';
import * as net from 'node:net';
import forge from 'node-forge';
import type { SecretStore } from './secretStore.js';

const CA_KEY_SECRET = 'tls-ca-private-key';
const CA_SUBJECT_CN = 'GreyNOC Belcher Project CA';
const CA_ORG = 'GreyNOC Belcher (authorized testing)';

const DAY_MS = 24 * 60 * 60 * 1000;

export interface CaMaterial {
  certPem: string;
  keyPem: string;
  /** SHA-256 fingerprint (colon-separated hex) for display/verification. */
  fingerprintSha256: string;
}

interface LeafEntry {
  certPem: string;
  keyPem: string;
  context: tls.SecureContext;
}

function randomSerialHex(): string {
  // Positive serial: force high bit clear by prefixing 0x00-safe byte.
  const bytes = forge.random.getBytesSync(16);
  const hex = forge.util.bytesToHex(bytes);
  return '00' + hex.slice(2);
}

function sha256Fingerprint(certPem: string): string {
  const der = forge.pki.pemToDer(certPem).getBytes();
  const md = forge.md.sha256.create();
  md.update(der);
  const hex = md.digest().toHex().toUpperCase();
  return (hex.match(/.{2}/g) ?? []).join(':');
}

export class CertificateAuthority {
  private caCert!: forge.pki.Certificate;
  private caKey!: forge.pki.rsa.PrivateKey;
  private caCertPem = '';
  private caKeyPem = '';
  private leafKeys!: forge.pki.rsa.KeyPair;
  private leafKeyPem = '';
  // LRU-bounded so client-controlled TLS SNI cannot grow the cache without limit
  // (each miss synchronously mints + signs a leaf — a DoS lever otherwise).
  private readonly leafCache = new Map<string, LeafEntry>();
  private static readonly LEAF_CACHE_MAX = 1024;

  private constructor() {}

  /**
   * Load the CA from disk + secret store, or generate a new one if absent.
   * @param certPath path to the public CA certificate PEM on disk.
   * @param secrets  secret store holding the CA private key.
   */
  static async loadOrCreate(certPath: string, secrets: SecretStore): Promise<CertificateAuthority> {
    const ca = new CertificateAuthority();
    const keyPem = await secrets.get(CA_KEY_SECRET);
    let certPem: string | null = null;
    try {
      certPem = await fs.readFile(certPath, 'utf8');
    } catch {
      certPem = null;
    }

    if (keyPem && certPem) {
      ca.caKey = forge.pki.privateKeyFromPem(keyPem) as forge.pki.rsa.PrivateKey;
      ca.caCert = forge.pki.certificateFromPem(certPem);
      ca.caCertPem = certPem;
      ca.caKeyPem = keyPem;
    } else {
      ca.generateCa();
      await fs.mkdir(path.dirname(certPath), { recursive: true });
      await fs.writeFile(certPath, ca.caCertPem, { mode: 0o644 });
      await secrets.set(CA_KEY_SECRET, ca.caKeyPem);
    }

    ca.leafKeys = forge.pki.rsa.generateKeyPair(2048);
    ca.leafKeyPem = forge.pki.privateKeyToPem(ca.leafKeys.privateKey);
    return ca;
  }

  private generateCa(): void {
    const keys = forge.pki.rsa.generateKeyPair(3072);
    const cert = forge.pki.createCertificate();
    cert.publicKey = keys.publicKey;
    cert.serialNumber = randomSerialHex();
    const now = Date.now();
    cert.validity.notBefore = new Date(now - DAY_MS);
    cert.validity.notAfter = new Date(now + 5 * 365 * DAY_MS);
    const attrs = [
      { name: 'commonName', value: CA_SUBJECT_CN },
      { name: 'organizationName', value: CA_ORG },
    ];
    cert.setSubject(attrs);
    cert.setIssuer(attrs);
    cert.setExtensions([
      { name: 'basicConstraints', cA: true, critical: true },
      { name: 'keyUsage', keyCertSign: true, cRLSign: true, critical: true },
      { name: 'subjectKeyIdentifier' },
    ]);
    cert.sign(keys.privateKey, forge.md.sha256.create());
    this.caCert = cert;
    this.caKey = keys.privateKey;
    this.caCertPem = forge.pki.certificateToPem(cert);
    this.caKeyPem = forge.pki.privateKeyToPem(keys.privateKey);
  }

  get material(): CaMaterial {
    return {
      certPem: this.caCertPem,
      keyPem: this.caKeyPem,
      fingerprintSha256: sha256Fingerprint(this.caCertPem),
    };
  }

  /** Public CA certificate PEM, safe to export for the user to trust. */
  get certificatePem(): string {
    return this.caCertPem;
  }

  get fingerprint(): string {
    return sha256Fingerprint(this.caCertPem);
  }

  /** Mint (or fetch cached) a leaf certificate for a host. */
  private leafFor(host: string): LeafEntry {
    const cached = this.leafCache.get(host);
    if (cached) {
      // Mark as most-recently-used.
      this.leafCache.delete(host);
      this.leafCache.set(host, cached);
      return cached;
    }

    const cert = forge.pki.createCertificate();
    cert.publicKey = this.leafKeys.publicKey;
    cert.serialNumber = randomSerialHex();
    const now = Date.now();
    cert.validity.notBefore = new Date(now - DAY_MS);
    cert.validity.notAfter = new Date(now + 397 * DAY_MS);
    cert.setSubject([{ name: 'commonName', value: host }]);
    cert.setIssuer(this.caCert.subject.attributes);

    const isIp = net.isIP(host) !== 0;
    const altName = isIp ? { type: 7, ip: host } : { type: 2, value: host };
    cert.setExtensions([
      { name: 'basicConstraints', cA: false },
      {
        name: 'keyUsage',
        digitalSignature: true,
        keyEncipherment: true,
      },
      { name: 'extKeyUsage', serverAuth: true },
      { name: 'subjectAltName', altNames: [altName] },
    ]);
    cert.sign(this.caKey, forge.md.sha256.create());

    const certPem = forge.pki.certificateToPem(cert);
    const context = tls.createSecureContext({ key: this.leafKeyPem, cert: certPem });
    const entry: LeafEntry = { certPem, keyPem: this.leafKeyPem, context };
    // Evict least-recently-used entries once the cache is full.
    while (this.leafCache.size >= CertificateAuthority.LEAF_CACHE_MAX) {
      const oldest = this.leafCache.keys().next().value;
      if (oldest === undefined) break;
      this.leafCache.delete(oldest);
    }
    this.leafCache.set(host, entry);
    return entry;
  }

  /** Secure context for TLS termination of `host` (for SNICallback). */
  secureContextFor(host: string): tls.SecureContext {
    return this.leafFor(host).context;
  }

  /** Leaf cert+key PEMs for a host (used to build a MITM tls.Server). */
  leafPemFor(host: string): { cert: string; key: string } {
    const leaf = this.leafFor(host);
    return { cert: leaf.certPem, key: leaf.keyPem };
  }
}
