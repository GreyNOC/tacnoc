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
 *
 * Lifecycle: the CA can be **rotated** (replaced with fresh material, e.g. to
 * test what a client does when the certificate changes mid-engagement, or to
 * retire a CA whose private key was exposed) and **revoked** (material destroyed
 * outright, which turns TLS interception off until a new CA is issued). Both are
 * local operations on this project's own CA — no OS trust store is touched, so
 * "revoked" means "this app will no longer sign leaves with it", not a CRL
 * anyone else honours. `generation` increments on every change so the proxy can
 * notice and rebuild its TLS server without a restart.
 */

import * as tls from 'node:tls';
import { promises as fs } from 'node:fs';
import * as path from 'node:path';
import * as net from 'node:net';
import forge from 'node-forge';
import type { SecretStore } from './secretStore.js';
import type { CaCertStatus, CaRevocation } from '../../shared/engagement.js';

const CA_KEY_SECRET = 'tls-ca-private-key';
const CA_SUBJECT_CN = 'TACNOC Project CA';
const CA_ORG = 'TACNOC (authorized testing)';

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

interface CaMaterialInternal {
  cert: forge.pki.Certificate;
  key: forge.pki.rsa.PrivateKey;
  certPem: string;
  keyPem: string;
}

/** Generate CA material without touching any instance state. */
function generateCaMaterial(): CaMaterialInternal {
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
  return {
    cert,
    key: keys.privateKey,
    certPem: forge.pki.certificateToPem(cert),
    keyPem: forge.pki.privateKeyToPem(keys.privateKey),
  };
}

async function persistMaterial(
  certPath: string,
  secrets: SecretStore,
  material: CaMaterialInternal,
): Promise<void> {
  await fs.mkdir(path.dirname(certPath), { recursive: true });
  await fs.writeFile(certPath, material.certPem, { mode: 0o644 });
  await secrets.set(CA_KEY_SECRET, material.keyPem);
}

/**
 * Revocation is recorded next to the certificate so it outlives the process.
 * Without it, reopening a project with no CA looks exactly like a first run.
 */
const markerPath = (certPath: string): string => `${certPath}.revoked.json`;

async function writeRevocationMarker(certPath: string, record: CaRevocation): Promise<void> {
  await fs.writeFile(markerPath(certPath), JSON.stringify(record), { mode: 0o600 });
}

async function readRevocationMarker(certPath: string): Promise<CaRevocation | undefined> {
  try {
    const raw = await fs.readFile(markerPath(certPath), 'utf8');
    const parsed = JSON.parse(raw) as CaRevocation;
    return typeof parsed?.revokedAt === 'number' ? parsed : undefined;
  } catch {
    return undefined;
  }
}

async function clearRevocationMarker(certPath: string): Promise<void> {
  await fs.rm(markerPath(certPath), { force: true });
}

/** Render an X.509 name as `CN=…, O=…` for display. */
function describeName(attributes: forge.pki.CertificateField[]): string {
  return attributes
    .map((attr) => `${attr.shortName ?? attr.name ?? '?'}=${String(attr.value ?? '')}`)
    .join(', ');
}

function sha256Fingerprint(certPem: string): string {
  const der = forge.pki.pemToDer(certPem).getBytes();
  const md = forge.md.sha256.create();
  md.update(der);
  const hex = md.digest().toHex().toUpperCase();
  return (hex.match(/.{2}/g) ?? []).join(':');
}

export class CertificateAuthority {
  private caCert?: forge.pki.Certificate;
  private caKey?: forge.pki.rsa.PrivateKey;
  private caCertPem = '';
  private caKeyPem = '';
  private leafKeys!: forge.pki.rsa.KeyPair;
  private leafKeyPem = '';
  private certPath = '';
  private secrets!: SecretStore;
  private revokedAt?: number;
  private revokedReason?: string;
  /** Bumped on every rotate/revoke so the proxy can rebuild its TLS server. */
  private caGeneration = 0;
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
    ca.certPath = certPath;
    ca.secrets = secrets;
    const keyPem = await secrets.get(CA_KEY_SECRET);
    let certPem: string | null = null;
    try {
      certPem = await fs.readFile(certPath, 'utf8');
    } catch {
      certPem = null;
    }

    const revocation = await readRevocationMarker(certPath);
    if (keyPem && certPem) {
      ca.caKey = forge.pki.privateKeyFromPem(keyPem) as forge.pki.rsa.PrivateKey;
      ca.caCert = forge.pki.certificateFromPem(certPem);
      ca.caCertPem = certPem;
      ca.caKeyPem = keyPem;
    } else if (revocation) {
      // Revocation is a state the operator chose, so it survives a reopen.
      // Regenerating here would silently flip interception back on with a CA no
      // browser trusts — every HTTPS site would then hard-fail, which is worse
      // than the pass-through the operator asked for, and the status would
      // contradict the CA history that still records the revoke.
      ca.revokedAt = revocation.revokedAt;
      if (revocation.reason) ca.revokedReason = revocation.reason;
    } else {
      ca.generateCa();
      await ca.persist();
    }

    ca.leafKeys = forge.pki.rsa.generateKeyPair(2048);
    ca.leafKeyPem = forge.pki.privateKeyToPem(ca.leafKeys.privateKey);
    return ca;
  }

  private async persist(): Promise<void> {
    await fs.mkdir(path.dirname(this.certPath), { recursive: true });
    await fs.writeFile(this.certPath, this.caCertPem, { mode: 0o644 });
    await this.secrets.set(CA_KEY_SECRET, this.caKeyPem);
  }

  /**
   * Issue a fresh CA, replacing the current one. Existing per-host leaves are
   * discarded, so every subsequent TLS interception uses the new chain — which
   * clients that trusted the OLD certificate will reject until the operator
   * installs the new one. That break is the point: it is how you test a client's
   * pinning or trust behaviour, and how you retire a CA safely.
   *
   * Returns the record of what was replaced (undefined when there was nothing —
   * e.g. issuing after a revoke).
   */
  async rotate(reason = ''): Promise<CaRevocation | undefined> {
    const previous = this.caCert ? this.revocationRecord('rotate', reason) : undefined;
    // Build the new material off to the side and publish it in one synchronous
    // step. Swapping first and awaiting the write afterwards leaves a window
    // where the generation still reads as unchanged (so the proxy keeps its old
    // TLS server) while freshly-minted leaves are already signed by the new CA —
    // three chains in play at once, and none of them consistently trusted.
    const fresh = generateCaMaterial();
    await persistMaterial(this.certPath, this.secrets, fresh);
    await clearRevocationMarker(this.certPath);
    this.caCert = fresh.cert;
    this.caKey = fresh.key;
    this.caCertPem = fresh.certPem;
    this.caKeyPem = fresh.keyPem;
    delete this.revokedAt;
    delete this.revokedReason;
    this.leafCache.clear();
    this.caGeneration += 1;
    return previous;
  }

  /**
   * Destroy this project's CA material. TLS interception stops: the proxy can no
   * longer mint leaf certificates, so CONNECT tunnels pass through unread until
   * a new CA is issued with `rotate()`. The certificate file and the stored
   * private key are both removed.
   */
  async revoke(reason = ''): Promise<CaRevocation | undefined> {
    if (!this.caCert) return undefined;
    const record = this.revocationRecord('revoke', reason);
    // Destroy the durable material FIRST, and only then drop the in-memory
    // state. The other order leaves a failed revoke in the worst possible
    // place: the app believes the CA is gone (so the retry short-circuits and
    // nothing is ever cleaned up) while the certificate the browser trusts and
    // its private key both remain on disk indefinitely.
    await this.secrets.delete(CA_KEY_SECRET);
    await fs.rm(this.certPath, { force: true });
    await writeRevocationMarker(this.certPath, record);
    delete this.caCert;
    delete this.caKey;
    this.caCertPem = '';
    this.caKeyPem = '';
    this.leafCache.clear();
    this.revokedAt = record.revokedAt;
    this.revokedReason = reason;
    this.caGeneration += 1;
    return record;
  }

  private revocationRecord(action: 'revoke' | 'rotate', reason: string): CaRevocation {
    return {
      fingerprint: this.caCertPem ? sha256Fingerprint(this.caCertPem) : '',
      serial: this.caCert?.serialNumber ?? '',
      revokedAt: Date.now(),
      reason,
      action,
    };
  }

  /** False once revoked: the proxy must not attempt TLS interception. */
  get active(): boolean {
    return !!this.caCert;
  }

  get generation(): number {
    return this.caGeneration;
  }

  get revocation(): { revokedAt?: number; reason?: string } {
    return {
      ...(this.revokedAt !== undefined ? { revokedAt: this.revokedAt } : {}),
      ...(this.revokedReason ? { reason: this.revokedReason } : {}),
    };
  }

  /** Certificate metadata for display and expiry checks; undefined once revoked. */
  status(): CaCertStatus | undefined {
    const cert = this.caCert;
    if (!cert) return undefined;
    const notBefore = cert.validity.notBefore.getTime();
    const notAfter = cert.validity.notAfter.getTime();
    const daysRemaining = Math.floor((notAfter - Date.now()) / DAY_MS);
    return {
      subject: describeName(cert.subject.attributes),
      issuer: describeName(cert.issuer.attributes),
      serial: cert.serialNumber,
      fingerprint: sha256Fingerprint(this.caCertPem),
      notBefore,
      notAfter,
      daysRemaining,
      expired: notAfter <= Date.now(),
      expiringSoon: daysRemaining <= 30,
    };
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
      fingerprintSha256: this.caCertPem ? sha256Fingerprint(this.caCertPem) : '',
    };
  }

  /** Public CA certificate PEM, safe to export for the user to trust. */
  get certificatePem(): string {
    return this.caCertPem;
  }

  get fingerprint(): string {
    return this.caCertPem ? sha256Fingerprint(this.caCertPem) : '';
  }

  /** Mint (or fetch cached) a leaf certificate for a host. */
  private leafFor(host: string): LeafEntry {
    const caCert = this.caCert;
    const caKey = this.caKey;
    if (!caCert || !caKey) {
      throw new Error(
        'the project CA is revoked — TLS interception is off until a new CA is issued',
      );
    }
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
    cert.setIssuer(caCert.subject.attributes);

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
    cert.sign(caKey, forge.md.sha256.create());

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
