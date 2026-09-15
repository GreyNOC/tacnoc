/**
 * Tests for the engagement layer: the workspace sandbox, engagement identity,
 * certificate lifecycle, and preflight.
 *
 * The workspace tests carry the most weight. That surface is driven by a model
 * writing path strings, so "refuses to leave the folder" is not a nice property
 * — it is the whole reason the feature is allowed to exist.
 */

import { describe, expect, it, beforeEach, afterEach } from 'vitest';
import { promises as fs } from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import {
  listWorkspace,
  readWorkspaceFile,
  searchWorkspace,
  resolveInside,
} from '../../src/engine/workspace/workspace.js';
import {
  applyIdentity,
  checkIdentity,
  identityEnforced,
  requiredIdentityHeaders,
} from '../../src/engine/engagement/identity.js';
import { buildPreflight } from '../../src/engine/engagement/preflight.js';
import {
  defaultEngagementProfile,
  validateEngagementProfile,
  type EngagementProfile,
} from '../../src/shared/engagement.js';
import { CertificateAuthority } from '../../src/engine/ca/certificateAuthority.js';
import { InMemorySecretStore } from '../../src/engine/ca/secretStore.js';
import { emptyScope } from '../../src/shared/scope.js';
import type { HttpHeader } from '../../src/shared/model.js';

let root = '';
let outside = '';

beforeEach(async () => {
  // Resolved for the same reason as in huntFolderLayout.test.ts: macOS tmpdir is a symlink.
  const base = await fs.realpath(await fs.mkdtemp(path.join(os.tmpdir(), 'tacnoc-ws-')));
  root = path.join(base, 'engagement');
  outside = path.join(base, 'outside');
  await fs.mkdir(root, { recursive: true });
  await fs.mkdir(outside, { recursive: true });
  await fs.writeFile(path.join(outside, 'secret.txt'), 'DO NOT READ ME', 'utf8');

  await fs.writeFile(
    path.join(root, 'program-policy.md'),
    '# Acme Bounty\nIn scope: api.acme.test\nRequired User-Agent: greynoc-research\n',
    'utf8',
  );
  await fs.writeFile(path.join(root, 'notes.txt'), 'prior report: idor on /orders\n', 'utf8');
  // Project internals that live in the same folder and must never be served.
  await fs.writeFile(path.join(root, 'secrets.json'), '{"tls-ca-private-key":"nope"}', 'utf8');
  await fs.writeFile(path.join(root, 'belcher.db'), 'SQLite format 3\u0000', 'utf8');
  await fs.mkdir(path.join(root, 'blobs'), { recursive: true });
  await fs.writeFile(path.join(root, 'blobs', 'aa11.bin'), 'blobdata', 'utf8');
});

afterEach(async () => {
  await fs.rm(path.dirname(root), { recursive: true, force: true }).catch(() => undefined);
});

describe('workspace sandbox', () => {
  it('lists engagement documents and flags the notable ones', async () => {
    const listing = await listWorkspace(root);
    const paths = listing.entries.map((e) => e.path);
    expect(paths).toContain('program-policy.md');
    expect(paths).toContain('notes.txt');
    expect(listing.notableFiles).toContain('program-policy.md');
  });

  it('never lists the project’s own secrets, database, or blob store', async () => {
    const listing = await listWorkspace(root);
    const paths = listing.entries.map((e) => e.path);
    expect(paths).not.toContain('secrets.json');
    expect(paths).not.toContain('belcher.db');
    expect(paths.some((p) => p.startsWith('blobs'))).toBe(false);
  });

  it('refuses to read the project secret store even when named directly', async () => {
    await expect(readWorkspaceFile(root, 'secrets.json')).rejects.toThrow(/denied/i);
  });

  it('refuses parent-directory traversal', async () => {
    await expect(readWorkspaceFile(root, '../outside/secret.txt')).rejects.toThrow(/outside/i);
    await expect(readWorkspaceFile(root, '../../etc/passwd')).rejects.toThrow(/outside/i);
  });

  it('refuses an absolute path', async () => {
    await expect(readWorkspaceFile(root, path.join(outside, 'secret.txt'))).rejects.toThrow(
      /relative/i,
    );
    await expect(readWorkspaceFile(root, 'C:\\Windows\\win.ini')).rejects.toThrow(/relative/i);
  });

  it('refuses a backslash-separated traversal (Windows-style input)', async () => {
    await expect(readWorkspaceFile(root, '..\\outside\\secret.txt')).rejects.toThrow(/outside/i);
  });

  it('refuses a symlink that points out of the workspace', async () => {
    const link = path.join(root, 'escape.txt');
    try {
      await fs.symlink(path.join(outside, 'secret.txt'), link);
    } catch {
      return; // symlink creation needs privilege on Windows; skip rather than fail
    }
    await expect(readWorkspaceFile(root, 'escape.txt')).rejects.toThrow(/outside/i);
    const listing = await listWorkspace(root);
    expect(listing.entries.map((e) => e.path)).not.toContain('escape.txt');
  });

  it('reads a real document and reports truncation honestly', async () => {
    const file = await readWorkspaceFile(root, 'program-policy.md');
    expect(file.content).toContain('greynoc-research');
    expect(file.truncated).toBe(false);

    const short = await readWorkspaceFile(root, 'program-policy.md', 10);
    expect(short.truncated).toBe(true);
    expect(short.content.length).toBeLessThanOrEqual(10);
  });

  it('refuses binary content rather than returning mojibake', async () => {
    await fs.writeFile(path.join(root, 'blob.json'), Buffer.from([0x7b, 0x00, 0x01, 0x7d]));
    await expect(readWorkspaceFile(root, 'blob.json')).rejects.toThrow(/binary/i);
  });

  it('points the operator at a text export when handed a PDF policy', async () => {
    await fs.writeFile(path.join(root, 'policy.pdf'), '%PDF-1.7 fake', 'utf8');
    await expect(readWorkspaceFile(root, 'policy.pdf')).rejects.toThrow(/export the policy/i);
  });

  it('searches across documents and reports where the match is', async () => {
    const result = await searchWorkspace(root, 'api.acme.test');
    expect(result.matches.length).toBeGreaterThan(0);
    expect(result.matches[0]?.path).toBe('program-policy.md');
    expect(result.matches[0]?.line).toBeGreaterThan(0);
  });

  it('refuses a Windows 8.3 short name that aliases a denied file', async () => {
    // The denylist used to run on the caller's string only. On Windows the
    // short name `SECRET~1.JSO` sails past a check for `secrets.json` and
    // resolves to exactly that file — the sealed secret store, egressed to a
    // model provider. The denylist now re-runs on the RESOLVED path.
    let short = '';
    try {
      const { execFileSync } = await import('node:child_process');
      const out = execFileSync('cmd', ['/c', 'dir', '/x', '/b', 'secrets.json'], {
        cwd: root,
        encoding: 'utf8',
      });
      short = out.trim().split(/\s+/)[0] ?? '';
    } catch {
      return; // not Windows, or 8.3 generation disabled — nothing to assert
    }
    if (!short || short.toLowerCase() === 'secrets.json') return;
    await expect(readWorkspaceFile(root, short)).rejects.toThrow(/denied/i);
  });

  it('refuses a hard link that aliases a denied file', async () => {
    try {
      await fs.link(path.join(root, 'secrets.json'), path.join(root, 'inventory.json'));
    } catch {
      return; // hard links unavailable on this filesystem
    }
    // Same class as the 8.3 case: a different name for the same inode.
    await expect(readWorkspaceFile(root, 'inventory.json')).rejects.toThrow(/denied|another name/i);
  });

  it('refuses an NTFS alternate data stream', async () => {
    await expect(readWorkspaceFile(root, 'notes.txt:hidden.txt')).rejects.toThrow(/stream/i);
  });

  it('does not serve a different file when an intermediate directory is missing', async () => {
    // Resolving the deepest EXISTING ancestor returned <root>/notes.txt for a
    // path that does not exist, labelled with the requested path — real content
    // under fabricated provenance, in a tool whose output becomes evidence.
    await expect(readWorkspaceFile(root, 'no/such/dir/notes.txt')).rejects.toThrow(
      /does not exist|outside/i,
    );
  });

  it('keeps walking siblings when one branch is too deep', async () => {
    let deep = root;
    for (let i = 0; i < 10; i += 1) {
      deep = path.join(deep, `level${i}`);
      await fs.mkdir(deep, { recursive: true });
    }
    await fs.writeFile(path.join(root, 'zz-scope.md'), 'ONLY test-api.example.test', 'utf8');

    const listing = await listWorkspace(root);
    // An over-deep branch used to abort the whole walk, hiding every later
    // sibling — so the scope document went unread and the mesh answered
    // "is this in scope?" from an authoritative-looking empty listing.
    expect(listing.entries.map((e) => e.path)).toContain('zz-scope.md');
    expect(listing.truncated).toBe(true);

    const found = await searchWorkspace(root, 'test-api.example.test');
    expect(found.matches.length).toBeGreaterThan(0);
  });

  it('detects binary content past the first 8 KiB', async () => {
    const payload = Buffer.concat([Buffer.alloc(9000, 0x41), Buffer.from([0, 1, 2, 3])]);
    await fs.writeFile(path.join(root, 'sneaky.log'), payload);
    await expect(readWorkspaceFile(root, 'sneaky.log')).rejects.toThrow(/binary/i);
  });

  it('refuses a file containing private key material whatever its extension', async () => {
    await fs.writeFile(
      path.join(root, 'client.pem'),
      ['-----BEGIN RSA PRIVATE KEY-----', 'MIIEpAIBAAKCAQEA', '-----END RSA PRIVATE KEY-----'].join(
        '\n',
      ),
      'utf8',
    );
    // `.pem` is both the usual certificate extension and the usual private-key
    // one, so the refusal is by content rather than by name.
    await expect(readWorkspaceFile(root, 'client.pem')).rejects.toThrow(/private key/i);
  });

  it('resolveInside accepts a legitimate relative path', async () => {
    const resolved = await resolveInside(root, 'notes.txt');
    expect(resolved.endsWith('notes.txt')).toBe(true);
  });
});

describe('engagement identity', () => {
  const profile = (over: Partial<EngagementProfile> = {}): EngagementProfile => ({
    ...defaultEngagementProfile(),
    userAgent: { required: 'greynoc-research', enforce: true },
    identityHeaders: [{ name: 'X-Bug-Bounty', value: 'greynoc' }],
    ...over,
  });

  const headers = (...pairs: [string, string][]): HttpHeader[] =>
    pairs.map(([name, value]) => ({ name, value }));

  it('is a no-op when enforcement is off', () => {
    const original = headers(['Host', 'x.test'], ['User-Agent', 'curl/8']);
    const out = applyIdentity(original, profile({ userAgent: { required: 'ua', enforce: false } }));
    expect(out).toEqual(original);
  });

  it('replaces the User-Agent in place, keeping header order', () => {
    const out = applyIdentity(
      headers(['Host', 'x.test'], ['User-Agent', 'curl/8'], ['Accept', '*/*']),
      profile(),
    );
    expect(out.map((h) => h.name)).toEqual(['Host', 'User-Agent', 'Accept', 'X-Bug-Bounty']);
    expect(out[1]?.value).toBe('greynoc-research');
  });

  it('drops duplicate identifying headers so the target sees exactly one', () => {
    const out = applyIdentity(
      headers(['User-Agent', 'a'], ['User-Agent', 'b'], ['Host', 'x.test']),
      profile(),
    );
    expect(out.filter((h) => h.name.toLowerCase() === 'user-agent')).toHaveLength(1);
  });

  it('appends the identity headers when they are absent', () => {
    const out = applyIdentity(headers(['Host', 'x.test']), profile());
    expect(out.find((h) => h.name === 'X-Bug-Bounty')?.value).toBe('greynoc');
  });

  it('reports compliance against headers that were actually sent', () => {
    const compliant = checkIdentity(
      headers(['User-Agent', 'greynoc-research'], ['X-Bug-Bounty', 'greynoc']),
      profile(),
    );
    expect(compliant.compliant).toBe(true);

    const wrong = checkIdentity(headers(['User-Agent', 'curl/8']), profile());
    expect(wrong.compliant).toBe(false);
    expect(wrong.missing).toContain('User-Agent');
    expect(wrong.userAgent).toBe('curl/8');
  });

  it('refuses a CRLF in a header value — that is header injection, not config', () => {
    const problems = validateEngagementProfile(
      profile({ identityHeaders: [{ name: 'X-Bug-Bounty', value: 'a\r\nX-Admin: 1' }] }),
    );
    expect(problems.join(' ')).toMatch(/control character/i);
  });

  it('drops an invalid header at apply time even if it reached storage', () => {
    const dangerous = profile({ identityHeaders: [{ name: 'X-Evil', value: 'a\r\nX-Admin: 1' }] });
    expect(requiredIdentityHeaders(dangerous).map((h) => h.name)).not.toContain('X-Evil');
    const out = applyIdentity([{ name: 'Host', value: 'x.test' }], dangerous);
    expect(out.some((h) => h.value.includes('\r'))).toBe(false);
  });

  it('refuses a profile that would forge an engine-owned header', () => {
    const problems = validateEngagementProfile(
      profile({ identityHeaders: [{ name: 'Host', value: 'evil.test' }] }),
    );
    expect(problems.join(' ')).toMatch(/set by the engine/i);
  });

  it('treats enforcement with nothing to apply as a configuration error', () => {
    const problems = validateEngagementProfile({
      ...defaultEngagementProfile(),
      userAgent: { required: '', enforce: true },
    });
    expect(problems.join(' ')).toMatch(/nothing would be applied/i);
    expect(identityEnforced({ ...defaultEngagementProfile() })).toBe(false);
  });
});

describe('certificate lifecycle', () => {
  it('reports status, rotates to fresh material, and revokes interception', async () => {
    const dir = await fs.realpath(await fs.mkdtemp(path.join(os.tmpdir(), 'tacnoc-ca-')));
    const certPath = path.join(dir, 'ca.pem');
    const secrets = new InMemorySecretStore();
    const ca = await CertificateAuthority.loadOrCreate(certPath, secrets);

    const first = ca.status();
    expect(first?.fingerprint).toMatch(/^[0-9A-F:]+$/);
    expect(first?.expired).toBe(false);
    expect(ca.active).toBe(true);
    expect(ca.leafPemFor('example.test').cert).toContain('BEGIN CERTIFICATE');

    const generationBefore = ca.generation;
    const replaced = await ca.rotate('key exposure drill');
    expect(replaced?.action).toBe('rotate');
    expect(replaced?.fingerprint).toBe(first?.fingerprint);
    expect(ca.status()?.fingerprint).not.toBe(first?.fingerprint);
    expect(ca.generation).toBeGreaterThan(generationBefore);
    // The rotated CA is persisted, so a reopen sees the new material.
    expect(await fs.readFile(certPath, 'utf8')).toBe(ca.certificatePem);

    const revoked = await ca.revoke('testing an untrusted client');
    expect(revoked?.action).toBe('revoke');
    expect(ca.active).toBe(false);
    expect(ca.status()).toBeUndefined();
    expect(ca.revocation.reason).toBe('testing an untrusted client');
    // With no CA there is nothing to sign with — interception must fail loudly.
    expect(() => ca.leafPemFor('example.test')).toThrow(/revoked/i);
    await expect(fs.access(certPath)).rejects.toThrow();
    expect(await secrets.get('tls-ca-private-key')).toBeNull();

    // Issuing again restores interception.
    await ca.rotate('reissue after drill');
    expect(ca.active).toBe(true);
    expect(ca.leafPemFor('example.test').cert).toContain('BEGIN CERTIFICATE');

    await fs.rm(dir, { recursive: true, force: true });
  });
});

describe('preflight', () => {
  const baseInputs = () => ({
    project: {
      name: 'acme',
      directory: '/tmp/acme.tacnocproj',
      authorizationRef: 'https://program.test/acme',
      encryptedAtRest: true,
    },
    profile: {
      ...defaultEngagementProfile(),
      authorizationRef: 'https://program.test/acme',
      userAgent: { required: 'greynoc-research', enforce: true },
    },
    scope: {
      include: [
        {
          id: 'i1',
          enabled: true,
          hostMatch: 'exact' as const,
          host: 'api.acme.test',
          schemes: [],
          ports: [],
        },
      ],
      exclude: [],
    },
    ca: {
      certificate: {
        subject: 'CN=TACNOC Project CA',
        issuer: 'CN=TACNOC Project CA',
        serial: '00ab',
        fingerprint: 'AA:BB',
        notBefore: Date.now() - 1000,
        notAfter: Date.now() + 365 * 24 * 3600 * 1000,
        daysRemaining: 365,
        expired: false,
        expiringSoon: false,
      },
      interceptionEnabled: true,
      secureBackend: true,
      backendName: 'safeStorage',
      history: [],
      observedHttpsExchanges: 12,
      installInstructions: 'install it',
    },
    identity: {
      applicable: true,
      required: 'greynoc-research',
      enforced: true,
      sampled: 4,
      compliant: 4,
      observedUserAgents: ['greynoc-research'],
      missingHeaders: [],
    },
    proxy: { running: true, host: '127.0.0.1', port: 8080, loopbackOnly: true },
    workspace: {
      root: '/tmp/acme.tacnocproj',
      isProjectDir: true,
      fileCount: 3,
      totalBytes: 900,
      notableFiles: ['program-policy.md'],
    },
    history: { exchanges: 40, findings: 2 },
  });

  const ids = (report: ReturnType<typeof buildPreflight>, severity: string): string[] =>
    report.checks.filter((c) => c.severity === severity).map((c) => c.id);

  it('is ready when authorization, scope, certificate, and identity all hold', () => {
    const report = buildPreflight(baseInputs());
    expect(report.ready).toBe(true);
    expect(ids(report, 'blocker')).toHaveLength(0);
  });

  it('blocks when nothing records what authorizes the testing', () => {
    const inputs = baseInputs();
    inputs.project.authorizationRef = '';
    inputs.profile.authorizationRef = '';
    const report = buildPreflight(inputs);
    expect(report.ready).toBe(false);
    expect(ids(report, 'blocker')).toContain('authorization');
  });

  it('blocks on an empty scope, because every request would be refused', () => {
    const report = buildPreflight({ ...baseInputs(), scope: emptyScope() });
    expect(report.ready).toBe(false);
    expect(ids(report, 'blocker')).toContain('scope');
  });

  it('blocks on an expired CA — HTTPS capture would silently produce nothing', () => {
    const inputs = baseInputs();
    inputs.ca.certificate = {
      ...inputs.ca.certificate,
      notAfter: Date.now() - 1000,
      daysRemaining: -1,
      expired: true,
      expiringSoon: true,
    };
    const report = buildPreflight(inputs);
    expect(report.ready).toBe(false);
    expect(ids(report, 'blocker')).toContain('ca-expired');
  });

  it('blocks a non-loopback proxy bind', () => {
    const inputs = baseInputs();
    inputs.proxy = { running: true, host: '0.0.0.0', port: 8080, loopbackOnly: false };
    const report = buildPreflight(inputs);
    expect(report.ready).toBe(false);
    expect(ids(report, 'blocker')).toContain('proxy-bind');
  });

  it('warns when traffic exists but no HTTPS was ever decrypted', () => {
    const inputs = baseInputs();
    inputs.ca.observedHttpsExchanges = 0;
    const report = buildPreflight(inputs);
    expect(ids(report, 'warning')).toContain('ca-trust');
    expect(report.ready).toBe(true); // a warning, not a blocker
  });

  it('warns when a revoked CA means nothing encrypted is being captured', () => {
    const inputs = baseInputs();
    inputs.ca.interceptionEnabled = false;
    const report = buildPreflight(inputs);
    expect(ids(report, 'warning')).toContain('ca-revoked');
  });

  it('warns when sent traffic did not carry the required identity', () => {
    const inputs = baseInputs();
    inputs.identity = { ...inputs.identity, compliant: 1, observedUserAgents: ['curl/8'] };
    const report = buildPreflight(inputs);
    expect(ids(report, 'warning')).toContain('user-agent');
  });
});
