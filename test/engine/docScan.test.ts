/**
 * Adopting a folder that existed before TACNOC did, and finding what matters in
 * it.
 *
 * Real hunt folders are mostly enumeration output — a few hundred lines of
 * subdomains for every one file that says what may be touched. The value of the
 * scan is not "342 documents"; it is putting the six that decide scope at the
 * top and saying why.
 */

import { describe, expect, it, beforeEach, afterEach } from 'vitest';
import { promises as fs } from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { TacnocSession } from '../../src/engine/session.js';
import { InMemorySecretStore } from '../../src/engine/ca/secretStore.js';
import { classifyDocument, nameRank } from '../../src/engine/engagement/docScan.js';

let root = '';
let hunt = '';
let session: TacnocSession;

const POLICY = [
  '# Acme Bounty — program policy',
  '',
  '## In scope',
  '- api.acme-corp.test',
  '- *.dev.acme-corp.test',
  '',
  '## Out of scope',
  '- internal.acme-corp.test',
  '',
  'Rules of engagement: identify your traffic with a User-Agent of GNBB-research.',
  'Do not test the payment provider.',
].join('\n');

const REPORT = [
  '# F01 — reflected XSS in the preference centre',
  '',
  'Severity: medium. Steps to reproduce:',
  '1. GET /preference?country=<payload>',
  '',
  'Outcome: triaged, accepted.',
].join('\n');

const NOTES = 'Tried the login flow on 2026-07-20. Nothing on the password reset yet.';

/** 200 hostnames — the shape of real amass output. */
const SUBS = Array.from({ length: 200 }, (_, i) => `host${i}.acme-corp.test`).join('\n');

const newSession = (): TacnocSession =>
  new TacnocSession({
    secretStoreFactory: () => new InMemorySecretStore(),
    aiSecretStore: new InMemorySecretStore(),
  });

beforeEach(async () => {
  // `os.tmpdir()` on macOS is `/var/folders/…`, a symlink to `/private/var/folders/…`.
  // Every workspace path the engine reports has been through `fs.realpath`, so a
  // temp path compared to one of them must be resolved too — otherwise the two
  // name the same directory and differ as strings, on macOS and nowhere else.
  root = await fs.realpath(await fs.mkdtemp(path.join(os.tmpdir(), 'tacnoc-adopt-')));
  hunt = path.join(root, 'AcmeCorp');
  await fs.mkdir(path.join(hunt, 'recon'), { recursive: true });
  await fs.mkdir(path.join(hunt, 'findings'), { recursive: true });
  await fs.writeFile(path.join(hunt, 'ENGAGEMENT.md'), POLICY, 'utf8');
  await fs.writeFile(path.join(hunt, '_notes.md'), NOTES, 'utf8');
  await fs.writeFile(path.join(hunt, 'findings', 'F01-report.md'), REPORT, 'utf8');
  await fs.writeFile(path.join(hunt, 'recon', 'subdomains.txt'), SUBS, 'utf8');
  session = newSession();
});

afterEach(async () => {
  await session.dispose();
  await fs.rm(root, { recursive: true, force: true }).catch(() => undefined);
});

describe('classifying a document', () => {
  it('reads content over filename — scope in a README is still scope', () => {
    const doc = classifyDocument('README.md', POLICY, POLICY.length);
    expect(doc.kind).toBe('scope');
    expect(doc.reasons.join(' ')).toMatch(/OUT of scope/i);
  });

  it('calls a host dump recon however it is named', () => {
    const doc = classifyDocument('assets.md', SUBS, SUBS.length);
    expect(doc.kind).toBe('recon');
    expect(doc.reasons.join(' ')).toMatch(/hostnames/);
  });

  it('does not mistake a policy that mentions hosts for a host dump', () => {
    // Density, not count: a policy naturally names its assets.
    expect(classifyDocument('ENGAGEMENT.md', POLICY, POLICY.length).kind).toBe('scope');
  });

  it('recognises a prior report', () => {
    expect(classifyDocument('findings/F01-report.md', REPORT, REPORT.length).kind).toBe('report');
  });

  it('says so plainly when nothing matched', () => {
    const doc = classifyDocument('vendor/chunk.js', 'export const a = 1;', 19);
    expect(doc.kind).toBe('other');
    expect(doc.reasons).toEqual(['no hunting-relevant signal']);
  });

  it('marks a document judged on its filename alone', () => {
    expect(classifyDocument('scope.pdf', undefined, 100).nameOnly).toBe(true);
    expect(classifyDocument('scope.md', 'x', 1).nameOnly).toBe(false);
  });

  it('ranks a top-level brief above the same name buried in tool output', () => {
    expect(nameRank('ENGAGEMENT.md').score).toBeGreaterThan(
      nameRank('recon/old/2024/archive/ENGAGEMENT.md').score,
    );
  });
});

describe('adopting a hunt folder that has no project in it', () => {
  it('creates the project inside the folder and points the workspace at it', async () => {
    const res = await session.adoptHuntFolder(hunt, { name: 'Acme' });

    expect(res.created).toBe(true);
    expect(res.projectDirectory).toBe(path.join(hunt, 'Acme.tacnocproj'));
    expect(session.getProjectInfo()?.name).toBe('Acme');
    // The folder the operator picked is the engagement folder — no second step.
    expect(session.workspaceRoot()).toBe(hunt);
  });

  it('finds the scope immediately, with no manual re-pointing', async () => {
    await session.adoptHuntFolder(hunt, { name: 'Acme' });
    const proposal = await session.proposeScopeFromWorkspace();
    expect(proposal.include.map((c) => c.host)).toContain('api.acme-corp.test');
    expect(proposal.exclude.map((c) => c.host)).toContain('internal.acme-corp.test');
  });

  it('ranks the scope document above the recon dump', async () => {
    const res = await session.adoptHuntFolder(hunt, { name: 'Acme' });
    expect(res.scan.docs[0]?.path).toBe('ENGAGEMENT.md');
    expect(res.scan.docs[0]?.kind).toBe('scope');
    expect(res.scan.byKind.scope).toBeGreaterThanOrEqual(1);
    expect(res.scan.byKind.recon).toBeGreaterThanOrEqual(1);
    expect(res.scan.filesRead).toBeGreaterThan(0);
  });

  it('never puts anything in scope by itself — the gate stays closed', async () => {
    await session.adoptHuntFolder(hunt, { name: 'Acme' });
    // Reading a policy is not the same as being authorized by it.
    expect(session.getScope().include).toEqual([]);
  });

  it('records the adoption, including what the folder exposed', async () => {
    await session.adoptHuntFolder(hunt, { name: 'Acme' });
    const audit = session.listAudit(50);
    const entry = audit.find((e) => e.action === 'project.adopted-folder');
    expect(entry).toBeDefined();
    expect(entry?.detail?.engagementFolder).toBe(hunt);
    expect(Number(entry?.detail?.documentsRead)).toBeGreaterThan(0);
  });

  it('opens the existing project when the folder already has one', async () => {
    await session.adoptHuntFolder(hunt, { name: 'Acme' });
    await session.dispose();

    session = newSession();
    const again = await session.adoptHuntFolder(hunt);
    expect(again.created).toBe(false);
    expect(again.projectDirectory).toBe(path.join(hunt, 'Acme.tacnocproj'));
    expect(session.getProjectInfo()?.name).toBe('Acme');
  });

  it('will not let a project name climb out of the chosen folder', async () => {
    const res = await session.adoptHuntFolder(hunt, { name: '../../escaped' });
    // The separators are gone, so the name cannot address anything above the
    // folder the operator picked: it is one directory sitting directly inside it.
    expect(path.dirname(res.projectDirectory)).toBe(hunt);
    expect(path.resolve(res.projectDirectory)).toBe(
      path.join(hunt, path.basename(res.projectDirectory)),
    );
    // Note the name it lands on is `..-..-escaped.tacnocproj` — leading dots are
    // harmless in a filename, and a `startsWith('..')` containment check would
    // wrongly flag it. Containment is a path question, not a string one.
    const rel = path.relative(hunt, res.projectDirectory);
    expect(rel === '..' || rel.startsWith(`..${path.sep}`)).toBe(false);
    expect(rel.includes(path.sep)).toBe(false);
  });

  it('reports files it could not read rather than quietly shortening the list', async () => {
    await fs.writeFile(path.join(hunt, 'capture.bin'), Buffer.from([0, 1, 2, 3, 0]));
    const res = await session.adoptHuntFolder(hunt, { name: 'Acme' });
    const bin = res.scan.docs.find((d) => d.path === 'capture.bin');
    expect(bin?.nameOnly).toBe(true);
    expect(res.scan.filesSeen).toBeGreaterThan(res.scan.filesRead);
    expect(res.scan.notes.join(' ')).toMatch(/classified by filename only/i);
  });
});
