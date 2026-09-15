/**
 * Opening a hunt folder, and finding the scope that is in it.
 *
 * The layout that actually occurs in practice puts the project INSIDE the hunt
 * folder, next to the paperwork:
 *
 *   TiffanyCo/
 *     ENGAGEMENT.md, SURFACE.md, _notes.md    <- where the scope is written down
 *     Tiffany.tacnocproj/                     <- the project
 *
 * Two failures came out of that, and both looked like the scope gate refusing
 * to open when it was nothing of the sort:
 *
 *  1. Picking `TiffanyCo` in the folder chooser failed with a raw
 *     `ENOENT ... belcher.db` — an internal filename, and nothing to act on.
 *  2. Opening the project succeeded, but the engagement folder defaulted to the
 *     project directory, which holds the database and no documents. The scope
 *     reader then correctly reported "nothing to read" about a folder that was
 *     never where the operator put anything.
 *
 * These tests drive the real session through that layout.
 */

import { describe, expect, it, beforeEach, afterEach } from 'vitest';
import { promises as fs } from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { TacnocSession } from '../../src/engine/session.js';
import { InMemorySecretStore } from '../../src/engine/ca/secretStore.js';
import { resolveProjectDir } from '../../src/engine/project/projectStore.js';
import { scopeRulesFromProposal } from '../../src/engine/engagement/scopeProposal.js';

let root = '';
let hunt = '';
let projectDir = '';
let session: TacnocSession;

const ENGAGEMENT = `# Acme Bounty — engagement

## In scope
- api.acme-corp.test
- *.dev.acme-corp.test

## Out of scope
- internal.acme-corp.test
`;

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
  root = await fs.realpath(await fs.mkdtemp(path.join(os.tmpdir(), 'tacnoc-layout-')));
  hunt = path.join(root, 'AcmeCorp');
  projectDir = path.join(hunt, 'Acme.tacnocproj');
  await fs.mkdir(hunt, { recursive: true });
  await fs.writeFile(path.join(hunt, 'ENGAGEMENT.md'), ENGAGEMENT, 'utf8');
  await fs.writeFile(path.join(hunt, '_notes.md'), 'Tested login on api.acme-corp.test.', 'utf8');
  session = newSession();
  await session.createProject(projectDir, 'acme', 'https://program.test/acme');
});

afterEach(async () => {
  await session.dispose();
  await fs.rm(root, { recursive: true, force: true }).catch(() => undefined);
});

describe('picking the hunt folder instead of the project', () => {
  it('resolves the project nested one level down', async () => {
    await expect(resolveProjectDir(hunt)).resolves.toBe(projectDir);
  });

  it('returns a project directory unchanged', async () => {
    await expect(resolveProjectDir(projectDir)).resolves.toBe(projectDir);
  });

  it('opens through the session, so the folder chooser can point at either', async () => {
    await session.dispose();
    session = newSession();
    await session.openProject(hunt);
    expect(session.getProjectInfo()?.name).toBe('acme');
  });

  it('names every candidate rather than guessing when a folder holds several', async () => {
    const second = new TacnocSession({
      secretStoreFactory: () => new InMemorySecretStore(),
      aiSecretStore: new InMemorySecretStore(),
    });
    await second.createProject(path.join(hunt, 'Acme-Old.tacnocproj'), 'acme-old');
    await second.dispose();
    await expect(resolveProjectDir(hunt)).rejects.toThrow(/Acme-Old\.tacnocproj/);
    await expect(resolveProjectDir(hunt)).rejects.toThrow(/Acme\.tacnocproj/);
  });

  it('says what is wrong, without naming an internal file, when there is no project', async () => {
    const empty = path.join(root, 'Empty');
    await fs.mkdir(empty);
    await expect(resolveProjectDir(empty)).rejects.toThrow(/not a TACNOC project/);
    await expect(resolveProjectDir(empty)).rejects.not.toThrow(/belcher\.db/);
  });
});

describe('finding the engagement material when the project is nested in it', () => {
  it('reports the parent folder when the project directory has nothing to read', async () => {
    const report = await session.getPreflight();
    expect(report.workspace.root).toBe(projectDir);
    expect(report.workspace.fileCount).toBe(0);
    expect(report.workspace.suggestedRoot).toBe(hunt);
    expect(report.workspace.suggestedFileCount).toBeGreaterThanOrEqual(2);
  });

  it('does not count the project CA as an engagement document', async () => {
    // ca.pem sits in every project directory. Counting it made an empty project
    // folder report "1 document(s)" and suppressed the hint above.
    await expect(fs.access(path.join(projectDir, 'ca.pem'))).resolves.toBeUndefined();
    const listing = await session.listWorkspace();
    expect(listing.entries.some((e) => e.path === 'ca.pem')).toBe(false);
  });

  it('names the parent in preflight, with what switching to it would expose', async () => {
    const report = await session.getPreflight();
    const check = report.checks.find((c) => c.id === 'workspace');
    expect(check?.severity).toBe('warning');
    expect(check?.detail).toContain(hunt);
    expect(check?.remedy).toMatch(/sent to the model provider/i);
  });

  it('stays quiet once the operator has chosen a folder', async () => {
    await session.setEngagementProfile({
      ...session.getEngagementProfile(),
      workspaceDir: hunt,
    });
    const report = await session.getPreflight();
    expect(report.workspace.suggestedRoot).toBeUndefined();
  });

  it('finds the scope once the folder points at the material', async () => {
    // Before: the project directory, which holds no documents.
    const before = await session.proposeScopeFromWorkspace();
    expect(before.filesRead).toBe(0);
    expect(before.include).toEqual([]);

    await session.setEngagementProfile({
      ...session.getEngagementProfile(),
      workspaceDir: hunt,
    });

    const after = await session.proposeScopeFromWorkspace();
    expect(after.filesRead).toBeGreaterThan(0);
    expect(after.include.map((c) => c.host)).toContain('api.acme-corp.test');
    expect(after.exclude.map((c) => c.host)).toContain('internal.acme-corp.test');

    // And a ticked proposal becomes a rule the gate actually enforces.
    const rules = scopeRulesFromProposal(
      after,
      ['api.acme-corp.test', 'internal.acme-corp.test'],
      session.getScope(),
    );
    session.setScope({
      include: rules.include as never,
      exclude: rules.exclude as never,
    });
    const scope = session.getScope();
    expect(scope.include.map((r) => r.host)).toContain('api.acme-corp.test');
    expect(scope.exclude.map((r) => r.host)).toContain('internal.acme-corp.test');
  });
});
