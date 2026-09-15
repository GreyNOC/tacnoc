/**
 * The hunt-folder layout, through the real Electron runtime.
 *
 * The layout that actually occurs puts the project inside the hunt folder, next
 * to the paperwork. Two failures came out of that and both presented as "the
 * scope gate is closed": picking the hunt folder failed with a raw
 * `ENOENT ... belcher.db`, and opening the project pointed the engagement folder
 * at a directory holding the database and no documents.
 *
 * This drives it over IPC in the shipping runtime rather than under Vitest,
 * because the folder chooser, the project open, and the preflight all cross the
 * main-process boundary and a headless engine test would not exercise that.
 *
 * OPT-IN: requires `npm run build` first. Run with: npm run test:e2e
 */

import { test, expect, _electron as electron } from '@playwright/test';
import * as path from 'node:path';
import * as os from 'node:os';
import { promises as fs } from 'node:fs';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

const ENGAGEMENT = [
  '# Acme Bounty — engagement',
  '',
  '## In scope',
  '- api.acme-corp.test',
  '',
  '## Out of scope',
  '- internal.acme-corp.test',
  '',
].join('\n');

test('a project nested in a hunt folder opens, and its scope is found', async () => {
  const huntPath = path.join(os.tmpdir(), `tacnoc-hunt-${Date.now()}`, 'AcmeCorp');
  await fs.mkdir(huntPath, { recursive: true });
  // `os.tmpdir()` on macOS is `/var/folders/…`, a symlink to `/private/var/folders/…`.
  // Every workspace path the engine reports has been through `fs.realpath`, so a
  // temp path compared to one of them must be resolved too — otherwise the two
  // name the same directory and differ as strings, on macOS and nowhere else.
  const hunt = await fs.realpath(huntPath);
  const projectDir = path.join(hunt, 'Acme.tacnocproj');
  await fs.writeFile(path.join(hunt, 'ENGAGEMENT.md'), ENGAGEMENT, 'utf8');

  const app = await electron.launch({ args: [path.join(root, 'out/main/index.js')] });
  try {
    const win = await app.firstWindow();
    await win.getByRole('button', { name: 'Create project' }).waitFor({ timeout: 20000 });

    const result = await win.evaluate(
      async ([huntDir, projDir]: string[]) => {
        const b = (
          window as unknown as {
            tacnoc: { invoke: (m: string, ...a: unknown[]) => Promise<unknown> };
          }
        ).tacnoc;
        const tryCall = async (method: string, ...args: unknown[]): Promise<string | null> => {
          try {
            await b.invoke(method, ...args);
            return null;
          } catch (e) {
            return e instanceof Error ? e.message : String(e);
          }
        };

        await b.invoke('createProject', projDir, 'acme');
        await b.invoke('closeProject');

        // The operator points the chooser at the hunt folder, not the project.
        const openErr = await tryCall('openProject', huntDir);
        const info = await b.invoke('getProjectInfo');

        // Preflight should name the parent as the place the material lives.
        const before = (await b.invoke('getPreflight')) as {
          workspace: { root: string; fileCount: number; suggestedRoot?: string };
        };

        // Take the suggestion, the way the button does.
        const profile = (await b.invoke('getEngagementProfile')) as Record<string, unknown>;
        await b.invoke('setEngagementProfile', {
          ...profile,
          workspaceDir: before.workspace.suggestedRoot,
        });

        const proposal = (await b.invoke('proposeScopeFromWorkspace')) as {
          filesRead: number;
          include: { host: string }[];
          exclude: { host: string }[];
        };
        return { openErr, info, before, proposal };
      },
      [hunt, projectDir],
    );

    // 1. Picking the hunt folder opens the project inside it.
    expect(result.openErr).toBeNull();
    expect((result.info as { name: string } | null)?.name).toBe('acme');

    // 2. The engagement folder starts empty, and preflight says where to look.
    expect(result.before.workspace.fileCount).toBe(0);
    expect(result.before.workspace.suggestedRoot).toBe(hunt);

    // 3. Taking the suggestion finds the scope that was in the folder all along.
    expect(result.proposal.filesRead).toBeGreaterThan(0);
    expect(result.proposal.include.map((c) => c.host)).toContain('api.acme-corp.test');
    expect(result.proposal.exclude.map((c) => c.host)).toContain('internal.acme-corp.test');
  } finally {
    await app.close();
    await fs.rm(path.dirname(hunt), { recursive: true, force: true }).catch(() => undefined);
  }
});

test('a folder that predates TACNOC is adopted, read, and ranked', async () => {
  // No project in this folder — only the material an operator already had.
  const huntPath = path.join(os.tmpdir(), `tacnoc-adopt-${Date.now()}`, 'AcmeCorp');
  await fs.mkdir(path.join(huntPath, 'recon'), { recursive: true });
  // `os.tmpdir()` on macOS is `/var/folders/…`, a symlink to `/private/var/folders/…`.
  // Every workspace path the engine reports has been through `fs.realpath`, so a
  // temp path compared to one of them must be resolved too — otherwise the two
  // name the same directory and differ as strings, on macOS and nowhere else.
  const hunt = await fs.realpath(huntPath);
  await fs.writeFile(path.join(hunt, 'ENGAGEMENT.md'), ENGAGEMENT, 'utf8');
  await fs.writeFile(
    path.join(hunt, 'recon', 'subdomains.txt'),
    Array.from({ length: 200 }, (_, i) => `host${i}.acme-corp.test`).join('\n'),
    'utf8',
  );

  const app = await electron.launch({ args: [path.join(root, 'out/main/index.js')] });
  try {
    const win = await app.firstWindow();
    await win.getByRole('button', { name: 'Create project' }).waitFor({ timeout: 20000 });

    const res = await win.evaluate(async (dir: string) => {
      const b = (
        window as unknown as {
          tacnoc: { invoke: (m: string, ...a: unknown[]) => Promise<unknown> };
        }
      ).tacnoc;
      const adopted = (await b.invoke('adoptHuntFolder', dir, 'Acme')) as {
        created: boolean;
        projectDirectory: string;
        scan: {
          filesSeen: number;
          filesRead: number;
          byKind: Record<string, number>;
          docs: { path: string; kind: string }[];
        };
      };
      const scope = (await b.invoke('getScope')) as { include: unknown[] };
      const proposal = (await b.invoke('proposeScopeFromWorkspace')) as {
        include: { host: string }[];
      };
      const pre = (await b.invoke('getPreflight')) as { workspace: { root: string } };
      return {
        adopted,
        scopeRules: scope.include.length,
        proposal,
        workspaceRoot: pre.workspace.root,
      };
    }, hunt);

    // The project is created inside the folder the operator picked...
    expect(res.adopted.created).toBe(true);
    expect(res.adopted.projectDirectory).toBe(path.join(hunt, 'Acme.tacnocproj'));
    // ...and the engagement folder is that folder, with no second step.
    expect(res.workspaceRoot).toBe(hunt);

    // The scope document outranks 200 lines of subdomains.
    expect(res.adopted.scan.docs[0]?.path).toBe('ENGAGEMENT.md');
    expect(res.adopted.scan.docs[0]?.kind).toBe('scope');
    expect(res.adopted.scan.filesRead).toBeGreaterThan(0);

    // Its hosts are PROPOSED...
    expect(res.proposal.include.map((c) => c.host)).toContain('api.acme-corp.test');
    // ...and nothing was authorized by reading a file. The gate stays closed.
    expect(res.scopeRules).toBe(0);
  } finally {
    await app.close();
    await fs.rm(path.dirname(hunt), { recursive: true, force: true }).catch(() => undefined);
  }
});
