/**
 * Evidence bundles and the agent handoff, through the REAL Electron app.
 *
 * The engine tests cover what a bundle contains. This covers the things only
 * the shipping runtime can answer: that the four new IPC methods are reachable
 * across the contextBridge at all (the startup parity gate refuses to open the
 * window otherwise), that the handoff survives the IPC serialisation boundary
 * with its authorization block intact, and — the part that matters — that
 * handing a target to the mesh is still refused by the same gates a manual run
 * faces.
 *
 * The two export methods open a save dialog, which Playwright cannot dismiss,
 * so they are exercised by the engine suite. `previewTargetHandoff` needs no
 * dialog and reaches the same builder.
 *
 * OPT-IN: requires `npm run build` first and a display. Run: npm run test:e2e
 */

import { test, expect, _electron as electron } from '@playwright/test';
import * as path from 'node:path';
import * as os from 'node:os';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const MAIN = path.join(root, 'out/main/index.js');

type Bridge = { invoke: (m: string, ...a: unknown[]) => Promise<unknown> };

test('the handoff crosses IPC intact, and handing off still obeys the scope gate', async () => {
  const stamp = Date.now();
  const userDataDir = path.join(os.tmpdir(), `tacnoc-eh-${stamp}`);
  const projectDir = path.join(os.tmpdir(), `tacnoc-eh-proj-${stamp}`);
  const app = await electron.launch({ args: [MAIN, `--user-data-dir=${userDataDir}`] });

  try {
    const win = await app.firstWindow();
    await win.getByRole('button', { name: 'Create project' }).waitFor({ timeout: 20000 });

    const result = await win.evaluate(async (dir: string) => {
      const b = (window as unknown as { tacnoc: Bridge }).tacnoc;
      const fail = async (method: string, ...args: unknown[]): Promise<string | null> => {
        try {
          await b.invoke(method, ...args);
          return null;
        } catch (e) {
          return e instanceof Error ? e.message : String(e);
        }
      };

      await b.invoke('createProject', dir, 'evidence');

      // Scope is empty on a fresh project: the gate is fail-closed.
      const emptyScopeHandoff = (await b.invoke('previewTargetHandoff', 'api.acme-corp.test')) as {
        authorization: { failClosed: boolean; targetInScope: boolean };
        constraints: string[];
        suggestedObjective: string;
        tool: { name: string };
        schemaVersion: number;
      };
      const refusedWhileClosed = await fail('handoffTargetToMesh', 'api.acme-corp.test');

      // Put one host in scope; a DIFFERENT host must still be refused.
      await b.invoke('setScope', {
        include: [
          {
            id: 'r1',
            enabled: true,
            hostMatch: 'exact',
            host: 'api.acme-corp.test',
            schemes: [],
            ports: [],
          },
        ],
        exclude: [],
      });
      const inScopeHandoff = (await b.invoke('previewTargetHandoff', 'api.acme-corp.test')) as {
        authorization: { failClosed: boolean; targetInScope: boolean; inScope: string[] };
        constraints: string[];
      };
      const outOfScopeHandoff = (await b.invoke('previewTargetHandoff', 'other.example.test')) as {
        authorization: { targetInScope: boolean };
        constraints: string[];
      };
      const refusedOutOfScope = await fail('handoffTargetToMesh', 'other.example.test');
      // In scope, but the mesh still needs a key and acknowledged egress.
      const refusedInScope = await fail('handoffTargetToMesh', 'api.acme-corp.test');

      return {
        emptyScopeHandoff,
        refusedWhileClosed,
        inScopeHandoff,
        outOfScopeHandoff,
        refusedOutOfScope,
        refusedInScope,
      };
    }, projectDir);

    // 1. The handoff survives IPC with its shape intact.
    expect(result.emptyScopeHandoff.schemaVersion).toBe(1);
    expect(result.emptyScopeHandoff.tool.name).toBe('TACNOC');

    // 2. Fail-closed scope is reported, and leads the constraints.
    expect(result.emptyScopeHandoff.authorization.failClosed).toBe(true);
    expect(result.emptyScopeHandoff.constraints[0]).toContain('STOP CONDITION');
    expect(result.emptyScopeHandoff.suggestedObjective).toContain('Do not test');

    // 3. Handing off with no scope is refused — the handoff is not a bypass.
    expect(result.refusedWhileClosed).toBeTruthy();

    // 4. With the host in scope, the handoff says so and drops the stop condition.
    expect(result.inScopeHandoff.authorization.failClosed).toBe(false);
    expect(result.inScopeHandoff.authorization.targetInScope).toBe(true);
    expect(result.inScopeHandoff.authorization.inScope).toContain('exact: api.acme-corp.test');
    expect(result.inScopeHandoff.constraints[0]).not.toContain('STOP CONDITION');

    // 5. A different host is still out of scope, and still refused.
    expect(result.outOfScopeHandoff.authorization.targetInScope).toBe(false);
    expect(result.outOfScopeHandoff.constraints[0]).toContain('STOP CONDITION');
    expect(result.refusedOutOfScope).toContain('not in scope');

    // 6. Even in scope, the mesh's own gates still apply — no key is configured
    //    here, so this must refuse rather than start a run.
    expect(result.refusedInScope).toBeTruthy();
  } finally {
    await app.close();
  }
});
