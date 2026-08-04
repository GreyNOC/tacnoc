/**
 * AI mesh — real Electron runtime smoke test. Proves the shipping app boots with
 * the new IPC methods (the parity gate accepts them, or the window never opens),
 * the app-level key store works, all three start-guards fire, and the view
 * renders. Uses an isolated --user-data-dir so it never touches a real stored
 * key, and never makes a network call (every guard throws before the provider).
 */

import { test, expect, _electron as electron } from '@playwright/test';
import * as path from 'node:path';
import * as os from 'node:os';
import { promises as fs } from 'node:fs';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const MAIN = path.join(root, 'out/main/index.js');

test('ai mesh boots, key management + guards work, view renders', async () => {
  const userDataDir = path.join(os.tmpdir(), `tacnoc-ai-e2e-${Date.now()}`);
  const projectDir = path.join(os.tmpdir(), `tacnoc-ai-proj-${Date.now()}`);
  const app = await electron.launch({ args: [MAIN, `--user-data-dir=${userDataDir}`] });
  const win = await app.firstWindow();
  await win.getByRole('button', { name: 'Create project' }).waitFor({ timeout: 20000 });

  const result = await win.evaluate(async (dir: string) => {
    const b = (
      window as unknown as { tacnoc: { invoke: (m: string, ...a: unknown[]) => Promise<unknown> } }
    ).tacnoc;
    const tryCall = async (method: string, ...args: unknown[]): Promise<string | null> => {
      try {
        await b.invoke(method, ...args);
        return null;
      } catch (e) {
        return e instanceof Error ? e.message : String(e);
      }
    };

    await b.invoke('createProject', dir, 'ai-e2e');
    const cfg0 = await b.invoke('getAiConfig');
    const key0 = await b.invoke('getAiKeyStatus');

    // A test-only placeholder string (not a real credential) into the isolated store.
    await b.invoke('setAiApiKey', 'sk-ant-smoke-not-a-real-key');
    const key1 = await b.invoke('getAiKeyStatus');

    // Default config has enabled=false → disabled guard.
    const disabledErr = await tryCall('startMeshRun', { objective: 'smoke' });

    const cfg = (await b.invoke('getAiConfig')) as Record<string, unknown>;
    await b.invoke('setAiConfig', { ...cfg, enabled: true, egressAcknowledged: false });
    const egressErr = await tryCall('startMeshRun', { objective: 'smoke' });

    await b.invoke('setAiConfig', { ...cfg, enabled: true, egressAcknowledged: true });
    const scopeErr = await tryCall('startMeshRun', { objective: 'smoke' });

    await b.invoke('clearAiApiKey');
    const key2 = await b.invoke('getAiKeyStatus');
    return { cfg0, key0, key1, disabledErr, egressErr, scopeErr, key2 };
  }, projectDir);

  const cfg0 = result.cfg0 as {
    enabled: boolean;
    egressAcknowledged: boolean;
    roles: Record<string, { model: string }>;
  };
  expect(cfg0.enabled).toBe(false);
  expect(cfg0.egressAcknowledged).toBe(false);
  expect(cfg0.roles.planner?.model).toBe('claude-opus-4-8');
  expect(cfg0.roles.analyst?.model).toBe('claude-haiku-4-5');
  expect((result.key0 as { configured: boolean }).configured).toBe(false);
  expect((result.key1 as { configured: boolean }).configured).toBe(true);
  expect(result.disabledErr).toMatch(/disabled/i);
  expect(result.egressErr).toMatch(/egress/i);
  expect(result.scopeErr).toMatch(/scope is empty/i);
  expect((result.key2 as { configured: boolean }).configured).toBe(false);

  // The view renders and is reachable from the nav.
  await win.getByRole('button', { name: 'AI Mesh' }).click();
  await expect(win.getByRole('heading', { name: 'Anthropic API key' })).toBeVisible();
  await expect(win.getByRole('heading', { name: 'Mesh settings' })).toBeVisible();
  await expect(win.getByRole('button', { name: 'Start mesh ▶' })).toBeVisible();

  await app.close();
  await fs.rm(userDataDir, { recursive: true, force: true }).catch(() => undefined);
  await fs.rm(projectDir, { recursive: true, force: true }).catch(() => undefined);
});
