/**
 * Playwright smoke test — launches the built Electron app and checks the
 * welcome screen renders and the engine bridge is exposed.
 *
 * OPT-IN: requires `npm run build` first and a display. Not part of the headless
 * Vitest suite. Run with: npm run test:e2e
 */

import { test, expect, _electron as electron } from '@playwright/test';
import * as path from 'node:path';
import * as os from 'node:os';
import { promises as fs } from 'node:fs';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

test('app boots to the welcome screen and exposes the bridge', async () => {
  const app = await electron.launch({ args: [path.join(root, 'out/main/index.js')] });
  try {
    const window = await app.firstWindow();
    // "Create project" is a unique welcome-screen target ("GreyNOC Belcher"
    // appears in both the brand and the welcome heading, which trips strict mode).
    await expect(window.getByRole('button', { name: 'Create project' })).toBeVisible({
      timeout: 15000,
    });
    await expect(window.locator('.brand')).toContainText('GreyNOC Belcher');

    // The preload bridge must be present and callable.
    const hasBridge = await window.evaluate(
      () => typeof (window as unknown as { belcher?: unknown }).belcher,
    );
    expect(hasBridge).toBe('object');
  } finally {
    await app.close();
  }
});

test('real Electron runtime: create project, CA, and loopback proxy via the bridge', async () => {
  const projectDir = path.join(os.tmpdir(), `belcher-e2e-${Date.now()}`);
  const app = await electron.launch({ args: [path.join(root, 'out/main/index.js')] });
  try {
    const window = await app.firstWindow();
    await window.getByRole('button', { name: 'Create project' }).waitFor({ timeout: 15000 });

    // Drive the real main-process pipeline (WASM SQLite + safeStorage CA) via IPC,
    // bypassing only the native folder-picker dialog.
    const result = await window.evaluate(async (dir: string) => {
      const belcher = (
        window as unknown as {
          belcher: { invoke: (m: string, ...a: unknown[]) => Promise<unknown> };
        }
      ).belcher;
      const info = await belcher.invoke('createProject', dir, 'e2e-proj');
      const ca = (await belcher.invoke('getCaInfo')) as { fingerprint: string };
      const status = (await belcher.invoke('startProxy', '127.0.0.1', 0)) as {
        running: boolean;
        loopbackOnly: boolean;
        port?: number;
      };
      const count = (await belcher.invoke('historyCount')) as number;
      await belcher.invoke('stopProxy');
      await belcher.invoke('closeProject');
      return { info, fingerprint: ca.fingerprint, status, count };
    }, projectDir);

    expect(result.info).toBeTruthy();
    expect(result.fingerprint).toMatch(/^([0-9A-F]{2}:){31}[0-9A-F]{2}$/);
    expect(result.status.running).toBe(true);
    expect(result.status.loopbackOnly).toBe(true);
    expect(result.count).toBe(0);
  } finally {
    await app.close();
    await fs.rm(projectDir, { recursive: true, force: true });
  }
});
