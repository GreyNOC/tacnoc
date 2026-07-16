/**
 * Playwright RELEASE-ARTIFACT verification — drives the actual PACKAGED app
 * (dist/win-unpacked/...), not the dev `out/main/index.js` bundle.
 *
 * Why this exists separately from smoke/full specs: several code paths only ever
 * execute in a packaged build and are invisible to the dev-bundle E2E run —
 *   - node-sqlite3-wasm's .wasm resolved from `app.asar.unpacked` (asarUnpack),
 *   - the example extension resolved from `process.resourcesPath` (extraResources,
 *     the `app.isPackaged` branch in src/main/ipc.ts),
 *   - forking the extension host child out of a packaged Electron binary
 *     (ELECTRON_RUN_AS_NODE against app.asar.unpacked).
 * A green dev-bundle suite says nothing about any of them.
 *
 * OPT-IN: skips unless `npm run dist` has produced the packaged app.
 */

import { test, expect, _electron as electron } from '@playwright/test';
import * as path from 'node:path';
import * as os from 'node:os';
import { existsSync, promises as fs } from 'node:fs';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

/** The packaged executable for the host platform, if it was built. */
function packagedExe(): string | undefined {
  const candidates = [
    path.join(root, 'dist/win-unpacked/GreyNOC Belcher.exe'),
    path.join(root, 'dist/linux-unpacked/greynoc-belcher'),
    path.join(root, 'dist/mac/GreyNOC Belcher.app/Contents/MacOS/GreyNOC Belcher'),
    path.join(root, 'dist/mac-arm64/GreyNOC Belcher.app/Contents/MacOS/GreyNOC Belcher'),
  ];
  return candidates.find((p) => existsSync(p));
}

const exe = packagedExe();

test.describe('packaged release artifact', () => {
  test.skip(!exe, 'no packaged app in dist/ — run `npm run dist` first');

  test('packaged app: WASM SQLite, CA, proxy, and the resources example extension all work', async () => {
    const projectDir = path.join(os.tmpdir(), `belcher-pkg-${Date.now()}`);
    const app = await electron.launch({ executablePath: exe! });
    try {
      const window = await app.firstWindow();
      await window.getByRole('button', { name: 'Create project' }).waitFor({ timeout: 30000 });

      const result = await window.evaluate(async (dir: string) => {
        const belcher = (
          window as unknown as {
            belcher: { invoke: (m: string, ...a: unknown[]) => Promise<unknown> };
          }
        ).belcher;
        // createProject exercises the WASM SQLite loaded from app.asar.unpacked
        // and the CA minted into OS secure storage.
        const info = await belcher.invoke('createProject', dir, 'pkg-proj');
        const ca = (await belcher.invoke('getCaInfo')) as { fingerprint: string };
        const status = (await belcher.invoke('startProxy', '127.0.0.1', 0)) as {
          running: boolean;
          loopbackOnly: boolean;
        };
        // Exercises the `app.isPackaged` resourcesPath branch AND forking the
        // extension host child process out of the packaged binary.
        const exts = (await belcher.invoke('loadExampleExtension')) as unknown[];
        const transforms = (await belcher.invoke('listTransforms')) as { id: string }[];
        const rot13 = await belcher.invoke('applyTransform', 'ext.header-hygiene.rot13', 'Hello');
        await belcher.invoke('stopProxy');
        await belcher.invoke('closeProject');
        return {
          info,
          fingerprint: ca.fingerprint,
          status,
          extCount: exts.length,
          transforms,
          rot13,
        };
      }, projectDir);

      expect(result.info).toBeTruthy(); // SQLite WASM really loaded from the asar.unpacked path
      expect(result.fingerprint).toMatch(/^([0-9A-F]{2}:){31}[0-9A-F]{2}$/);
      expect(result.status.running).toBe(true);
      expect(result.status.loopbackOnly).toBe(true); // safety default survives packaging
      expect(result.extCount).toBe(1); // example extension found under resourcesPath
      // Round-trip through the forked extension child process in a packaged build.
      expect(result.transforms.some((t) => t.id === 'ext.header-hygiene.rot13')).toBe(true);
      expect(result.rot13).toBe('Uryyb');
    } finally {
      await app.close();
      await fs.rm(projectDir, { recursive: true, force: true });
    }
  });
});
