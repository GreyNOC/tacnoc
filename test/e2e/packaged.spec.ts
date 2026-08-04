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
 * OPT-IN: skips unless a packaged app has been produced. Both `dist/` (the
 * default output) and `release/` are searched, because a build can be directed
 * elsewhere when `dist/` holds an artifact that is currently running.
 */

import { test, expect, _electron as electron } from '@playwright/test';
import * as path from 'node:path';
import * as os from 'node:os';
import { existsSync, promises as fs } from 'node:fs';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

/** The packaged executable for the host platform, if it was built. */
function packagedExe(): string | undefined {
  const relative = [
    'win-unpacked/TACNOC.exe',
    'linux-unpacked/greynoc-tacnoc',
    'mac/TACNOC.app/Contents/MacOS/TACNOC',
    'mac-arm64/TACNOC.app/Contents/MacOS/TACNOC',
  ];
  const outputs = [process.env.TACNOC_PACKAGE_DIR, 'dist', 'release'].filter(
    (d): d is string => !!d,
  );
  for (const out of outputs) {
    const hit = relative.map((r) => path.join(root, out, r)).find((p) => existsSync(p));
    if (hit) return hit;
  }
  return undefined;
}

const exe = packagedExe();

test.describe('packaged release artifact', () => {
  test.skip(!exe, 'no packaged app in dist/ or release/ — run `npm run dist:win` first');

  test('packaged app: WASM SQLite, CA, proxy, and the resources example extension all work', async () => {
    const projectDir = path.join(os.tmpdir(), `tacnoc-pkg-${Date.now()}`);
    const app = await electron.launch({ executablePath: exe! });
    try {
      const window = await app.firstWindow();
      await window.getByRole('button', { name: 'Create project' }).waitFor({ timeout: 30000 });

      const result = await window.evaluate(async (dir: string) => {
        const tacnoc = (
          window as unknown as {
            tacnoc: { invoke: (m: string, ...a: unknown[]) => Promise<unknown> };
          }
        ).tacnoc;
        // createProject exercises the WASM SQLite loaded from app.asar.unpacked
        // and the CA minted into OS secure storage.
        const info = await tacnoc.invoke('createProject', dir, 'pkg-proj');
        const ca = (await tacnoc.invoke('getCaInfo')) as { fingerprint: string };
        const status = (await tacnoc.invoke('startProxy', '127.0.0.1', 0)) as {
          running: boolean;
          loopbackOnly: boolean;
        };
        // Exercises the `app.isPackaged` resourcesPath branch AND forking the
        // extension host child process out of the packaged binary.
        const exts = (await tacnoc.invoke('loadExampleExtension')) as unknown[];
        const transforms = (await tacnoc.invoke('listTransforms')) as { id: string }[];
        const rot13 = await tacnoc.invoke('applyTransform', 'ext.header-hygiene.rot13', 'Hello');
        await tacnoc.invoke('stopProxy');
        await tacnoc.invoke('closeProject');
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
