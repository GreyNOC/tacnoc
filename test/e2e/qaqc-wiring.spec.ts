/**
 * Wiring regressions — driven through the REAL Electron app, because both of
 * these were invisible to the engine tests. Each one is a control that looked
 * like it worked from the operator's chair while doing something else.
 *
 * OPT-IN: requires `npm run build` first and a display. Run: npm run test:e2e
 */

import { test, expect, _electron as electron, type Page } from '@playwright/test';
import * as path from 'node:path';
import * as os from 'node:os';
import { promises as fs } from 'node:fs';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const MAIN = path.join(root, 'out/main/index.js');

type Bridge = { invoke: (m: string, ...a: unknown[]) => Promise<unknown> };

/** Renderer-side unhandled rejections — where a silently failing button lands. */
async function trackRejections(win: Page): Promise<() => Promise<string[]>> {
  await win.evaluate(() => {
    (window as unknown as { __rejections: string[] }).__rejections = [];
    window.addEventListener('unhandledrejection', (e) => {
      (window as unknown as { __rejections: string[] }).__rejections.push(String(e.reason));
    });
  });
  return () => win.evaluate(() => (window as unknown as { __rejections: string[] }).__rejections);
}

test('scope rules are saved exactly as the form displays them, and a revoked CA says so', async () => {
  const userDataDir = path.join(os.tmpdir(), `tacnoc-wiring-${Date.now()}`);
  const projectDir = path.join(os.tmpdir(), `tacnoc-wiring-proj-${Date.now()}`);
  const app = await electron.launch({ args: [MAIN, `--user-data-dir=${userDataDir}`] });
  const win = await app.firstWindow();
  await win.getByRole('button', { name: 'Create project' }).waitFor({ timeout: 20000 });
  const rejections = await trackRejections(win);

  await win.evaluate(async (dir: string) => {
    await (window as unknown as { tacnoc: Bridge }).tacnoc.invoke('createProject', dir, 'wiring');
  }, projectDir);

  // ---- scope: the narrowing fields must not survive an Add ----
  //
  // Ports / scheme / path were uncontrolled inputs. Adding a rule reset the
  // draft but left the boxes showing what had just been typed, so the NEXT rule
  // was stored with no port, no scheme and no path — strictly WIDER than the
  // rule on screen — in the gate that decides whether a request is authorized.
  await win.getByRole('button', { name: 'Scope' }).click();
  await win.getByPlaceholder('host e.g. example.test').fill('a.example.test');
  await win.getByPlaceholder('ports (comma) — blank = any').fill('8443');
  await win.getByPlaceholder('path prefix (optional)').fill('/api');
  await win.getByLabel('Scheme').selectOption('https');
  await win.getByRole('button', { name: 'Add', exact: true }).click();

  // After the add every narrowing field is visibly cleared…
  await expect(win.getByPlaceholder('ports (comma) — blank = any')).toHaveValue('');
  await expect(win.getByPlaceholder('path prefix (optional)')).toHaveValue('');
  await expect(win.getByLabel('Scheme')).toHaveValue('');

  await win.getByPlaceholder('host e.g. example.test').fill('b.example.test');
  await win.getByRole('button', { name: 'Add', exact: true }).click();
  await win.waitForTimeout(200);

  const scope = (await win.evaluate(async () =>
    (window as unknown as { tacnoc: Bridge }).tacnoc.invoke('getScope'),
  )) as {
    include: { host: string; ports: number[]; schemes: string[]; path?: { value: string } }[];
  };

  const a = scope.include.find((r) => r.host === 'a.example.test');
  const b = scope.include.find((r) => r.host === 'b.example.test');
  // …and what was stored matches what was shown, for both rules.
  expect(a?.ports).toEqual([8443]);
  expect(a?.schemes).toEqual(['https']);
  expect(a?.path?.value).toBe('/api');
  expect(b?.ports).toEqual([]);
  expect(b?.schemes).toEqual([]);
  expect(b?.path).toBeUndefined();

  // ---- revoked CA: no silent failure ----
  //
  // The main process refuses to write a 0-byte .crt for a revoked CA. That
  // rejection went nowhere: the button stayed enabled, the click raised an
  // unhandled rejection, and the operator got no response at all.
  await win.evaluate(async () => {
    await (window as unknown as { tacnoc: Bridge }).tacnoc.invoke('revokeCa', 'wiring regression');
  });
  await win.getByRole('button', { name: 'CA Certificate' }).click();
  await expect(win.getByText(/this project has no CA/i)).toBeVisible();

  await win.getByRole('checkbox').first().check();
  await expect(win.getByRole('button', { name: /Save CA certificate/ })).toBeDisabled();
  expect(await rejections()).toEqual([]);

  await app.close();
  await fs.rm(userDataDir, { recursive: true, force: true }).catch(() => undefined);
  await fs.rm(projectDir, { recursive: true, force: true }).catch(() => undefined);
});

test('the CA view follows a rotation it did not initiate', async () => {
  const userDataDir = path.join(os.tmpdir(), `tacnoc-ca-evt-${Date.now()}`);
  const projectDir = path.join(os.tmpdir(), `tacnoc-ca-evt-proj-${Date.now()}`);
  const app = await electron.launch({ args: [MAIN, `--user-data-dir=${userDataDir}`] });
  const win = await app.firstWindow();
  await win.getByRole('button', { name: 'Create project' }).waitFor({ timeout: 20000 });

  await win.evaluate(async (dir: string) => {
    await (window as unknown as { tacnoc: Bridge }).tacnoc.invoke('createProject', dir, 'ca-evt');
  }, projectDir);

  await win.getByRole('button', { name: 'CA Certificate' }).click();
  const before = (await win
    .getByText(/^[0-9A-F]{2}(:[0-9A-F]{2})+$/i)
    .first()
    .textContent()) as string;
  expect(before.length).toBeGreaterThan(0);

  // Rotate from outside the view — the same path the mesh takes when it is
  // granted cert ops mid-run. 'ca-changed' is emitted; the view must follow it
  // rather than keep presenting a fingerprint for a certificate that is gone.
  await win.evaluate(async () => {
    await (window as unknown as { tacnoc: Bridge }).tacnoc.invoke('rotateCa', 'regression');
  });
  await expect
    .poll(async () =>
      win
        .getByText(/^[0-9A-F]{2}(:[0-9A-F]{2})+$/i)
        .first()
        .textContent(),
    )
    .not.toBe(before);

  await app.close();
  await fs.rm(userDataDir, { recursive: true, force: true }).catch(() => undefined);
  await fs.rm(projectDir, { recursive: true, force: true }).catch(() => undefined);
});
