/**
 * Full GUI click-through E2E against the REAL Electron app + the local test
 * server. Drives project setup + proxy via the bridge (only bypassing the native
 * folder dialog), makes real proxied HTTPS traffic, then clicks through every
 * view asserting real data renders. Also exercises the isolated-worker example
 * extension end-to-end.
 *
 * OPT-IN: requires `npm run build` first and a display. Run: npm run test:e2e
 */

import {
  test,
  expect,
  _electron as electron,
  type ElectronApplication,
  type Page,
} from '@playwright/test';
import * as path from 'node:path';
import * as os from 'node:os';
import { promises as fs } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { startTestServer, type TestServerHandle } from '../server/testServer.js';
import { httpsThroughProxy } from '../support/proxyClient.js';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

let app: ElectronApplication;
let win: Page;
let server: TestServerHandle;
let projectDir: string;

test.beforeAll(async () => {
  server = await startTestServer();
  projectDir = path.join(os.tmpdir(), `belcher-e2e-full-${Date.now()}`);
  app = await electron.launch({ args: [path.join(root, 'out/main/index.js')] });
  win = await app.firstWindow();
  await win.getByRole('button', { name: 'Create project' }).waitFor({ timeout: 20000 });
});

test.afterAll(async () => {
  await app.close();
  await server.close();
  await fs.rm(projectDir, { recursive: true, force: true });
});

test('end-to-end: proxy capture, findings, and all views render with real data', async () => {
  // 1) Create project, start proxy, set scope, grab the CA — via the bridge.
  const setup = await win.evaluate(async (dir: string) => {
    const b = (
      window as unknown as { belcher: { invoke: (m: string, ...a: unknown[]) => Promise<unknown> } }
    ).belcher;
    await b.invoke('createProject', dir, 'e2e-full');
    const status = (await b.invoke('startProxy', '127.0.0.1', 0)) as { port: number };
    const ca = (await b.invoke('getCaInfo')) as { certPem: string };
    await b.invoke('setScope', {
      include: [
        { id: 'r', enabled: true, hostMatch: 'exact', host: 'localhost', schemes: [], ports: [] },
      ],
      exclude: [],
    });
    return { port: status.port, ca: ca.certPem };
  }, projectDir);

  // App should have transitioned from the welcome screen to the workspace.
  await expect(win.getByRole('button', { name: 'HTTP History' })).toBeVisible({ timeout: 15000 });

  // 2) Make real proxied HTTPS traffic through the app's MITM proxy.
  const res = await httpsThroughProxy(
    '127.0.0.1',
    setup.port,
    setup.ca,
    'localhost',
    server.httpsPort,
    {
      path: '/missing-headers',
    },
  );
  expect(res.status).toBe(200);

  // 3) History view shows the captured exchange; selecting it shows the inspector.
  await win.getByRole('button', { name: 'HTTP History' }).click();
  await expect(win.getByText('/missing-headers').first()).toBeVisible({ timeout: 15000 });
  await win.getByText('/missing-headers').first().click();
  await expect(win.getByText('Send to Repeater →')).toBeVisible();

  // 4) Findings view shows a passive finding (missing security headers).
  await win.getByRole('button', { name: 'Findings' }).click();
  await expect(
    win.getByText(/Content-Security-Policy|Strict-Transport-Security/).first(),
  ).toBeVisible({
    timeout: 15000,
  });

  // 5) Scope view renders the rule we added.
  await win.getByRole('button', { name: 'Scope' }).click();
  await expect(win.getByRole('heading', { name: 'Include rules' })).toBeVisible();
  await expect(win.getByText('localhost').first()).toBeVisible();

  // 6) Encoder view: apply a Base64 transform and check the output.
  await win.getByRole('button', { name: 'Encoder / Decoder' }).click();
  await expect(win.getByText('JWT inspector')).toBeVisible();
  const input = win.locator('textarea').first();
  await input.fill('hello');
  await win.getByRole('button', { name: 'Apply →' }).click();
  await expect(win.locator('textarea').nth(1)).toHaveValue('aGVsbG8=', { timeout: 10000 });

  // 7) Compare view renders (the Left/Right editors and Diff pane).
  await win.getByRole('button', { name: 'Compare' }).click();
  await expect(win.getByText('Left', { exact: true })).toBeVisible();
  await expect(win.getByText('Right', { exact: true })).toBeVisible();

  // 8) Repeater, Variation, CA, Audit views render.
  await win.getByRole('button', { name: 'Repeater' }).click();
  await expect(win.getByRole('button', { name: 'Send ▶' })).toBeVisible();

  await win.getByRole('button', { name: 'Variation' }).click();
  await expect(win.getByText('Controlled variation')).toBeVisible();

  await win.getByRole('button', { name: 'CA Certificate' }).click();
  await expect(win.getByText(/trusting this CA is powerful/i)).toBeVisible();

  await win.getByRole('button', { name: 'Audit Log' }).click();
  await expect(win.getByText(/every automated action is recorded/i)).toBeVisible();

  // 9) Extensions view: load the bundled example (isolated worker) and see it listed.
  await win.getByRole('button', { name: 'Extensions' }).click();
  await win.getByRole('button', { name: /Load bundled example/i }).click();
  await expect(win.getByText('Header Hygiene (example)')).toBeVisible({ timeout: 15000 });

  // 10) Emergency stop is always available and safe to click.
  await win.getByRole('button', { name: /EMERGENCY STOP/ }).click();
  await expect(win.getByRole('button', { name: 'HTTP History' })).toBeVisible();
});
