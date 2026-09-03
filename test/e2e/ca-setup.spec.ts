/**
 * The guided CA setup, driven through the REAL Electron app.
 *
 * What this protects is the honesty of the last step. The guide tells the
 * operator "HTTPS interception is working" on the strength of decrypted proxy
 * traffic, and that claim is only worth making if engine-generated HTTPS cannot
 * satisfy it — a Repeater probe travels over Node's own TLS and proves nothing
 * about whether any browser trusts the CA.
 *
 * OPT-IN: requires `npm run build` first and a display. Run: npm run test:e2e
 */

import { test, expect, _electron as electron } from '@playwright/test';
import * as path from 'node:path';
import * as os from 'node:os';
import { promises as fs } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { startTestServer, type TestServerHandle } from '../server/testServer.js';
import { httpsThroughProxy } from '../support/proxyClient.js';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const MAIN = path.join(root, 'out/main/index.js');

type Bridge = { invoke: (m: string, ...a: unknown[]) => Promise<unknown> };

test('the CA guide is optional, gives a runnable command, and only claims success on real interception', async () => {
  const projectDir = path.join(os.tmpdir(), `tacnoc-ca-setup-${Date.now()}`);
  let server: TestServerHandle | undefined;
  const app = await electron.launch({ args: [MAIN] });
  try {
    const win = await app.firstWindow();
    await win.getByRole('button', { name: 'Create project' }).waitFor({ timeout: 20000 });
    await win.evaluate(async (dir: string) => {
      await (window as unknown as { tacnoc: Bridge }).tacnoc.invoke(
        'createProject',
        dir,
        'ca-setup',
      );
    }, projectDir);

    await win.getByRole('button', { name: 'CA Certificate' }).click();

    // 1) It says up front that this is optional, and that HTTP works without it.
    await expect(
      win.getByRole('heading', { name: /Read HTTPS traffic \(optional\)/i }),
    ).toBeVisible();
    await expect(win.getByText('HTTPS not set up')).toBeVisible();

    // 2) The steps are present, and the trust step is gated on acknowledgement.
    await expect(win.getByText(/trusting this CA is powerful/i)).toBeVisible();
    await expect(win.getByRole('button', { name: /Save CA certificate/ })).toBeDisabled();

    // 3) Skipping is real: the whole flow collapses to one line and an offer.
    await win.getByRole('button', { name: 'Skip for now' }).click();
    await expect(win.getByText(/Setup skipped/i)).toBeVisible();
    await expect(win.getByRole('button', { name: /Save CA certificate/ })).toHaveCount(0);
    await win.getByRole('button', { name: 'Set up HTTPS interception' }).click();
    await expect(win.getByRole('button', { name: /Save CA certificate/ })).toBeVisible();

    // 4) Engine-generated HTTPS must NOT flip the verdict. Send a real Repeater
    //    request over HTTPS, which never presents the project's leaf cert.
    server = await startTestServer();
    const scheme = 'https';
    await win.evaluate(
      async ({ port }: { port: number }) => {
        const b = (window as unknown as { tacnoc: Bridge }).tacnoc;
        await b.invoke('setScope', {
          include: [
            {
              id: 'r',
              enabled: true,
              hostMatch: 'exact',
              host: 'localhost',
              schemes: [],
              ports: [],
            },
          ],
          exclude: [],
        });
        await b.invoke(
          'sendRepeater',
          {
            scheme: 'https',
            host: 'localhost',
            port,
            raw: `GET /json HTTP/1.1\r\nHost: localhost\r\n\r\n`,
          },
          { timeoutMs: 10000, followRedirects: false, maxRedirects: 0, useCookieJar: false },
        );
      },
      { port: server.httpsPort },
    );

    await win.getByRole('button', { name: 'Check again' }).click();
    // Still not set up: a Repeater request is not evidence about a browser.
    await expect(win.getByText('HTTPS not set up')).toBeVisible();
    await expect(win.getByText(/No decrypted HTTPS yet/i)).toBeVisible();

    // 5) Now make genuinely intercepted traffic: through the proxy, trusting the
    //    project CA the way a correctly-configured browser would.
    const setup = (await win.evaluate(async () => {
      const b = (window as unknown as { tacnoc: Bridge }).tacnoc;
      const status = (await b.invoke('startProxy', '127.0.0.1', 0)) as { port: number };
      const ca = (await b.invoke('getCaInfo')) as { certPem: string };
      return { port: status.port, ca: ca.certPem };
    })) as { port: number; ca: string };

    const res = await httpsThroughProxy(
      '127.0.0.1',
      setup.port,
      setup.ca,
      'localhost',
      server.httpsPort,
      { path: '/json' },
    );
    expect(res.status).toBe(200);
    expect(scheme).toBe('https');

    // The guide notices on its own poll, and collapses once it is satisfied.
    await expect(win.getByText('HTTPS interception working')).toBeVisible({ timeout: 15000 });
    await expect(win.getByText(/interception is already working/i)).toBeVisible();

    // 6) "Show the steps anyway" has to actually show them. Being already
    //    verified is what collapses the guide, and that does not stop being true
    //    when the operator asks to see it — so the button needs its own override
    //    or it announces itself and does nothing.
    await win.getByRole('button', { name: 'Show the steps anyway' }).click();
    await expect(win.getByText(/trusting this CA is powerful/i)).toBeVisible();
    await win.getByRole('button', { name: 'Skip for now' }).click();
    await expect(win.getByText(/interception is already working/i)).toBeVisible();
  } finally {
    await app.close();
    await server?.close();
    await fs.rm(projectDir, { recursive: true, force: true }).catch(() => undefined);
  }
});
