/**
 * The reported crash, driven through the REAL app.
 *
 * "I uploaded the entire hunt dir with all the scope and it crashes the app."
 * A real hunt folder is mostly recon output — subfinder/amass/httpx dumps
 * holding tens of thousands of hostnames — and every one of those became a scope
 * candidate, a table row, and eventually a rule the gate re-parsed from SQLite
 * on every proxied request.
 *
 * This builds exactly that folder, adopts it the way the welcome screen does,
 * and drives the screens the operator would actually touch. The assertions are
 * time budgets: the point is not that the numbers are pretty, it is that the app
 * still answers at all. Before the fix the proposal alone was ~500,000
 * candidates and the Engagement table blocked the renderer for ~17 seconds.
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

/** Hostnames deliberately NOT under a domain containing a scope marker word. */
const hosts = (count: number, prefix: string): string =>
  Array.from({ length: count }, (_, i) => `${prefix}${i}.bounty-corp.test`).join('\n');

/** A hunt folder shaped like a real one: a little policy, a lot of recon. */
async function makeHuntFolder(dir: string): Promise<void> {
  await fs.mkdir(path.join(dir, 'recon'), { recursive: true });
  await fs.writeFile(
    path.join(dir, 'POLICY.md'),
    [
      '# Bounty Corp program',
      '',
      '## In scope',
      'api.bounty-corp.test',
      'app.bounty-corp.test',
      '',
      '## Out of scope',
      'billing.bounty-corp.test is explicitly out of scope — do not test it.',
      '',
      'Required User-Agent: greynoc-research',
    ].join('\n'),
    'utf8',
  );
  // ~95,000 hostnames across the dumps, which is an ordinary recon haul.
  await fs.writeFile(path.join(dir, 'recon', 'subs.txt'), hosts(40_000, 'sub'), 'utf8');
  await fs.writeFile(path.join(dir, 'recon', 'all-domains.txt'), hosts(35_000, 'dom'), 'utf8');
  await fs.writeFile(path.join(dir, 'recon', 'httpx.log'), hosts(20_000, 'live'), 'utf8');
}

test('a hunt folder full of recon output stays responsive and never proposes an unreviewable list', async () => {
  const userDataDir = path.join(os.tmpdir(), `tacnoc-scale-${Date.now()}`);
  const huntDir = path.join(os.tmpdir(), `tacnoc-hunt-${Date.now()}`);
  await makeHuntFolder(huntDir);

  const app = await electron.launch({ args: [MAIN, `--user-data-dir=${userDataDir}`] });
  const win: Page = await app.firstWindow();
  await win.getByRole('button', { name: 'Create project' }).waitFor({ timeout: 30000 });

  // Adopt the folder exactly as "Open hunt folder" does, bypassing only the
  // native directory dialog.
  const adopted = await win.evaluate(async (dir: string) => {
    const started = performance.now();
    const res = (await (window as unknown as { tacnoc: Bridge }).tacnoc.invoke(
      'adoptHuntFolder',
      dir,
      'scale',
    )) as { scan: { filesSeen: number } };
    return { ms: performance.now() - started, filesSeen: res.scan.filesSeen };
  }, huntDir);

  expect(adopted.filesSeen).toBeGreaterThan(0);
  // Adoption reads and classifies the folder. It used to be unbounded.
  expect(adopted.ms).toBeLessThan(30_000);

  // The proposal must come back bounded, and must SAY it was bounded.
  const proposal = await win.evaluate(async () => {
    const started = performance.now();
    const p = (await (window as unknown as { tacnoc: Bridge }).tacnoc.invoke(
      'proposeScopeFromWorkspace',
    )) as {
      include: unknown[];
      exclude: { host: string }[];
      unclear: unknown[];
      omitted: number;
      truncated: boolean;
      notes: string[];
    };
    return {
      ms: performance.now() - started,
      total: p.include.length + p.exclude.length + p.unclear.length,
      excluded: p.exclude.map((c) => c.host),
      omitted: p.omitted,
      truncated: p.truncated,
      notes: p.notes.join(' '),
    };
  });

  expect(proposal.total).toBeLessThanOrEqual(2000);
  expect(proposal.truncated).toBe(true);
  // Tens of thousands elided. Not the full 95,000: the workspace reader already
  // caps each file at 256 KiB, so only the first ~12,000 lines of each dump are
  // ever seen. That bound is pre-existing and independent of the candidate cap.
  expect(proposal.omitted).toBeGreaterThan(20_000);
  // Truncation is never silent — the operator is told what was left out.
  expect(proposal.notes).toMatch(/further host\(s\) were found and NOT listed/i);
  // The cap must never cost an exclusion, however deep in the folder it sits.
  expect(proposal.excluded).toContain('billing.bounty-corp.test');
  expect(proposal.ms).toBeLessThan(30_000);

  // The Engagement view is where the renderer used to die building one table row
  // per candidate. It must paint, and the window must still answer afterwards.
  // `exact` because the Setup view also offers an "Open Engagement" shortcut.
  await win.getByRole('button', { name: 'Engagement', exact: true }).click();
  await expect(
    win.getByRole('heading', { name: 'Proposed scope (from the engagement folder)' }),
  ).toBeVisible({ timeout: 60_000 });
  await expect(win.getByText(/Only hosts shown here can be ticked/i)).toBeVisible({
    timeout: 60_000,
  });

  // Responsiveness: a round trip through the main process while the big folder
  // is loaded. A blocked event loop shows up here as a timeout.
  const pinged = await win.evaluate(async () => {
    const started = performance.now();
    await (window as unknown as { tacnoc: Bridge }).tacnoc.invoke('getProxyStatus');
    return performance.now() - started;
  });
  expect(pinged).toBeLessThan(5_000);

  // Filtering must not silently discard an already-reviewed selection. Narrow
  // the list so most ticked rows are hidden, then confirm the button still
  // promises them and the save still delivers them.
  const beforeFilter = await win
    .getByRole('button', { name: /Add \d+ selected to scope/ })
    .textContent();
  const promised = Number(/Add (\d+) selected/.exec(beforeFilter ?? '')?.[1] ?? '0');
  expect(promised).toBeGreaterThan(0);

  await win.getByLabel('Filter candidates by host').fill('sub1234.bounty-corp.test');
  await expect(
    win.getByRole('button', { name: `Add ${promised} selected to scope` }),
  ).toBeVisible();

  const scopeBefore = await win.evaluate(
    async () =>
      (
        (await (window as unknown as { tacnoc: Bridge }).tacnoc.invoke('getScope')) as {
          include: unknown[];
        }
      ).include.length,
  );

  await win.getByRole('button', { name: /Add \d+ selected to scope/ }).click();
  await expect(win.getByText(/Added \d+ host\(s\) to scope/)).toBeVisible({ timeout: 30_000 });

  const scopeAfter = await win.evaluate(
    async () =>
      (
        (await (window as unknown as { tacnoc: Bridge }).tacnoc.invoke('getScope')) as {
          include: unknown[];
        }
      ).include.length,
  );
  // What the button promised is what was written, even though the filter hid
  // most of those rows at the moment it was clicked.
  expect(scopeAfter - scopeBefore).toBe(promised);

  // Then open Scope — the second place it used to freeze.
  await win.getByRole('button', { name: 'Scope', exact: true }).click();
  await expect(win.getByRole('heading', { name: 'Include rules' })).toBeVisible({
    timeout: 60_000,
  });

  // Still answering after all of it.
  const finalPing = await win.evaluate(async () => {
    const started = performance.now();
    await (window as unknown as { tacnoc: Bridge }).tacnoc.invoke('historyCount');
    return performance.now() - started;
  });
  expect(finalPing).toBeLessThan(5_000);

  await app.close();
  await fs.rm(userDataDir, { recursive: true, force: true }).catch(() => undefined);
  await fs.rm(huntDir, { recursive: true, force: true }).catch(() => undefined);
});
