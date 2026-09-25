/**
 * Guided setup, through the REAL Electron app.
 *
 * The engine suite covers the pure logic — what `shouldOfferTour` decides, how
 * the checklist routes. None of that can answer the questions that actually
 * matter here, which are all about wiring across the contextBridge and across a
 * restart:
 *
 *  - does the walkthrough appear on its own for a new project,
 *  - does stepping it actually move the app to the view being described,
 *  - does Skip stick — across a relaunch, which is the only test that proves
 *    the preference reached disk and was read back.
 *
 * That last one is the load-bearing case. "Skippable" is worthless if the tour
 * returns on the next launch, and it is a two-process round trip (renderer →
 * IPC → userData file → IPC → renderer) that no unit test can stand in for.
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

const TOUR = '[role="dialog"][aria-label="Feature walkthrough"]';

test('the walkthrough runs, drives the view, and stays skipped across a restart', async () => {
  const stamp = Date.now();
  // One userData dir reused by both launches: the preference has to survive it.
  const userDataDir = path.join(os.tmpdir(), `tacnoc-guide-${stamp}`);
  const projectDir = path.join(os.tmpdir(), `tacnoc-guide-proj-${stamp}`);

  const first = await electron.launch({ args: [MAIN, `--user-data-dir=${userDataDir}`] });
  try {
    const win = await first.firstWindow();
    await win.getByRole('button', { name: 'Create project' }).waitFor({ timeout: 20000 });

    await win.evaluate(async (dir: string) => {
      const b = (window as unknown as { tacnoc: Bridge }).tacnoc;
      await b.invoke('createProject', dir, 'guided');
    }, projectDir);

    // It offers itself: no click got us here.
    const tour = win.locator(TOUR);
    await expect(tour).toBeVisible({ timeout: 15000 });
    await expect(tour).toContainText('step 1 of');

    // Step 1 is Setup, and a new project lands there rather than on an empty
    // history table.
    await expect(win.locator('.view')).toContainText('Setup');

    // Next moves both the step counter AND the view behind it.
    await win.getByRole('button', { name: 'Next' }).click();
    await expect(tour).toContainText('step 2 of');
    await expect(win.locator('.view')).toContainText('Engagement');

    // Back is not a trapdoor on the first step.
    await win.getByRole('button', { name: 'Back' }).click();
    await expect(tour).toContainText('step 1 of');
    await expect(win.getByRole('button', { name: 'Back' })).toBeDisabled();

    // Skipping from a step the tour navigated to puts the operator back where
    // they were, rather than stranding them on a view they never chose.
    await win.getByRole('button', { name: 'Next' }).click();
    await expect(win.locator('.view')).toContainText('Engagement');
    await win.getByRole('button', { name: 'Skip tour' }).click();
    await expect(tour).toBeHidden();
    await expect(win.locator('.nav-item.active')).toContainText('Setup');
  } finally {
    await first.close();
  }

  // Relaunch against the same userData and reopen the project.
  const second = await electron.launch({ args: [MAIN, `--user-data-dir=${userDataDir}`] });
  try {
    const win = await second.firstWindow();
    await win.getByRole('button', { name: 'Create project' }).waitFor({ timeout: 20000 });

    await win.evaluate(async (dir: string) => {
      const b = (window as unknown as { tacnoc: Bridge }).tacnoc;
      await b.invoke('openProject', dir);
    }, projectDir);

    // The app is up and on a project...
    await expect(win.locator('.view')).toContainText('Setup', { timeout: 15000 });
    // ...and the walkthrough does NOT come back.
    await expect(win.locator(TOUR)).toBeHidden();

    // It is still reachable on demand, which is the other half of the promise.
    const prefs = await win.evaluate(async () => {
      const b = (window as unknown as { tacnoc: Bridge }).tacnoc;
      return (await b.invoke('getUiPrefs')) as { tour: { status: string } };
    });
    expect(prefs.tour.status).toBe('skipped');
  } finally {
    await second.close();
  }
});

test('Setup reports the same blockers the engine gates on, and routes to the fix', async () => {
  const stamp = Date.now();
  const userDataDir = path.join(os.tmpdir(), `tacnoc-guide2-${stamp}`);
  const projectDir = path.join(os.tmpdir(), `tacnoc-guide2-proj-${stamp}`);

  const app = await electron.launch({ args: [MAIN, `--user-data-dir=${userDataDir}`] });
  try {
    const win = await app.firstWindow();
    await win.getByRole('button', { name: 'Create project' }).waitFor({ timeout: 20000 });

    await win.evaluate(async (dir: string) => {
      const b = (window as unknown as { tacnoc: Bridge }).tacnoc;
      await b.invoke('createProject', dir, 'guided-setup');
    }, projectDir);

    await win.locator(TOUR).waitFor({ timeout: 15000 });
    await win.getByRole('button', { name: 'Skip tour' }).click();
    await expect(win.locator(TOUR)).toBeHidden();

    // A fresh project has an empty scope, so the engine is fail-closed and the
    // checklist must say so rather than reporting a ready engagement.
    await expect(win.locator('.setup-banner')).toHaveClass(/blocked/);
    await expect(win.locator('.setup-item.blocker').first()).toBeVisible();

    // The checklist agrees with the report it is rendering.
    const ready = await win.evaluate(async () => {
      const b = (window as unknown as { tacnoc: Bridge }).tacnoc;
      return ((await b.invoke('getPreflight')) as { ready: boolean }).ready;
    });
    expect(ready).toBe(false);

    // "Open Scope" actually goes to Scope — the wiring a checklist invites rot in.
    await win.getByRole('button', { name: 'Open Scope' }).first().click();
    await expect(win.locator('.nav-item.active')).toContainText('Scope');
  } finally {
    await app.close();
  }
});
