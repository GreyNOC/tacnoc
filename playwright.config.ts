import { defineConfig } from '@playwright/test';

/**
 * Playwright drives the Electron renderer for end-to-end UI flows.
 * E2E specs live in test/e2e and launch the built app via Electron.
 * These are opt-in (npm run test:e2e) and require a built app + a display.
 */
export default defineConfig({
  testDir: './test/e2e',
  timeout: 60000,
  fullyParallel: false,
  workers: 1,
  reporter: [['list'], ['html', { open: 'never' }]],
  use: {
    trace: 'retain-on-failure',
  },
});
