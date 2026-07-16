import { resolve } from 'node:path';
import { defineConfig } from 'vitest/config';

export default defineConfig({
  resolve: {
    alias: {
      '@shared': resolve('src/shared'),
      '@engine': resolve('src/engine'),
      '@sdk': resolve('src/sdk'),
    },
  },
  test: {
    globals: true,
    environment: 'node',
    include: ['test/**/*.test.ts'],
    // Engine + integration tests bind loopback sockets; keep them serialized-ish
    // to avoid port pressure but still allow file-level parallelism.
    pool: 'forks',
    testTimeout: 20000,
    hookTimeout: 20000,
    coverage: {
      provider: 'v8',
      include: ['src/engine/**/*.ts', 'src/shared/**/*.ts', 'src/sdk/**/*.ts'],
      exclude: ['**/*.d.ts'],
      reporter: ['text', 'html'],
    },
  },
});
