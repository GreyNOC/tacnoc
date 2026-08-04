/**
 * TACNOC MCP server entry point.
 *
 * Runs as a plain Node process over stdio — no Electron, no window, no project,
 * no network listener. An MCP client (Claude Code) spawns it, speaks
 * newline-delimited JSON-RPC on stdin/stdout, and gets TACNOC's offline
 * analysis engine as callable tools.
 *
 * Start it by hand to sanity-check the wiring:
 *   echo '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' | node out/mcpsrv/mcp/index.js
 */

import { promises as fs } from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { McpServer, log } from './protocol.js';
import { buildReadOnlyTools } from './tools.js';

const SERVER_NAME = 'tacnoc';

/**
 * Find the package version by walking up from this module.
 *
 * Deliberately layout-independent: the compiled entry sits at a different depth
 * than the source, and hardcoding either path would silently report a stale
 * version the moment the build output moves.
 */
async function resolveVersion(): Promise<string> {
  let dir = path.dirname(fileURLToPath(import.meta.url));
  for (let depth = 0; depth < 6; depth++) {
    try {
      const raw = await fs.readFile(path.join(dir, 'package.json'), 'utf8');
      const pkg = JSON.parse(raw) as { name?: string; version?: string };
      if (pkg.name === 'greynoc-tacnoc' && pkg.version) return pkg.version;
    } catch {
      // Not at the package root yet (or unreadable) — keep walking.
    }
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return '0.0.0-dev';
}

async function main(): Promise<void> {
  const version = await resolveVersion();
  const tools = buildReadOnlyTools();
  const server = new McpServer(SERVER_NAME, version, tools);

  log(`v${version} ready — ${tools.length} read-only tools: ${server.toolNames().join(', ')}`);
  log('offline analysis only: no project is opened and no traffic is generated.');

  // Terminate cleanly on a client disconnect or a supervisor signal, so the
  // process never lingers holding the pipe open.
  for (const signal of ['SIGINT', 'SIGTERM'] as const) {
    process.on(signal, () => process.exit(0));
  }

  await server.serve(process.stdin, process.stdout);
  log('stdin closed — exiting.');
}

main().catch((err: unknown) => {
  log(`fatal: ${err instanceof Error ? (err.stack ?? err.message) : String(err)}`);
  process.exit(1);
});
