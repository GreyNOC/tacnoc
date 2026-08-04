# TACNOC as an MCP server (Claude Code extension)

TACNOC's analysis engine is exposed to MCP clients — Claude Code in particular —
as a set of callable tools. The server is a plain Node process spawned over
stdio: no Electron, no window, no project, no listening socket.

> **Everything this server exposes is read-only and offline.** No tool opens a
> project, reads a secret, writes to disk, or emits a packet. That property is
> the whole safety argument; [Adding a tool](#adding-a-tool) explains what breaks
> if it stops being true.

## Tools

| Tool | What it does |
|---|---|
| `inspect_jwt` | Decode a JWT's header and claims. **Decode-only** — never verifies a signature. |
| `analyze_tokens` | Screen captured tokens for predictability: collisions, byte and positional entropy, monobit bias, adjacent-byte correlation, compressibility. |
| `list_transforms` | Enumerate the 19 transform ids. |
| `apply_transform` | URL/Base64/Base64url/hex/HTML encode and decode, gzip, MD5/SHA-1/SHA-256/SHA-512, epoch↔ISO. |
| `diff_text` | Line-level diff. |
| `diff_json` | Structure-aware JSON diff (paths, not line noise). |
| `diff_bytes` | Byte diff of two base64 blobs: equality, first-difference offset, common prefix/suffix. |
| `evaluate_scope` | Decide whether a URL is in an authorized scope, using the engine's own fail-closed evaluator. |

`analyze_tokens` is deliberately cautious: it can show a generator is **weak**,
never that one is cryptographically secure. Below ~100 samples it returns
`insufficient-data` and says so rather than guessing.

`evaluate_scope` normalizes partial rules so a caller can pass
`{include:[{host:"*.example.com"}]}`. Defaults are chosen to **under-claim**: a
host with no `*` becomes an `exact` match, not `subdomain`. With no include
rules, nothing is in scope.

## Build

The server compiles separately from the app, because the root `tsconfig.json` is
typecheck-only (`noEmit`) while the app is bundled by electron-vite:

```bash
npm run build:mcp     # tsc -p tsconfig.mcp.json  →  out/mcpsrv/
```

`out/` is gitignored, so build once after cloning and again after touching
`src/mcp` or the engine modules it imports.

Sanity-check it by hand — it speaks newline-delimited JSON-RPC on stdio:

```bash
echo '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' | node out/mcpsrv/mcp/index.js
```

## Install

**As a plugin.** This repo *is* the plugin: `.claude-plugin/plugin.json` plus a
root `.mcp.json` that resolves `${CLAUDE_PLUGIN_ROOT}`, so it works wherever the
plugin lands. Enable it by adding the repo path to `enabledPlugins` in your
Claude Code settings.

**As a project server.** A workspace can register the server directly instead.
`${CLAUDE_PLUGIN_ROOT}` does *not* expand outside plugin context, so use an
absolute path in that workspace's `.mcp.json`:

```json
{
  "mcpServers": {
    "tacnoc": {
      "type": "stdio",
      "command": "node",
      "args": ["C:\\path\\to\\GreyNOC Belcher\\out\\mcpsrv\\mcp\\index.js"]
    }
  }
}
```

Tools then appear as `mcp__tacnoc__<tool>`. Pre-allow them **by name** rather
than with an `mcp__tacnoc__*` wildcard, so that a tool added later has to be
allowed deliberately instead of inheriting the grant.

## Design notes

**No MCP SDK.** The transport is hand-rolled in `src/mcp/protocol.ts`. TACNOC
ships three runtime dependencies and a published SBOM; for a security research
tool the dependency surface is part of the threat model, and the stdio transport
is newline-delimited JSON-RPC over four methods. The SDK would add more
supply-chain surface than it saves.

**stdout is sacred.** It carries JSON-RPC frames and nothing else — a stray
write corrupts the stream and the client drops the connection. Diagnostics go to
stderr via `log()`.

**Tool failures are results, not transport errors.** A rejected input comes back
as `isError: true` content the model can read and adapt to, rather than a
protocol error it cannot see.

**Results are truncated at 100k characters** with a visible marker, so one
oversized diff cannot flood a caller's context.

**Why these modules.** `transforms/codec`, `compare/compare`,
`analysis/sequencer`, and `scope/scope` import nothing but `node:crypto` and
`node:zlib` (`compare` imports nothing at all). That is what lets the server run
as plain Node: no WASM SQLite, and no Electron `safeStorage`, which a non-Electron
process cannot call — meaning it could not decrypt a desktop-created project's
bodies and headers even if it tried to open one.

`tsconfig.mcp.json` includes only `src/mcp/**`, so tsc emits exactly the modules
actually imported. If a build ever starts emitting storage or renderer files, an
import crept in that breaks the offline guarantee — treat that as a build
failure, not a surprise.

## Adding a tool

A read-only, offline tool is a normal change: add it to `buildReadOnlyTools()`
and update `EXPECTED_TOOLS` in `test/mcp/mcpServer.test.ts`.

A **traffic-generating** tool (Repeater, Variation) is not, and the registry test
will fail on purpose to stop it going in unnoticed. Before exposing one:

1. **Re-implement the active-request guard.** The tool handlers in
   `engine/ai/tools.ts` carry scope gating, but the per-run request budget
   (`maxActiveRequestsPerRun`), the `mesh.request` audit record, and the abort
   check live in `engine/ai/orchestrator.ts` → `wrapActive()`. Exposing handlers
   directly inherits the scope gate and silently drops all three.
2. **Give it a session.** Active tools need a real `TacnocSession` with a
   project, which reintroduces the secret-store and single-writer constraints
   described above.
3. **Extend the client's own guardrails.** In the GreyNOC Hunting workspace, the
   `PreToolUse` hook in `.claude/settings.json` matches specific
   traffic-generating tool names; a TACNOC tool not on that list bypasses the
   charter's traffic hard stops entirely. Update the matcher **before** the tool
   ships, and narrow the pre-allow list.
