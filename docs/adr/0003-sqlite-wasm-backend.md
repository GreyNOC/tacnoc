# ADR 0003 — SQLite via WASM (`node-sqlite3-wasm`), not `node:sqlite`

- Status: Accepted
- Date: 2026-07-16
- Amends: ADR 0002 (which initially chose `node:sqlite`)

## Context

ADR 0002 chose Node's built-in `node:sqlite`. Empirical verification exposed a
fatal flaw: **Electron 33 bundles Node 20.18, which has no `node:sqlite`** (that
module landed in Node 22.5, behind a flag). The engine tests pass under the test
runner's Node 24, but the *shipped* app runs on Electron's Node — so the app
would crash the moment a project's database was opened. This is exactly the
"green tests that don't work when exercised" failure the house rules warn about.

> **Update (2026-07-18, v0.3.0):** the app has since moved to Electron 43 (the
> Node 22.x line, which *does* include `node:sqlite`, still behind a flag). The
> decision below is unchanged: `node-sqlite3-wasm` remains the single backend so
> the store is version-independent and identical across the test runner and the
> shipped runtime. The Electron-33/Node-20.18 detail above is the original,
> as-of-decision context.

## Decision

Use **`node-sqlite3-wasm`** — a pure-WebAssembly SQLite build — as the single
storage backend everywhere.

Verified directly under **both** runtimes (Node 24 test runner AND Electron's
Node 20.18 via `ELECTRON_RUN_AS_NODE`):

- synchronous `run` / `get` / `all` / `exec` with array-bound params,
- `{ changes, lastInsertRowid }` from `run`,
- BLOB values round-trip as `Uint8Array`,
- `BEGIN IMMEDIATE` / `COMMIT` / `ROLLBACK` transactions,
- `PRAGMA user_version` read/write for migrations,
- real on-disk file persistence across close/reopen.

The `Database` wrapper's public API is unchanged, so no repository or call-site
changes were needed. It is loaded via `createRequire` so bundlers don't try to
statically process the `.wasm` asset.

## Consequences

- **Tests now verify what ships**: the identical backend runs in tests and in
  the packaged Electron app. No native rebuild, no Node-version coupling.
- WAL journaling is unsupported by the WASM VFS; it transparently falls back to
  rollback journaling. We rely on the default durable journal.
- Whole-database throughput is lower than a native build, but the DB stores only
  metadata (large bodies live in the on-disk blob store), so this is acceptable.
- Packaging note: `node_modules/node-sqlite3-wasm` (including its `.wasm`) must
  be shipped unpacked (e.g. electron-builder `asarUnpack`) — captured in
  docs/testing.md and the packaging notes.
