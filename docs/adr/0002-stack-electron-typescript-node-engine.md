# ADR 0002 — Core stack: Electron + TypeScript + Node engine

- Status: Accepted
- Date: 2026-07-15
- Supersedes: n/a (the project charter's *preferred* stack was Tauri + Rust)

## Context

The project charter proposes Tauri + Rust/Tokio for the core proxy engine. Two
facts drove a re-evaluation:

1. **Toolchain reality.** The build host has Node.js 24 and Python 3.11 but **no
   Rust/Cargo toolchain**. Tauri cannot build without it. Installing rustup is
   possible but heavy, and the resulting build could not be verified as
   thoroughly in this environment.
2. **Ecosystem fit.** The rest of the GreyNOC toolkit that ships as desktop apps
   (GreyNet, Saturn, GreyIQ) is **Electron**. The charter explicitly permits
   deviating from the preferred stack when "the existing repository strongly
   indicates another suitable architecture." The surrounding ecosystem does.
3. **Empirical-verification house rule.** "Reproducible or it didn't happen."
   A stack we can build, run, and test *now* is strongly preferred over one we
   can only partially verify.

The operator explicitly chose the Electron + TypeScript/Node option.

## Decision

- **Core proxy/networking engine:** TypeScript on Node's built-in `net`, `tls`,
  `http`, `https`, and `zlib`. The engine is a standalone, Electron-free module
  (`src/engine`) so it can be unit- and integration-tested headlessly under
  Node/Vitest.
- **Desktop shell:** Electron (main + contextIsolated preload + React renderer).
- **UI:** React + TypeScript, bundled with `electron-vite`.
- **Local persistence:** SQLite via Node's built-in `node:sqlite`
  (`DatabaseSync`) — no native module to rebuild against Electron's ABI. Large
  bodies are streamed to a content-addressed blob store on disk, keeping the DB
  small.
- **TLS interception CA:** generated locally with `node-forge` (pure JS).
- **Secret storage:** Electron `safeStorage` (DPAPI on Windows, Keychain on
  macOS, libsecret on Linux) behind a `SecretStore` interface, with an
  explicitly-less-secure file fallback used only for headless tests/CI.
- **Testing:** Vitest for engine/integration; Playwright for UI E2E.

## Consequences

- **Pro:** zero native builds; the engine is fully testable today; matches the
  team's shipped Electron apps; reproducible installs via `package-lock.json`.
- **Con:** an Electron renderer is a Chromium process — we must be strict about
  never executing captured HTML/JS (see THREAT_MODEL.md) and keep
  `contextIsolation` on with a minimal preload surface.
- `node:sqlite` is a recent/experimental Node API; we pin a modern Electron
  whose bundled Node includes it and isolate all DB access behind a small
  interface so the backend can be swapped without touching call sites.
- Memory-safety guarantees that Rust would have provided are instead obtained by
  treating all captured bytes as untrusted, using bounded buffers, streaming
  large bodies to disk, and never `eval`-ing or rendering response content.

## Follow-ups

- Revisit a Rust engine only if profiling shows Node throughput is the
  bottleneck for a real engagement; the `src/engine` boundary makes that a
  contained swap.
