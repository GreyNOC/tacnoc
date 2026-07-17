# GreyNOC Belcher

**An extensible web-application security research suite for _authorized_ testing.**

GreyNOC Belcher is an original, local-first intercepting-proxy workbench: capture
and inspect HTTP/HTTPS traffic, intercept and edit messages, replay requests,
transform data, run passive security checks, and perform tightly-controlled,
rate-limited request variation against destinations you are explicitly authorized
to test. It is inspired by the _workflow_ of intercepting-proxy tooling; it copies
no proprietary code, UI, branding, or assets.

> ⚠️ **Authorized use only.** This tool is for sanctioned engagements, your own
> systems, CTFs, and defensive/educational research. Do not use it against
> systems you are not authorized to test. See
> [docs/authorization-and-scope.md](docs/authorization-and-scope.md).

## Safety is built in, not bolted on

- **Loopback by default** — the proxy binds `127.0.0.1`; a non-loopback bind is
  flagged in the UI.
- **Fail-closed scope** — no automated request generation happens until a
  destination is explicitly added to project scope. Every row shows in/out of
  scope. Scope is enforced in the engine, not just the UI.
- **Emergency stop** — one control halts all automated work; every automated
  action is written to an audit log.
- **Configurable limits** — concurrency, requests/second, timeout, and a hard
  per-job maximum, all conservative by default.
- **Secret hygiene** — secrets are redacted in logs and exports; the UI warns
  before revealing or exporting cookies, authorization headers, or tokens.
- **Local CA, your trust decision** — TLS interception certificates are
  generated locally and the CA private key is stored in OS secure storage. The
  app never modifies your OS trust store; installing the CA is an explicit,
  warned, manual step. See [docs/certificate-management.md](docs/certificate-management.md).
- **No telemetry** — captured traffic is never sent to analytics, telemetry, or
  external AI services. There is no network sink for logs.

The tool deliberately contains **no** stealth/persistence, malware delivery,
phishing, credential-stuffing, denial-of-service, destructive payload,
CAPTCHA-bypass, or monitoring-evasion features.

## Stack

Electron + React/TypeScript UI, a standalone TypeScript proxy/networking engine
on Node's `net`/`tls`/`http` primitives, SQLite via WebAssembly
(`node-sqlite3-wasm`), and a local CA generated with `node-forge`. See
[ARCHITECTURE.md](ARCHITECTURE.md) and
[docs/adr/](docs/adr/) for the decisions behind this (notably ADR 0002 and
ADR 0003).

## Requirements

- Node.js ≥ 20.11 and npm (developed against Node 24).
- Windows, macOS, or Linux.
- No native build toolchain required (SQLite is WASM; the CA is pure JS).

## Quick start (development)

```bash
npm install
npm run dev          # launch the app (electron-vite dev)
```

In the app:

1. **Create a project** (choose a folder + name; optionally record an
   authorization reference).
2. Open **CA Certificate**, read the warning, and **save the CA** to a file;
   install it into the *browser/profile you will test with* (manual, per the
   instructions shown).
3. Click the **Proxy** chip in the top bar to start the loopback proxy.
4. Point your browser at `http://127.0.0.1:8080`.
5. Browse the local test server (below) or your authorized target — traffic
   appears in **HTTP History**.
6. Add your target to **Scope** before using **Variation**.

### Try it against the bundled safe test server

The repository ships a deliberately-safe local test server used by the test
suite. It never talks to the internet. It is started automatically by the tests;
to explore its endpoints (`/json`, `/gzip`, `/set-cookie`, `/missing-headers`,
`/reflect`, …) see [`test/server/testServer.ts`](test/server/testServer.ts).

## Common commands

```bash
npm run dev            # run the desktop app
npm run build          # typecheck + build main/preload/renderer bundles
npm test               # run the engine + integration test suite (Vitest)
npm run test:e2e       # Playwright E2E over the real Electron app (needs a display)
npm run test:coverage  # tests with coverage
npm run typecheck      # tsc --noEmit
npm run lint           # eslint (zero-warning policy)
npm run format         # prettier --write
npm run ci             # format:check + lint + typecheck + test
npm run sbom           # generate CycloneDX sbom.json
npm run dist           # build installers (electron-builder) → dist/
npm run checksums      # write dist/SHA256SUMS-<os>.txt
```

Packaging and the release runbook (SBOM, checksums, signing decision, CI) are in
[RELEASE.md](RELEASE.md); changes are tracked in [CHANGELOG.md](CHANGELOG.md).

## What works today (first delivery)

Implemented and covered by the automated suite (138 unit/integration tests plus
a real-Electron Playwright E2E suite: a smoke check, a full click-through, and a
packaged-artifact verification). Run `npm test` for the current count.

- HTTP/1.1 proxying; HTTPS interception via CONNECT + per-host leaf certs signed
  by the locally-generated project CA (verified with a real TLS handshake).
- **HTTP/2 interception** — the MITM negotiates ALPN `h2` and terminates HTTP/2,
  translating requests to HTTP/1.1 upstream so it works against any origin
  (verified with real h2 GET/POST through the proxy).
- **WebSocket frame capture** — bidirectional RFC 6455 frames (masked client +
  unmasked server, fragmentation, control frames) are decoded and stored, not
  just the handshake.
- Interception: edit/forward/drop for requests and responses (HTTP/1.1 + HTTP/2).
- History in SQLite with search/filter; raw/headers/JSON/hex message views with
  sensitive-value masking.
- **Encryption at rest** — captured bodies (blob store + inline) and headers are
  AES-256-GCM encrypted under a per-project key held in OS secure storage.
- Encoder/decoder, hashes, gzip, timestamps, JWT inspection (decode-only).
- Request/response comparison (text, JSON-aware, byte-level).
- Repeater (manual resend) with timing, TLS info, redirect + cookie-jar controls.
- Modular passive scanner (11 built-in checks) with redacted evidence and
  false-positive suppression.
- Controlled, scope-gated, rate-limited request variation with pause/resume,
  emergency stop, and an audit trail.
- Versioned project export/import (including captured WebSocket frames);
  close/reopen without data loss.
- **Settings** screen for the engine limits, capture toggles, and redaction
  policy; project export, saved-request loading, cookie-jar inspection, exchange
  notes/tags, and suppression-rule management are all reachable from the UI.
- Capability-based extension SDK; extensions run in an **isolated child process**
  with an RPC bridge (plus an inner `vm`), with a harmless example extension.

### Known limitations

- **HTTP/3 / QUIC interception is NOT implemented.** HTTP/2 *is* intercepted (via
  ALPN `h2`, translated to HTTP/1.1 upstream); h3 is not, and clients typically
  fall back to h2/h1 when h3 fails. See
  [docs/certificate-management.md](docs/certificate-management.md).
- Extensions run in a **separate child process** (minimal env, bounded heap,
  IPC-only bridge) with an inner `vm` that blocks `require`/`process`; a full
  escape can't reach host-process memory. This is a strong boundary but **not a
  full OS sandbox** (seccomp/AppContainer) — only load extensions you trust. See
  [docs/extension-sdk.md](docs/extension-sdk.md).
- At-rest encryption covers message **content** (bodies + headers); operational
  metadata (host, URL, method, status, timing) is stored in the clear to keep
  history searchable — keep project folders on trusted storage. See
  [THREAT_MODEL.md](THREAT_MODEL.md).
- The desktop GUI is now covered by a Playwright click-through E2E over the real
  Electron app, in addition to the headless engine suite.

## Documentation

- [SECURITY.md](SECURITY.md) · [THREAT_MODEL.md](THREAT_MODEL.md) ·
  [ARCHITECTURE.md](ARCHITECTURE.md) · [CONTRIBUTING.md](CONTRIBUTING.md)
- [docs/authorization-and-scope.md](docs/authorization-and-scope.md)
- [docs/certificate-management.md](docs/certificate-management.md)
- [docs/project-format.md](docs/project-format.md)
- [docs/extension-sdk.md](docs/extension-sdk.md)
- [docs/testing.md](docs/testing.md)
- [docs/PLAN.md](docs/PLAN.md) · [docs/adr/](docs/adr/)

## License

Apache-2.0.
