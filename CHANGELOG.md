# Changelog

All notable changes to GreyNOC Belcher are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and the project aims to follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] — 2026-07-16

First delivery: a working, tested intercepting-proxy workbench for authorized
web-application security research.

### Added — Phase 1 (foundation)

- Electron desktop shell with project create/open and versioned export/import.
- Local intercepting proxy (loopback by default) with HTTP/1.1 support and
  HTTPS interception via CONNECT + per-host leaf certs from a locally-generated
  project CA (CA key held in OS secure storage).
- Interception: edit / forward / drop for requests and responses.
- HTTP history in SQLite (WASM backend) with search/filter and raw / headers /
  JSON / XML / form / hex message views with sensitive-value masking.
- Fail-closed project scope (exact / subdomain / wildcard hosts, ports, schemes,
  path patterns) enforced in the engine.

### Added — Phase 2 (workbench)

- Repeater with timing/size, redirect + cookie-jar controls, and TLS info.
- Encoder/decoder (URL, Base64, hex, HTML entities, gzip, hashes, timestamps)
  and decode-only JWT inspection.
- Request/response comparison (text, JSON-aware, byte-level).

### Added — Phase 3 (passive analysis)

- Modular passive scanner (11 built-in checks) with severity/confidence,
  redacted evidence, remediation, and false-positive suppression.

### Added — Phase 4 (controlled variation)

- Scope-gated, rate-limited request-variation engine (sniper / battering-ram /
  pitchfork / cluster-bomb) with exact pre-run count, pause/resume, global
  emergency stop, and an audit trail. Only benign structural payloads.

### Added — Phase 5 (extensions)

- Capability-based extension SDK with a harmless example extension.

### Added — Phase 2 hardening (see ADR 0004)

- **HTTP/2 interception** (ALPN h2, translated to HTTP/1.1 upstream).
- **WebSocket frame capture** (bidirectional RFC 6455, encrypted at rest).
- **Encryption at rest** for captured bodies + headers (AES-256-GCM, per-project
  key in OS secure storage).
- **Process-isolated extensions** (dedicated child process, minimal env, bounded
  heap, IPC-only capability bridge + inner `vm`), replacing the in-process `vm`.
- Playwright end-to-end coverage of the real Electron app.

### Security — adversarial-review hardening (ADR 0005)

- Abort (don't poison) the client response on mid-stream upstream errors.
- LRU-bound the per-host leaf-cert cache (client-SNI DoS).
- Keyed-HMAC blob ids (no known-plaintext oracle on an off-host folder copy).
- Cap the WebSocket handshake buffer; page `export()` through all exchanges; raise
  the WS retrieval limit above the capture ceiling; roll back a failed
  extension's registrations; RPC timeout for a hung extension.

### Security — subprocess extension host + second review (ADR 0006)

- **Process-isolated extension host**: extensions run in a dedicated child
  process (scrubbed env, bounded heap, IPC-only bridge, inner `vm`) instead of a
  worker thread — an escape can no longer reach the host's engine, secrets, DB,
  or CA.
- Fail-closed on child crash (drop all extension capabilities + loud error);
  `dispose()` wired to app quit terminates the child and its temp bootstrap dir
  (no per-launch leak).
- Second adversarial-review round hardening: single-settle `ready` (no unhandled
  rejection), delta-scoped activate rollback + duplicate-id guard, per-check
  `structuredClone` of the exchange, malformed-IPC/finding survival with
  defensive field coercion, signal-kill-safe `terminate()`.
- Release: per-OS `SHA256SUMS-<os>.txt` (no upload collision); SBOM generated
  once; checksum manifest narrowed to distributed installers/archives only.

### Packaging & release (ADR 0004/M10)

- electron-builder config (WASM `asarUnpack`, example extension in resources),
  CycloneDX SBOM, SHA-256 checksums, CI + release GitHub Actions (release drafts,
  never auto-publishes), signing-ready via CI secrets.

### Security decisions

- Loopback-only default; no telemetry/external calls; secret redaction in logs
  and findings; warn-before-reveal for credentials; explicit, warned, manual CA
  trust flow (the app never edits OS trust); no stealth/persistence/DoS/etc.

### Known limitations

- HTTP/3 / QUIC interception not implemented (clients fall back to h2/h1).
- Extension isolation is a dedicated child process + inner `vm` (a materially
  stronger boundary than a worker thread, but not yet an OS-level sandbox such as
  seccomp / AppContainer / `sandbox-exec`).
- At-rest encryption covers content, not searchable metadata.

[Unreleased]: https://example.invalid/greynoc/belcher/compare/v0.1.0...HEAD
[0.1.0]: https://example.invalid/greynoc/belcher/releases/tag/v0.1.0
