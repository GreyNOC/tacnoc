# Changelog

All notable changes to GreyNOC Belcher are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and the project aims to follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.2.0] — 2026-07-17

### QA/QC pass — adversarial audit fixes

Findings from a multi-agent adversarial review of every engine and the full
renderer↔IPC↔engine wiring, each fixed with a regression test (suite grew from
119 to 138 tests).

#### Wired features that were exposed over IPC but unreachable in the UI

- **Settings** view: edit the engine config (listener host/port with a
  non-loopback warning, automation limits, capture/body limits, HTTP/2 and
  WebSocket capture toggles, redaction policy) plus project export and close.
  `setConfig` now applies redaction/repeater-limit changes immediately instead
  of silently requiring a project reopen.
- Repeater: load saved requests, and inspect/clear the cookie jar.
- History inspector: edit per-exchange notes and tags.
- Findings: create, list, and delete suppression **rules** (not just per-finding
  suppression).
- Scope view now re-syncs on external `scope-changed` events.

#### Correctness / security fixes

- Proxy no longer crashes/hangs on a malformed absolute-form request target
  (`new URL` guarded; upgrade handler destroys the socket on an unresolvable host).
- Secret store fails **closed**: a present-but-undecryptable CA key/DEK (e.g. a
  project copied to another OS user) now raises an error instead of regenerating
  over the key or silently dropping at-rest encryption.
- Suppression rules no longer mute *all* findings when only `host` (or nothing) is
  set; host is matched against the exchange host.
- `redactUrl` masks secrets in the URL **path**, not just the query string.
- Session `startProxy` no longer wedges the proxy after a failed bind.
- Repeater drops `Cookie`/`Authorization` on cross-host redirects; the cookie jar
  no longer replays `Secure` cookies over cleartext and detects hyphenated-epoch
  `Expires` deletions.
- Passive scanner: bounded gzip decompression (decompression-bomb guard); CORS
  check now flags reflected-Origin-with-credentials and `null`-origin-with-
  credentials (the actually-exploitable cases).
- Intercept mode fails loud instead of forwarding a silently-truncated body that
  exceeds the capture cap.
- Extension checks receive a **redacted** exchange (headers/URL/body), matching
  the sanitized `read-traffic` surface; `vm` in-context code generation disabled;
  child temp dir cleaned up on crash; overstated fs/network isolation claims in
  the SDK docs/API corrected.
- WebSocket frames are now included in project export/import.
- Migrations bump `user_version` inside the schema transaction (atomic).
- `htmlDecode` is a correct single-pass inverse of `htmlEncode` and no longer
  throws on out-of-range numeric character references.
- Scope host normalization strips all trailing dots; whole-value credential
  headers (`x-api-key`, …) mask independently of pattern scanning; variation
  pause/resume are audited and the documented absolute request ceiling is enforced.

#### Release / CI

- The release pipeline now runs the **mandatory packaged-artifact E2E** (it was
  documented as required but never executed); CI runs the real-Electron GUI E2E.

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

[Unreleased]: https://example.invalid/greynoc/belcher/compare/v0.2.0...HEAD
[0.2.0]: https://example.invalid/greynoc/belcher/compare/v0.1.0...v0.2.0
[0.1.0]: https://example.invalid/greynoc/belcher/releases/tag/v0.1.0
