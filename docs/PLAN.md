# TACNOC — Milestone Plan

Original work. Inspired by the *workflow* of intercepting-proxy tooling; no
proprietary code, UI, branding, or licensed assets are copied.

## Guiding constraints (non-negotiable)

- Proxy binds `127.0.0.1` by default.
- No automated request generation against a host until it is in project **scope**.
- Global **emergency stop** halts all automated work.
- **Audit log** records every automated action.
- Secrets redacted in logs and exports; warn before revealing credentials.
- CA key protected by OS secure storage; explicit warning before trusting a CA.
- No stealth/persistence/malware/credential-stuffing/DoS/CAPTCHA-bypass/evasion.
- Never send captured traffic to telemetry, analytics, or external AI services.

## Milestones

| ID | Milestone | Status |
|----|-----------|--------|
| M0 | Scaffold, configs, ADRs, plan | in progress |
| M1 | Core engine primitives: canonical message model, scope, redaction, limits, logging | planned |
| M2 | Local TLS CA + secret-storage abstraction | planned |
| M3 | SQLite storage + migrations + content-addressed blob store + repos | planned |
| M4 | Proxy engine: HTTP/1.1, CONNECT MITM, intercept (edit/forward/drop), capture, WS handshake | planned |
| M5 | Workbench: encoder/decoder, repeater, comparison | planned |
| M6 | Passive scanner + controlled variation engine (rate-limited, scoped, emergency stop) | planned |
| M7 | Local safe test server + Vitest/integration suite | planned |
| M8 | Electron shell + preload IPC + React UI | planned |
| M9 | Extension SDK + example extension + full docs | planned |

Phases from the brief map onto milestones: Phase 1 → M1–M4, M7, M8; Phase 2 →
M5; Phase 3 → M6 (scanner); Phase 4 → M6 (variation); Phase 5 → M9.

## Assumptions

1. ~~Electron's bundled Node exposes `node:sqlite`.~~ **Resolved (ADR 0003):**
   it did NOT in the then-current Electron 33 (Node 20.18). Storage was switched
   to `node-sqlite3-wasm`, verified to run identically under the test-runner Node
   and Electron's Node, so tests verify what ships. The app now pins Electron 43
   (Node 22.x line) and retains the WASM backend.
2. Node's HTTP parser (via `http.Server`/`http.request`) is the robustness
   boundary for malformed traffic: it rejects truly malformed messages rather
   than crashing. We preserve fidelity via `rawHeaders` + captured body and a
   reconstructed raw view, rather than re-implementing an HTTP parser.
3. HTTP/2 and QUIC/HTTP/3 interception are **out of scope for the first
   delivery** and are documented as such; HTTP/2 origins are handled by not
   negotiating h2 on the MITM side (ALPN downgraded to http/1.1). See
   `docs/certificate-management.md`.
4. The primary verification surface in this environment is the headless engine +
   integration tests. GUI flows are implemented for real but exercised by a
   human per the Definition of Done.

## Major risks & mitigations

- **TLS MITM correctness** → integration test decrypts real proxied HTTPS using
  a temporary test CA and asserts capture fidelity.
- **Fidelity loss / byte mutation** → canonical model keeps raw bytes + parsed
  views; tests assert header casing/duplication and chunked/compressed/binary
  round-trips.
- **Resource exhaustion from hostile traffic** → bounded buffers, configurable
  max body size, spill-to-disk, connection caps.
- **Accidental out-of-scope automation** → scope gate enforced in the engine
  (not just UI); tests include scope-bypass attempts.
- **Secret leakage** → central redactor; tests assert cookies/authorization/
  token formats are masked in logs and exports.
- **node:sqlite experimental churn** → isolated behind `Database`; migrations
  are explicit and versioned.
