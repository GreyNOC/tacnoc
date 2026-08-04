# Threat model

This document states what TACNOC defends against, what it does not, and
the trust boundaries a reviewer should audit. It is a living document.

## Assets

1. **Captured traffic** — requests/responses, which routinely contain cookies,
   authorization headers, tokens, and PII.
2. **The project CA private key** — signs leaf certs for TLS interception;
   whoever holds it can impersonate any HTTPS site to a client that trusts the CA.
3. **Project data at rest** — the SQLite DB and blob store on disk.
4. **The researcher's host and network** — must not be exposed by the tool.
5. **Authorization boundary** — the tool must not generate traffic against
   out-of-scope hosts.

## Trust boundaries

- **Captured bytes are untrusted input.** Malformed or hostile traffic must not
  crash the proxy, exhaust memory, or be executed. Mitigations: Node's
  parser + `clientError` handlers; bounded `BodyCollector`s with a hard body cap
  and spill-to-disk; the renderer never executes response HTML/JS (strict CSP,
  `contextIsolation`, `sandbox`, inert text/hex rendering only).
- **Renderer ⇄ engine.** The renderer is sandboxed and reaches the engine only
  through a preload `contextBridge` exposing two channels (`invoke`, `onEvent`).
  No Node, filesystem, or engine internals are exposed to the page.
- **Extensions.** Loaded into a dedicated **child process** (separate OS memory
  space; forked with a minimal environment, a bounded heap, no inherited stdio,
  and its own cwd) and reached only through a capability RPC bridge — the host
  and extension never share object references, so even a full escape cannot read
  the engine, session, secrets, or DB in the host process. Inside the child each
  extension is additionally evaluated in a `vm` with no `require`/`process`/
  `module` in scope. Only the capability-scoped `tacnoc` API is offered; elevated
  permissions (`read-traffic`, `findings`) require explicit user approval.
  **Residual caveat:** the child process still has Node built-ins, so this is a
  strong process boundary, not a full OS sandbox (seccomp/AppContainer/
  `sandbox_init`) — only load trusted extensions (see
  [docs/extension-sdk.md](docs/extension-sdk.md)).
- **The CA key.** Generated locally; stored via OS secure storage
  (`safeStorage` → DPAPI/Keychain/libsecret). Never transmitted. The app never
  edits the OS trust store; trusting the CA is a manual, warned user action.

## In scope (defended)

| Threat | Mitigation |
|---|---|
| Proxy exposed to the network | Binds `127.0.0.1` by default; non-loopback bind flagged in UI |
| Accidental automated hits on out-of-scope hosts | Fail-closed scope enforced in the engine; per-request re-check in variation; refusal to start out-of-scope jobs |
| Runaway automated traffic | Token-bucket rate, concurrency cap, per-job max, timeouts; global emergency stop |
| Secret leakage into logs/exports/findings | Central `Redactor`; structured logs redact; findings evidence re-redacted; no network log sink |
| Accidental credential disclosure in UI/exports | `detectSensitive` warns; body/headers masked until explicitly revealed |
| Malformed traffic crashing the tool | Parser robustness + bounded buffers; tests for malformed input |
| Data exfiltration by the tool itself | No telemetry, analytics, or update check; local-only logging with no network sink. **Exception: the opt-in AI mesh** — see the row below |
| Captured traffic sent to a model provider by the AI mesh | Off by default; refuses to start without a per-project egress acknowledgement (audited); optional best-effort redaction of cookies/auth/secret patterns before send; engagement-folder reads gated by a second switch; hunt-memory recall scoped to the open engagement. **Residual risk: when enabled, captured content and engagement documents leave the machine — this is the operator's explicit choice, not a defended boundary.** |
| Memory exhaustion from huge bodies | Configurable max body size; stream-to-disk; renderer view cap |
| CA key disclosure | OS secure storage; file fallback clearly marked non-secure |
| Captured content readable off-disk | Bodies + headers AES-256-GCM encrypted at rest under a per-project key in OS secure storage (GCM detects tampering); blob ids are keyed HMACs, not plaintext hashes, so there is no known-plaintext confirmation oracle |
| Proxy DoS via client-controlled TLS SNI | Per-host leaf-cert cache is LRU-bounded so unique SNIs cannot exhaust memory/CPU |
| Extension reaching host internals | Extensions run in a dedicated child PROCESS (scrubbed env, bounded heap) with an IPC-only bridge (no shared references) + inner `vm`; a full escape reaches only the child, not the host engine/secrets/DB/CA; a hung extension is bounded by an RPC timeout; the host fails closed (drops all extension capabilities) if the child dies |

## Out of scope / residual risks

- **HTTP/3 / QUIC interception** is not implemented. HTTP/2 *is* intercepted
  (ALPN `h2`, translated to HTTP/1.1 upstream). If a client insists on h3 and
  refuses to fall back, that traffic is not intercepted.
- **Extension isolation** is a separate OS process + inner `vm`, which prevents
  access to host-process memory/objects, but the child still has Node built-ins,
  so it is not a full OS sandbox. A malicious extension is treated as trusted code
  the user chose to run; OS-sandbox primitives (seccomp/AppContainer/
  `sandbox_init`) are future work.
- **At-rest encryption covers message content, not metadata.** Bodies (blob store
  + inline) and request/response headers are AES-256-GCM encrypted under a
  per-project data key held in OS secure storage. Operational metadata (host,
  URL, method, status, MIME, timing, tags) is stored in the clear so history
  stays searchable — and URLs can themselves contain secrets. Treat a project
  folder as sensitive and keep it on trusted/encrypted storage. The project
  export is deliberately plaintext for portability.
- **A researcher trusting the CA in their everyday browser profile** broadens
  their exposure. The docs and UI steer toward a dedicated testing profile and
  removing trust afterward.
- **Host compromise** is out of scope: if the researcher's machine is already
  compromised, the tool cannot protect captured data or the CA key.

## Explicitly excluded capabilities

By design the tool does **not** implement stealth, persistence, malware
delivery, phishing, credential stuffing, denial-of-service, destructive
payloads, CAPTCHA/bot-detection bypass, or evasion of monitoring. The variation
engine ships only benign structural payloads and refuses to generate traffic
outside project scope.

## Planned hardening

- Extend at-rest encryption to (optionally) cover URL/metadata columns, trading
  some search functionality for confidentiality.
- OS-sandbox primitives (seccomp-bpf / AppContainer / `sandbox_init`) on top of
  the current separate-process + `vm` extension isolation.
- HTTP/3 / QUIC interception.
