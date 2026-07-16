# Architecture

GreyNOC Belcher is split into a **UI-independent engine** and an **Electron
desktop shell**. The engine has no Electron dependency and is fully testable
headlessly; the shell wires it to a React UI over a narrow IPC boundary.

```
┌──────────────────────────── Electron ────────────────────────────┐
│  Renderer (React/TS, sandboxed, contextIsolation)                 │
│    window.belcher.invoke(method, …args)   ── belcher:invoke ──►   │
│    window.belcher.onEvent(cb)             ◄── belcher:event  ──    │
│                         │ preload (contextBridge, CJS)            │
│  Main process           ▼                                          │
│    ipc.ts  ──►  BelcherSession (engine facade)                     │
│    ElectronSecretStore (safeStorage / DPAPI·Keychain·libsecret)    │
└───────────────────────────────┬───────────────────────────────────┘
                                 │
┌──────────────────────────── Engine (src/engine) ──────────────────┐
│  proxy/        ProxyServer, Interceptor, proxyUtil                 │
│  ca/           CertificateAuthority, SecretStore                   │
│  storage/      Database (WASM SQLite), migrations, BlobStore,      │
│                BodyCollector, History/Meta/Findings/Audit repos    │
│  scope/        evaluateScope (the safety gate)                     │
│  scanner/      PassiveScanner + modular checks                     │
│  repeater/     Repeater, CookieJar, rawHttp                        │
│  variation/    VariationEngine, payloads (safe-only)              │
│  transforms/   codec (encode/decode/hash/jwt)                     │
│  compare/      text / JSON / byte diffs                            │
│  redaction/    Redactor (+ detectSensitive)                       │
│  net/ util/    sendRaw, TokenBucket, Semaphore                    │
│  project/      ProjectStore (open/create/export/import)           │
│  session.ts    BelcherSession — wires it all together             │
└──────────────────────────── sdk/ (extension host) ───────────────┘
                shared/ — types used by engine, main, and renderer
```

## Module boundaries (documented interfaces)

- **Canonical message model** (`shared/model.ts`) — preserves *both* raw bytes
  and a parsed representation, keeping header **order, casing, and duplicates**.
  Bodies are `inline` (small) or a `blobId` reference (large). We never silently
  lose or mutate captured bytes.
- **Storage** (`storage/database.ts`) — everything persists through one thin
  `Database` wrapper over WASM SQLite, so the backend is swappable (ADR 0003).
  Schema changes are additive, versioned migrations (`PRAGMA user_version`).
- **Scope** (`scope/scope.ts`) — a pure evaluator. Automated tooling calls it
  before acting; it fails closed.
- **Scanner** (`scanner/`) — each `ScannerCheck` is an isolated module; the
  runner guards every check so one failure can't crash a scan.
- **Extension SDK** (`sdk/`) — a capability-scoped API; the host injects only
  the methods a manifest is granted.

## The capture pipeline

```
client ⇄ ProxyServer ⇄ origin
              │  (tee)
              ▼
        BodyCollector ──► BlobStore (spill) / inline
              │
        HttpExchange ──► BelcherSession.ingest():
              ├─ history.insert()            (persist)
              ├─ emit 'exchange' (summary)   (live table)
              ├─ extHost.dispatchTraffic()   (sanitized to extensions)
              └─ PassiveScanner.scan() ──► findings.upsert() ──► emit 'finding'
```

Request/response bodies flow through **bounded** `BodyCollector`s: small bodies
stay in memory, larger ones stream to the content-addressed `BlobStore`, and
capture stops at a hard cap (marking the body truncated) while the proxy still
forwards every byte to the peer.

## TLS interception

`CONNECT host:port` is answered with `200`, then the client socket is wrapped in
a `tls.TLSSocket` presenting a per-host leaf certificate signed by the project
CA. The decrypted stream is handed to an inner `http.Server`, so HTTP and
decrypted HTTPS share one request path. ALPN offers only `http/1.1` (HTTP/2
downgrade). See [docs/certificate-management.md](docs/certificate-management.md).

## Robustness posture

All captured bytes are treated as untrusted. Node's HTTP parser is the
robustness boundary for malformed traffic (it rejects rather than crashes);
`clientError` handlers keep the proxy alive. Response content is **never**
executed or rendered — the renderer displays it as inert text/hex under a strict
CSP with `contextIsolation` and `sandbox` enabled. Large bodies stream to disk;
buffers are bounded; the renderer shows at most a few MiB per body.

## Threading / concurrency

The engine is single-process, event-loop concurrent. Automated request
generation is bounded by a token-bucket rate limiter and a concurrency
semaphore. Interception uses promise-gated holds resolved by the UI.

See [docs/adr/](docs/adr/) for the load-bearing decisions.
