# ADR 0004 — Phase-2 hardening: HTTP/2, WebSocket frames, at-rest encryption, worker-isolated extensions

- Status: Accepted
- Date: 2026-07-16

## Context

The first delivery documented five limitations. This ADR records how each was
resolved and the trade-offs taken.

## Decisions

### 1. HTTP/2 interception via a secure server + h2→h1 translation

The MITM is now a single `http2.createSecureServer({ allowHTTP1: true })` that
terminates TLS with per-host leaf certs (SNI), negotiates ALPN `h2`/`http/1.1`,
and delivers **both** protocols through the http1-compatible `'request'` event
(WebSocket via `'upgrade'`). HTTP/2 requests are translated to HTTP/1.1 upstream
(pseudo-headers stripped, `Host` synthesized from `:authority`).

- Rejected: feeding a manually-terminated `TLSSocket` to `http2.createServer()`
  (h2c) — empirically it never produced a stream. `createSecureServer` doing its
  own TLS is the reliable path (verified with real h2/http1/WS clients).
- Consequence: one request path handles h2 + http1; works against any origin
  regardless of the origin's protocol. HTTP/2's mandatory lowercase header names
  mean casing is normalized on the h2 leg (protocol behavior, not a proxy defect).
- HTTP/3/QUIC remains out of scope; clients fall back to h2/h1.

### 2. WebSocket frame capture

A streaming RFC 6455 parser (`wsFrame.ts`) observes both tunnel directions
(masked client + unmasked server), reassembles fragmented messages, surfaces
control frames, and stays wire-aligned even for oversized frames it declines to
fully buffer. Messages persist in a new `ws_messages` table (migration v2),
payloads encrypted at rest, bounded by count/size.

### 3. Encryption at rest (content, not metadata)

A per-project 32-byte data key lives in the SecretStore (OS secure storage).
`ContentCipher` (AES-256-GCM) encrypts blob-store bodies, inline body BLOBs, and
request/response header JSON. Metadata columns (host, URL, method, status, MIME,
timing, tags) stay plaintext so history remains searchable — a deliberate
confidentiality/functionality trade-off, documented in THREAT_MODEL.md. GCM
provides tamper detection; a missing key makes content unreadable.

### 4. Worker-isolated extensions

Extensions moved from an in-process `vm` to a dedicated **worker thread** with a
capability RPC bridge (structured-clone messages only; no shared references),
plus an inner `vm` for defense in depth. Passive checks/transforms run in the
worker and are invoked via async RPC. This prevents access to host memory/objects
even on a `vm` escape. Residual risk: a worker still has Node built-ins, so this
is a strong layered boundary, not an OS-level sandbox.

### 5. GUI end-to-end coverage

A Playwright click-through (`test/e2e/full.spec.ts`) drives the real Electron app
through every view against the local test server, including real proxied HTTPS
capture, findings, the encoder, and loading the worker-isolated example extension.

## Consequences

- Verified end-to-end in the real Electron runtime (Node 20) as well as the
  headless Node suite.
- The h2 secure-server refactor also removed ~200 lines of bespoke h2 code.
