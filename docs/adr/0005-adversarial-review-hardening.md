# ADR 0005 — Adversarial-review hardening

- Status: Accepted
- Date: 2026-07-16

## Context

After the Phase-2 hardening (ADR 0004), a multi-agent adversarial review fanned
out reviewers to *refute* the five fixes across correctness and security lenses,
then verified each finding with an independent skeptic. It confirmed a set of
real defects, all now fixed with regression tests.

## Confirmed defects and fixes

1. **Response-body poisoning on mid-stream upstream error** (high, correctness).
   On a mid-stream upstream reset/timeout after response headers were sent, the
   proxy appended `Bad Gateway (proxy upstream error)` into the in-flight body,
   which the client read as a *complete* 200 (Content-Length was dropped). Fix:
   once the client response has started, ABORT it (`clientRes.destroy`) on any
   upstream error/timeout — in both the `originReq.on('error')` handler and the
   `pumpResponse` catch — never append text. Regression: `proxy.test.ts`
   (`/slow-body` + short upstream timeout).

2. **Unbounded leaf-cert cache via client SNI** (high, DoS). The MITM SNICallback
   fed attacker-controlled TLS SNI into a never-evicted cache, each miss
   synchronously RSA-3072-signing a leaf. Fix: LRU-bound the cache (1024 entries)
   in `CertificateAuthority`.

3. **Blob ids were an unsalted plaintext SHA-256** (medium, confidentiality). The
   blob filename leaked a known-plaintext confirmation + equality oracle against
   an off-host folder copy, contradicting the at-rest guarantee. Fix: derive blob
   ids via HMAC-SHA256 under a DEK-derived subkey (`ContentCipher.contentId`),
   preserving in-project dedup while revealing nothing to a keyless attacker.
   Regression: `crypto.test.ts`, `storage.test.ts`.

4. **Unbounded WebSocket handshake buffer** (medium, DoS). A peer that never sent
   the header terminator grew the buffer without limit. Fix: cap at 64 KiB and
   tear down.

5. **`export()` dropped exchanges beyond 2000** (medium, data loss). Fix: page
   through all rows. Regression: `storage.test.ts`.

6. **WS retrieval limit (2000) below the capture ceiling (5000)** silently hid
   stored frames. Fix: raise the repo default above the capture ceiling.

7. **Orphaned extension registrations on a failed `activate()`** (low). A check
   registered before an `activate` throw stayed live and ran on later scans. Fix:
   roll back all of a failed extension's registrations in the worker. Regression:
   `sdk.test.ts`.

8. **`createFinding()` dropped when called outside a scanner check** (low). It was
   buffered and only returned from `runChecks`. Fix: deliver it immediately as a
   worker→host message routed to the findings sink.

9. **Hung worker could block the scan pipeline** (low). A malicious extension's
   infinite loop is uninterruptible in the worker. Fix: host-side RPC timeout so
   a stuck call rejects instead of blocking.

10. **Abusive 64-bit WebSocket frame length** (low). Added a validity/sanity
    bound; the parser fails safe (stops capturing) while the raw tunnel continues.
    Regression: `wsFrame.test.ts`.

## Not changed (documented residual risk)

- The **inner `vm`** used for extensions is escapable via prototype-chain tricks
  on objects passed into the context. This was never claimed as the boundary: the
  boundary is the **worker thread** (separate heap, message-only bridge), which a
  `vm` escape cannot cross to reach host objects/secrets. A worker still has Node
  built-ins, so this remains "trusted-extensions-only," documented in
  THREAT_MODEL.md and docs/extension-sdk.md. An OS-sandboxed subprocess is the
  planned next step.
