# Intercepting-proxy capability matrix

TACNOC is an original, local-first workbench for authorized testing.
This matrix compares common intercepting-proxy **workflows**, not proprietary
implementations, branding, UI, or licensed features. "Implemented" means the
workflow is usable and engine-enforced today; it does not imply one-for-one
parity with any commercial product.

| Workflow family | Status | TACNOC today | Important remaining gap |
|---|---|---|---|
| Target / site map | Implemented | Captured origins and normalized paths; methods, statuses, MIME types, query-parameter names, counts, current-scope evaluation, latest-exchange inspector, Repeater handoff | No crawler or content discovery |
| HTTP proxy and history | Implemented | HTTP/1.1, HTTPS CONNECT MITM, HTTP/2 termination/translation, bounded capture, filtering, notes/tags, encrypted content storage | No HTTP/3/QUIC, upstream/SOCKS proxy chains, or invisible-proxy mode |
| Interception | Implemented | Request and response hold/edit/forward/drop with bounded bodies | No project-level match/replace rule engine |
| WebSockets | Partial | Handshake plus bidirectional frame capture and persistence | No editable WebSocket message repeater/interceptor |
| Repeater | Implemented | Raw manual resend, redirects, cookie jar, timing/TLS details, saved requests, history ingestion | No multi-request tab groups or parallel request race tooling |
| Intruder-style variation | Implemented, deliberately constrained | Sniper/battering-ram/pitchfork/cluster-bomb modes; lists/ranges/safe structural values; exact counts; response grep, named extraction, hashes/word/line counts; hard limits, scope, rate, audit, pause/stop | No bundled exploit, credential, destructive, or denial-of-service payload libraries; no recursive payload processors |
| Passive scanner | Implemented | Eleven modular checks, extension checks, redacted evidence, confidence/severity, dedupe, per-finding and rule suppression | No active vulnerability scanner |
| Sequencer / token analysis | Implemented | Offline text/hex/Base64/Base64url samples; collisions, byte and positional entropy, monobit bias, adjacent-byte correlation, compression, cautious assessment | No automated live token harvesting/generation loop; statistics do not prove unpredictability |
| Decoder | Implemented | URL/Base64/hex/HTML/gzip, hashes, timestamps, decode-only JWT inspection, extension transforms | No automatic multi-layer decoding pipeline |
| Comparer | Implemented | Text, JSON-aware, and byte diffs | No synchronized visual response renderer |
| Session handling | Partial | Repeater cookie jar, secure-cookie enforcement, cross-host credential stripping | No macro engine, login-state rules, or automatic session refresh |
| Findings / issue management | Implemented | Findings list, evidence/remediation, suppression, scanner-module inventory | No standardized report generator or external issue-tracker sync |
| Extensions | Implemented | Capability-based SDK in a bounded subprocess plus inner VM; checks, transforms, traffic, findings, UI registrations | Not compatible with third-party BApp/Montoya APIs; not a kernel sandbox |
| Collaborator / OAST | Not implemented | — | Requires an explicitly configured, researcher-controlled interaction service and strict project scoping |
| Browser | Not implemented | Works with an externally configured browser and manually trusted project CA | No embedded preconfigured browser/profile manager |
| Dashboard / task orchestration | Partial | Variation job progress, global emergency stop, immutable automation audit | No persistent multi-tool task dashboard or scheduled scans |

## Red-team prioritization

The highest-value next capabilities are:

1. **Active crawler + scanner orchestration** with an explicit per-project
   authorization acknowledgement, strict scope re-check before every request,
   request budgets, recursion/depth limits, per-host rate pools, and reproducible
   evidence. This should be built as an engine service, not as UI-only buttons.
2. **Proxy match/replace and session rules** with ordered rules, safe previews,
   secret-aware logging, and clear separation between manual traffic mutation and
   automated actions.
3. **WebSocket workbench** for editable frame replay and comparison, retaining
   direction/opcode/fragmentation fidelity and enforcing message-size bounds.
4. **Researcher-controlled OAST adapter** with no vendor default or telemetry,
   explicit endpoint/key configuration, scope-correlated tokens, polling limits,
   and full audit records.
5. **Reporting** that exports redacted findings, affected endpoints, evidence,
   remediation, scope/authorization reference, methodology, and QA status.

HTTP/3 is useful for coverage but is lower priority than the workflow gaps above:
most web-app findings are protocol-agnostic, while crawling, active verification,
session handling, and evidence quality directly affect assessment depth.
