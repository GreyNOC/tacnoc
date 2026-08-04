# Changelog

All notable changes to TACNOC are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and the project aims to follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

_Nothing yet._

## [0.5.0] — 2026-08-04

### Added — open a folder that existed before TACNOC did

Operators do not start with an empty project. They start with a folder that
already holds the work: the program policy, an ENGAGEMENT.md, last quarter's
report, `recon/` full of subdomain dumps, a scratch `_notes.md`. Requiring a
TACNOC project to exist before any of that could be used had it backwards.

- **Open hunt folder** on the welcome screen adopts a folder as it stands. It
  creates the project inside that folder, points the engagement folder at it,
  reads what is there, and says which files carry the scope — no second step to
  re-point the workspace at its own parent. Picking the folder IS the egress
  decision, the button says so, and the adoption is written to the audit log
  with what the folder exposed.
- **Document scan.** A deterministic classifier sorts a folder into scope,
  engagement, report, recon, notes, and other, and ranks it by relevance to
  planning. Filename is a weak signal that decides READ ORDER; content decides
  what a file IS, so scope written in a `README.md` is still found and a file of
  200 hostnames is recon whatever it is called. A document that states what is
  in or out of scope is classified as scope outright — that is the class whose
  misfiling costs the most. Shown in Engagement, and available to the mesh.
- **Nothing is authorized by being read.** The scan ranks and explains; it never
  adds a rule. Scope still comes from the proposal card and the operator still
  ticks each host.

Measured on a real 342-file engagement folder: 120 read within the budget, every
scope-bearing document in the top twelve, 255 recon files sorted away from them.

## [0.4.3] — 2026-08-04

### Fixed — a project created by one build could not be opened by another

- **The app had no stable identity, and that made projects unopenable.** Electron
  derives the userData directory from the app name, which it resolved from however
  the process was started: the package name under `npm run dev`, "Electron" under a
  bare `electron out/main/index.js`, and the electron-builder productName when
  packaged. `safeStorage` keeps its master key in `<userData>/Local State`, so each
  identity sealed project secrets under a different key — a project created in dev
  simply could not be opened by the release build. In a tool whose value is the
  engagement evidence it retains, that is a data-availability defect. The main
  process now pins `app.setName('TACNOC')` before anything reads userData.
- **The error blamed the wrong thing.** It said the project was "sealed by a
  different OS user account or machine", sending the operator to look at their
  Windows profile for a problem that was really the launcher. It now names the
  running identity and its userData directory, and says to check for sibling
  directories first.
- **Added `scripts/reseal-project-secrets.mjs`** to migrate projects already in
  that state. It copies the secret store aside, decrypts under the old identity and
  re-encrypts under the current one in two Electron processes, and verifies every
  secret round-trips before it is done — restoring the original if not. The
  plaintext crosses a one-shot loopback socket, never a temp file or an environment
  variable: it is a CA private key, and neither the disk nor the process table is an
  acceptable place to park one.

## [0.4.2] — 2026-08-04

### Fixed — findings from the pre-release adversarial review

- **The consent figure understated what egresses.** The suggested-folder document
  count was measured two levels deep while the workspace reader walks eight, so the
  operator agreed to a smaller number than the run actually sends. The preview now
  walks at the depth the reader uses.
- **A declined recon turn dropped the preflight halt.** Recon stops a run by
  answering `BLOCKED:`; substituting the engine briefing for a declined turn lost
  that, and a run could test an engagement preflight had already called not-ready
  with nobody having reviewed it. The briefing now carries the halt itself — the
  engine knows the blockers and does not need a model to decide this one.
- **A declined reporting turn produced a blank report and still finished `done`.**
  A run that had sent real traffic presented as a completed engagement with an
  empty report. It now states that no report was written, names every declined
  role, and returns the unreviewed round-by-round analysis rather than losing it.
- **Emergency stop could be missed while the briefing was being built.** The
  awaited gap had no abort check, so a stop landing inside it was not seen until
  the next role had already been dispatched.
- **Switching engagement folders left the scope card showing its old result.** The
  proposal was never re-read, so clicking the button meant to find your scope left
  the card still reporting nothing found, relabelled with the new path.
- **The suggestion banner rendered unstyled** — it used `banner warn`, and neither
  class exists in the stylesheet.

### Fixed — opening a hunt folder, and finding the scope inside it

Three separate defects that all presented to the operator as "the scope gate is
closed" when the gate was doing exactly what it should. The gate is unchanged.

- **Picking the hunt folder failed with `ENOENT ... belcher.db`.** Projects
  normally live *inside* the hunt folder (`TiffanyCo/Tiffany.tacnocproj`), so
  pointing the chooser at `TiffanyCo` is the natural thing to do. It failed by
  naming an internal file the operator has no reason to know. Opening now
  resolves a project nested one level down, names every candidate when a folder
  holds more than one, and otherwise says what is actually wrong.
- **The engagement folder defaulted to a directory with nothing in it.** The
  default root is the project directory, which holds the database and no
  documents — while every scope document sits one level up. The scope reader
  then correctly reported "no readable documents" about a folder the operator
  never put anything in. Preflight now detects this and names the parent, with a
  one-click switch in Engagement. It only ever *suggests*: widening what leaves
  the machine is the operator's call, made once, in the open.
- **`ca.pem` counted as an engagement document.** Every project directory has
  one, so an empty project folder reported "1 document(s)" — which read as a
  folder with material in it, and suppressed the hint above. The CA has its own
  surface; it is not engagement material, and is no longer served by the
  workspace reader.

### Fixed — a declined model turn no longer throws the run away

- **A refusal on the recon turn aborted the entire run.** The engine had already
  computed the readiness report, the enforced scope, the engagement folder
  listing, and the ranked attack surface — none of which needs a model — and all
  of it was discarded. A declined recon or planner turn now continues on that
  engine-built briefing. The decline is recorded as a step, carried into the
  reporter's prompt, and stated in the report's coverage: the run is never
  presented as complete when a role did not run.


## [0.4.1] — 2026-08-04

### Fixed — scope gate wiring

- **A `*.host` line from a policy produced a rule that matched only ONE label.**
  TACNOC's glob gives `*` the meaning "exactly one label", so a policy listing
  `*.example.com` became a rule that matched `api.example.com` and silently
  refused `api.eu.example.com` — the operator believing a host was in scope
  that the gate rejected. Proposals now translate to `**.host` (one or more
  labels) and are verified against the real evaluator. The apex is deliberately
  NOT added: a policy listing only `*.example.com` has not authorized
  `example.com`, and erring toward refusing costs a moment where erring toward
  permitting is an unauthorized request.
- **`propose_scope_from_workspace` ignored the workspace-access switch.** It sat
  outside the gate, so the mesh could read the engagement folder — and egress
  its host names and evidence lines — with folder access turned off. It is now
  gated with the rest of the workspace tools.
- **The manual Add-rule form defaulted to `subdomain` matching.** Typing an apex
  host silently put every subdomain at any depth in scope — the one error
  direction that *permits* rather than refuses. It now defaults to `exact`;
  widening is a dropdown away and should be deliberate.
- **The mesh start guard counted include rules without checking `enabled`.** A
  project whose rules were all switched off passed the guard, started a run, and
  had every request refused — provider tokens spent rediscovering what the guard
  already knew.
- **The API-key error masked the empty-scope error.** Scope is checked first
  now: it is the safety gate, the likelier thing missing on a fresh engagement,
  and the one fixable in a click. The refusal names the hosts your folder
  contains rather than telling you to go add some.
- **Preflight dropped ambiguous folder hosts.** A hunt folder is usually a bare
  asset list with no "In scope" heading, so every host landed in `unclear` and
  preflight reported nothing — about a folder that plainly named the targets.
  Ambiguous candidates are now reported too; the operator still ticks each one.
- Rule construction moved out of the React view into the engine
  (`scopeRulesFromProposal`), where it is tested against `evaluateScope`. It
  decides what the safety gate permits, so it should not have been eyeballed
  inside a component.

### Added

- The Engagement view now says what it is doing while reading the folder —
  which directory it is searching, how many documents it read, and how many
  hosts were in scope, excluded, or unclear. A folder that cannot be read
  reports the error instead of silently showing nothing, which was
  indistinguishable from "your folder has no scope in it".
- The Scope view's fail-closed banner points at Engagement → Proposed scope
  when the include list is empty, so the feature is discoverable from the
  screen where the problem is actually noticed.

## [0.4.0] — 2026-08-03

### Added

- **AI mesh — the first feature in TACNOC that sends data off the machine.**
  A multi-agent layer (recon → planner → attacker → analyst → reporter) drives
  the existing engine primitives to work an authorized engagement, using the
  Anthropic API.

  **Read this before enabling it:** when the mesh runs, **captured request and
  response content — including any secrets, cookies, and PII it contains — and
  the documents in the engagement folder are sent to the configured model
  provider.** Everything else in TACNOC remains local.

  It is bounded by the controls that already existed and some new ones: disabled
  by default; refuses to start without a per-project **egress acknowledgement**
  that is written to the audit log; optional best-effort redaction of cookies,
  authorization headers, and secret patterns before send; the fail-closed scope
  gate; the rate limiter; a per-run active-request budget; the audit log; and
  emergency stop. Engagement-folder reads and certificate operations are each
  behind their own switch, and certificate operations are off by default. The
  provider API key is held app-wide in OS secure storage, is never sent to the
  renderer, and is never written to logs, the audit trail, or hunt memory.

  If your rules of engagement forbid third-party processing of captured data,
  leave the mesh disabled. See
  [docs/engagement-and-hunting.md](docs/engagement-and-hunting.md).
- **Scope read out of the engagement folder.** Hitting "scope is fail-closed,
  add hosts" while the program policy sits unread in the engagement folder is a
  bad experience and an easy place to mistype a hostname. TACNOC now extracts
  candidate hosts from those documents — in-scope, out-of-scope, and ambiguous —
  each with the file and line it came from, and offers a checklist to add them.
  It **proposes only**: a document is a claim about authorization, not
  authorization, so nothing is written to scope without the operator ticking it.
  Hosts the documents mark out-of-scope are never proposed as includes and are
  added as exclusions instead, a host seen both ways resolves to excluded, and
  the bounty platform's own domains are never proposed. The empty-scope preflight
  blocker now names what it found instead of just saying the scope is empty.
- **Engagement layer** — the mechanical parts of a bug-bounty engagement, made
  enforceable. A per-project **engagement profile** records the program,
  researcher handle, authorization reference, a required `User-Agent`, and any
  identity headers the program mandates; when enforcement is on, the Repeater
  and the Variation engine rewrite every request they generate to carry them,
  preserving header order and collapsing duplicates. A `CR`/`LF` in a value is
  refused rather than sanitized — that is header injection, not a typo. See
  [docs/engagement-and-hunting.md](docs/engagement-and-hunting.md).
- **Preflight readiness report** — one graded answer to "is this engagement
  ready to test?", grounded in evidence rather than configuration: a missing
  authorization reference, an empty scope, an expired CA, or a non-loopback
  proxy bind are blockers; a CA the test browser has clearly never trusted
  (traffic captured, zero decrypted HTTPS exchanges) is a warning.
- **Engagement folder** — a sandboxed, read-only workspace the AI reads before
  planning: program policy, scope documents, prior reports, notes. Path
  traversal, absolute paths, and symlinks pointing out are refused; the
  project's own database, blobs, and secret store are denied at every depth;
  size, depth, and entry counts are bounded; binaries are refused rather than
  returned as mojibake.
- **Certificate lifecycle** — the project CA can be issued (rotated) and revoked
  from the app, both audited with a reason and a persisted history. Revoking
  turns TLS interception off: `CONNECT` becomes an unread pass-through tunnel
  until a new CA is issued. The proxy picks up either change on the next
  `CONNECT`, without a restart. No OS trust store is ever touched.
- **Proof-of-exploit gate** — `prove_finding` takes a control and a test
  exchange and the *engine* grades the differential from the captured bytes:
  `confirmed`, `refuted`, or `inconclusive`. The mesh cannot mark its own work
  proven, and a second changed variable, a `429`, or a `5xx` is raised as a
  caveat rather than quietly confirmed.
- **Hunt memory** — local, app-global, append-only outcomes keyed by *path
  shape* (`/api/orders/{id}`), so what one engagement settled is available to
  the next and to targets with the same route shape. Advisory only: it reorders
  attention, and can never confirm a finding or place a host in scope. Notes are
  secret-redacted on write.
- **Attack-surface ranking** — deterministic, offline scoring of in-scope
  endpoints by the defect class each most likely hides (identifiers and
  state-changing methods → access control, URL-shaped parameters → SSRF, and so
  on), with reasons. Adapted from GreyIQ's BugHunter hunt brain; it only
  reorders work and never adds a target or a finding.
- **Recon role in the AI mesh**, running before the planner and reviewing the
  engagement folder, the program's rules, scope, certificate state, the ranked
  surface, and prior-hunt history. A preflight blocker stops the run there
  instead of producing a plan for an engagement that cannot proceed.

### Packaging

- **`npm run dist:linux`** (`scripts/package-linux.mjs`) produces
  `TACNOC-<version>-linux-x64.tar.gz` — extract and run `./tacnoc`. It builds
  from any host, including Windows.
- Documented which Linux target is buildable where: `tar.gz` cross-builds from
  Windows, **AppImage does not** (packaging it creates symlinks Windows refuses
  without elevation, so the build fails with `EPERM`). Build AppImage on Linux
  or via the CI matrix. See [RELEASE.md](RELEASE.md).
- Linux artifacts now use the same `${productName}-${version}-…` naming as the
  Windows ones.

### Changed

- The mesh's role prompts now encode a working methodology — hypothesis-driven
  testing, control-versus-test differentials, the defect classes that actually
  pay, and explicit evidence discipline — rather than guardrails alone.
- Mesh roles default to `claude-opus-5` with per-role reasoning effort (`xhigh`
  for the planner and attacker), and the per-turn output ceiling scales with
  effort so a deep turn is not truncated mid-answer.
- **A declined model turn is now reported, never swallowed.** A refusal returns
  a successful response with empty content, which previously read as "nothing to
  say"; the run now records it as an error, tells the reporter which roles were
  not done, and the report says the engagement was incomplete.
- Stored AI settings are normalized on read, so a project written by an earlier
  version loads without a missing role crashing the run.
- Renamed the application from **GreyNOC Belcher** to **TACNOC** (package,
  window/product name, engine facade, IPC channels, and docs). On-disk project
  format identifiers — the `belcher.db` filename, the `greynoc-belcher-project`
  export-format tag, and the secret-store/blob-id key-derivation salts — are
  left unchanged so existing projects and exports keep working unmodified.
  Historical entries below that name specific released artifacts (v0.1.0,
  v0.2.0) are left as-is; those files were actually shipped under the old name.

## [0.3.0] — 2026-07-18

### Added

- Captured-traffic **Target Map** with normalized endpoint grouping, current
  scope evaluation, request observations, inspector, and Repeater handoff.
- **Sequencer** workbench for decoded-byte token randomness screening across
  text, hex, Base64, and Base64url samples.
- Variation response triage: word/line counts, short SHA-256 fingerprints,
  grep-style markers, and named regex extraction columns.
- An explicit intercepting-proxy capability matrix and prioritized gap list.

### Security / robustness

- Variation plans now validate engine limits, marker presence/uniqueness,
  payload sizes, and response-regex bounds before any network request.
- Automated sends now have a hard wall-clock deadline and a 10 MiB response
  capture ceiling; oversized responses — and a deadline that fires mid-stream —
  are marked truncated with the partial body preserved, instead of being
  buffered without bound or discarded.
- Response analysis is limited to a 256 KiB prefix.
- Upgraded Electron, electron-builder, electron-vite, Vite, and Vitest to
  maintained lines that clear the current npm audit advisories; the development
  Node.js floor is now 22.12.
- Dependency auditing now covers the full tree (Electron is a shipping
  `devDependency`), release CI enforces it, and the concise SBOM explicitly
  includes Electron as a required packaged runtime.

### Packaging

- Windows now builds a **portable** single-file `.exe` (runs without installing)
  alongside the NSIS **installer**; the two are given distinct artifact names
  (`…-Portable-x64.exe` / `…-Setup-x64.exe`) so they no longer collide, replacing
  the previous Windows `.zip` archive.
- New `npm run dist:win` (`scripts/package-windows.mjs`): deletes previous
  releases from `dist/`, rebuilds, produces both Windows artifacts, and writes
  the SHA-256 manifest. Builds remain UNSIGNED unless signing secrets are set.

### QA/QC pass — adversarial audit fixes

A multi-agent adversarial review of the new Target Map, Sequencer, and variation
work, each fix pinned with a regression test (the suite grew from 138 to 155).

- **Sequencer severity was inverted for a strong bit-bias.** The assessment was
  derived by matching *formatted* warning strings, so a monobit p-value small
  enough to render in exponential notation (the strongest bias) was rated the
  milder "weak". Severity is now computed from the numeric metrics directly, and
  the adjacent-byte correlation signal can escalate to "poor".
- **Variation response-regex guard was bypassable.** The catastrophic-backtracking
  guard only caught flat `(a+)+` shapes; nested groups such as `((a)*)*` and
  `([a-z]+)+` slipped through and, since analysis runs on the engine's event loop,
  could freeze a job and defeat pause/stop. Replaced with a structural
  nested-quantifier detector (still: keep response regexes simple).
- **Variation request amplification.** A payload value that contains another
  position's marker could expand a validated ~84 KiB plan into a hundreds-of-MiB
  request at render time. Rendering now projects and bounds each substitution,
  refusing (and recording) an over-cap expansion before anything is sent; render
  failures are counted instead of silently dropped.
- **Target Map "latest exchange" pointed at the oldest same-millisecond capture**
  (an inverted tie-break), so the inspector and Repeater handoff could replay a
  stale request. Fixed to keep the newest.
- **Target Map IPv6 and host-case handling.** Unbracketed IPv6 authorities
  produced an invalid stored URL that collapsed the map (path and parameters
  lost); URLs are now bracketed, the metadata parser recovers path/parameters
  from otherwise-unparseable targets, mixed-case hosts group into a single origin,
  and empty query-parameter names are dropped.
- **Sequencer input handling.** Base64 and Base64url now validate identically
  (interior whitespace and the `% 4` length rule); whitespace-only sample lines no
  longer abort a run; large sample sets fold min/max without a spread that could
  overflow the call stack; and an unsupported encoding fails with a clear message.
- **IPC allowlist parity** is asserted at startup (a missing or extra handler
  fails loudly) rather than only documented, and the Target view now surfaces
  load errors.
- Corrected stale documentation that claimed the MITM offers only HTTP/1.1; it
  negotiates ALPN `h2` and intercepts HTTP/2 by default.

### QA/QC pass — second adversarial review

A second multi-agent adversarial review of the v0.3.0 diff (Target Map,
Sequencer, variation triage, and the `sendRaw` response bounds). Each surviving
finding was reproduced, fixed, and pinned with a regression test (the suite grew
from 155 to 159; two further reported findings were verified as non-issues and
dropped).

- **`sendRaw` could crash the main process on an already-aborted signal.** When
  the abort signal was already set, the request was destroyed before its `error`
  listener was attached, so Node re-emitted `error` with no handler — an
  uncaughtException that terminates the Electron main process. Reachable by
  pressing Stop while a variation task waits on a saturated concurrency
  semaphore. The request-level handlers are now attached before any path that
  can destroy the request.
- **The response-regex ReDoS guard was bypassable by group-wrapping.**
  `hasNestedQuantifier` discarded a nested group's inner-quantifier flag when the
  group had no immediate quantifier, so `((a*))*` (and `((a+))+`, `(([a-z]+))+`,
  …) passed validation and could freeze the engine event loop in
  `analyzeResponse`, defeating pause/stop. The scan now propagates an inner
  unbounded quantifier to the enclosing group.
- **The render size cap was measured in UTF-16 code units, not bytes.** A
  multibyte cross-marker expansion could render a request several times the 2 MiB
  base cap while passing the guard. The projection is now byte-accurate, honoring
  the documented bound.
- **The Target Map evaluated scope without the query string.** Endpoint scope
  used the bare pathname while the live gate uses path+query, so a query-sensitive
  include/exclude rule classified endpoints differently in the map than at the
  gate (display-only — every live automated path recomputes scope with the query
  intact, so there was no gate bypass). The map now evaluates scope with the same
  origin-form path (query included) the gate uses.
- **A trailing-dot FQDN split one origin into two sites** in the map. Host
  grouping only lowercased; the scope engine also strips trailing dots. Grouping
  now reuses the scope engine's `normalizeHost` (lowercase + strip trailing dots).
- **The Target view's endpoint-detail load had no error handling** — a rejected
  fetch became an unhandled rejection and left the inspector silently stale; it
  now surfaces the error the same way the map load does.
- Corrected stale docs that still described the pre-upgrade Electron 33 / Node
  20.18 runtime (the app now ships Electron 43 on the Node 22.x line):
  `docs/testing.md`, `docs/PLAN.md`, ADR 0003 (dated update note), ADR 0004; and
  the README "What works today" heading no longer reads "(first delivery)".

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

[Unreleased]: https://example.invalid/greynoc/tacnoc/compare/v0.3.0...HEAD
[0.3.0]: https://example.invalid/greynoc/tacnoc/compare/v0.2.0...v0.3.0
[0.2.0]: https://example.invalid/greynoc/tacnoc/compare/v0.1.0...v0.2.0
[0.1.0]: https://example.invalid/greynoc/tacnoc/releases/tag/v0.1.0
