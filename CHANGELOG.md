# Changelog

All notable changes to TACNOC are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and the project aims to follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added — guided setup: intake, a readiness checklist, and a skippable walkthrough

Opening TACNOC for the first time used to drop you on an empty HTTP History
table with no indication that nothing would work until scope and a CA existed.
Three pieces now sit between "installed" and "testing".

- **Intake** asks for the program, the platform and your handle alongside the
  project name and authorization reference, and folds them into the engagement
  profile as soon as the project exists. Best effort by design: the project is
  already open by then, so a profile write that fails must not read as a failed
  project creation. Every field stays editable in Engagement.
- **Setup is the new landing view**, and it renders `getPreflight()` — the same
  report the AI mesh refuses to run against — worst-first, with each item wired
  to the thing that clears it. It is deliberately not a second opinion about
  readiness: if Setup is green, the engine agrees. A test asserts that every
  check id `preflight.ts` can emit has somewhere to route, because a "Fix this"
  button that goes nowhere fails silently.
- **A walkthrough covers all seventeen features**, moving the app to each view as
  it describes it rather than talking about them in the abstract. It is docked,
  never modal, so you can keep clicking while it is open, and **Skip is on every
  step** (Escape does the same). Skipping returns you to the view you were on
  rather than stranding you where the tour navigated. Replay it any time from
  Settings.

Skipping sticks. The preference is per-install rather than per-project — having
skipped it once, you should not meet it again on the next engagement — so it
lives in `userData`, is written atomically, and repairs rather than rejects a
corrupt file. An end-to-end test relaunches the app against the same profile to
prove the skip survived the round trip, which is the only thing that actually
demonstrates "skippable".

### Fixed — IPC dispatch

- **IPC dispatch resolved inherited `Object.prototype` keys.** The handler map is
  an object literal, so `constructor` and `toString` reached dispatch despite not
  being on the allowlist. Now an `Object.hasOwn` check. No capability was
  reachable this way — the values are not callable handlers — but the allowlist
  should be the only thing deciding.

### Fixed — response bodies in an evidence bundle were unreadable, and the file said otherwise

Nearly every HTTPS response is gzip or brotli on the wire, and the proxy stores
what the wire carried. The bundle UTF-8-decoded those bytes, which destroys
them: the response bodies — the substance of the evidence — reached a triager as
mojibake, and the original was not recoverable from the file.

The label above them was worse than the damage. A redacted bundle printed
`# content: REDACTED (credentials and secret patterns masked)` over bytes the
redactor had never been able to read, because it cannot match a pattern in
compressed data. The claim was unverifiable rather than merely wrong. A raw
bundle printed `RAW as captured` over the same lossy decode.

Bodies are now decompressed first, through the same `maxOutputLength`-guarded
helper the redactor and the passive scanner already used — one decompressor, so
there is one place to keep the bomb guard. The `# content:` line says per body
what happened to it, and a body that cannot be decompressed is named as such
instead of being emitted as noise: on the redacted path it is omitted outright,
since unreadable is unredactable and a bundle that says `REDACTED` must not
carry bytes nothing inspected. Raw bodies are written byte for byte rather than
through a string, and the documented 256 KiB per-body cap now binds on the raw
path too — it applied only to the redacted one, so a raw bundle carried up to
4 MiB per message.

### Fixed — a bundle for one target carried the whole project

`bundle.ts` opens by saying why exact host matching is load-bearing: anything
looser "would hand a triager another target's traffic." Exchanges, findings and
audit rows honoured it. Two sections never had.

The **engine briefing** was rendered verbatim into `HANDOFF.md` and
`handoff.json`, and it is built from the whole project: every in-scope endpoint
the proxy has ranked, the absolute path of the engagement folder, and up to
twenty of its filenames — which in practice are named after the client. Export a
bundle for host A with host B in the same project, and B's endpoints and the
folder's name went with it. The briefing is now asked for **by host**: it ranks
only that host's endpoints, drops the engagement folder entirely, and drops
per-check preflight detail, where the local CA's subject and fingerprint live.
The full briefing is unchanged for the live UI and the mesh, neither of which
leaves the machine.

The **session log tail** shipped by default with no host filter at all, and the
proxy logs a line per host it touches. It is now an opt-in the operator makes
deliberately, alongside raw captures, with a checkbox in the target view.
Filtering it was the alternative and is the wrong one: many records carry no
host, others name one only inside free text, and deciding by substring is
exactly what rule 3 exists to forbid — a filtered tail would also present itself
as a whole log.

### Fixed — the log tail outlived the project it described

`LogBuffer` is built once per session and the session outlives every project
opened in it, so nothing ever cleared it. Work on one engagement, open the next,
export: up to 5000 of the previous client's records went out inside the new
project's bundle or diagnostics. `closeProject()` now clears the tail, which
covers opening and creating a project alike, since both close first.

The test that should have caught the briefing leak was structurally unable to:
its fixtures returned a one-line briefing and a one-line log that could not
mention the impostor host, so the assertion guarding against exactly this passed
by never being exercised. Both fixtures now carry the impostor.

## [0.5.8] — 2026-09-15

### Added — the GreyNOC owl is the application's mark

The owl replaces the placeholder shield in the top bar, leads the welcome card,
and is the application icon the installers carry. One source of truth —
`src/renderer/public/owl.svg` — and `npm run brand` regenerates both the React
component and the icons from it, so the mark and the icon cannot drift apart.

- **In the UI the owl is an inline SVG**, not an image: it takes its colour from
  `currentColor`, so it follows the accent on the dark and the light theme
  alike, and it asks nothing of `img-src` under the renderer's strict CSP.
- **The icon is the owl on the app's own `--bg` surface** (`#0d1117`), matching
  the badge form. `build/icon.png` is 1024x1024 and electron-builder derives the
  per-platform `.ico` / `.icns`; a 256px copy ships in the renderer for the
  `BrowserWindow` icon, which is what Linux and `electron-vite dev` read.
- The top-bar mark is 22px rather than the placeholder's 20px — the owl carries
  fine feather detail that turns to mush below about that size.

### Fixed — about 1 host in 512 could not be intercepted at all

A real interception defect, surfaced by a release run rather than by use, which
is the only reason it was ever found: it fails intermittently and blames ASN.1.

Certificate serial numbers were minted as `'00' + 15 random bytes`. That makes
the integer positive, which was the intent — but DER also requires an INTEGER to
be **minimally encoded**, with no redundant leading zero byte. node-forge strips
exactly one leading zero when it writes the DER, so whenever the first random
byte was *also* `0x00` and the next had its high bit clear, the encoding kept a
redundant zero.

OpenSSL 3 refuses such a certificate outright, from `tls.createSecureContext` —
the call that turns every minted leaf into a usable context:

```
error:068000DD:asn1 encoding routines::illegal padding
```

So roughly **1 leaf in 512** threw instead of producing a context, and HTTPS
interception for that host simply failed, with an ASN.1 error and nothing
pointing at the cause. A newly issued CA was unusable at the same rate. Measured
directly: **9 rejected out of 6000** with the old generator, **0 out of 6000**
with the new one.

The first byte is now forced into `0x01..0x7f` — positive, non-zero and minimal
by construction, with no leading zero to strip — keeping 127 bits of entropy,
well above the 64-bit CA/Browser Forum floor.

Two regression tests, both deterministic rather than probabilistic: one asserts
every minted serial survives a DER round trip at full length (the old generator
fails it on the first leaf), and one pins the mechanism by building certificates
with a known-bad and known-good serial and asserting OpenSSL's verdict on each.

### Fixed — the macOS "signing" secrets never signed anything

`release.yml` treated `APPLE_ID` as evidence that a macOS signing identity
existed. It is not one. On macOS the **certificate** and the **notarization
credentials** are separate, and only the certificate produces a signature:
electron-builder reads a Developer ID Application .p12 from `CSC_LINK` (importing
it into a throwaway keychain of its own), while the `APPLE_*` trio is read only
by `notarytool`, after a signature exists. The workflow's one certificate secret
was `WINDOWS_CSC_LINK` — Windows-specific — so the `macos-latest` leg had no way
to obtain a certificate at all, and RELEASE.md advertised a
"macOS Developer ID + notarization" row that could not be satisfied.

The failure was silent, which is the worst part. `MacPackager.sign()` returns
early when no identity is found and the notarization call sits *after* that
return, so an operator who configured all three advertised `APPLE_*` secrets got
an **unsigned, un-notarized artifact and no error** — and, because `APPLE_ID` was
set, the old guard also left `CSC_IDENTITY_AUTO_DISCOVERY` on, so the build
searched an empty runner keychain instead of saying it had nothing to sign with.

- **`APPLE_CSC_LINK` / `APPLE_CSC_KEY_PASSWORD`** carry the Developer ID
  certificate, and the macOS branch now gates on it exactly as Windows gates on
  `WINDOWS_CSC_LINK`. No `security import` step is needed — electron-builder
  imports a base64 .p12 itself.
- **`APPLE_*` set without a certificate now warns** that notarization is being
  skipped entirely rather than silently producing an unsigned build, and a
  partly-configured notarization trio fails fast with an `::error::` instead of
  dying after a full sign-and-package.
- **`Report signing status` reports per-OS on the certificate.** It tested the
  union of every secret, so any one platform being configured made all three
  runners claim "artifacts should be signed" — including macOS, where `APPLE_ID`
  alone signs nothing. It also no longer interpolates secrets into a script body.

## [0.5.7] — 2026-09-15

### Fixed — a TLS test that was really testing the OS port pool

v0.5.6 got the gate running on Windows and macOS, and the very next release run
failed on Windows again — on a different test, and this time an intermittent
one. `ca.test.ts` mints a leaf from the project CA and verifies it over a real
TLS handshake across loopback TCP, and roughly **1 run in 25** failed with a
transient socket error: either `unable to verify the first certificate` or the
client socket disconnecting mid-handshake.

The certificates were never the problem. Two probes established that before
anything was changed: 199 of 200 handshakes verified (the single failure being
a socket disconnect, with the chain intact), and 60 of 60 verified against
freshly minted CAs in isolation. A separate check refuted the obvious
explanation — Windows refuses a second bind to the same loopback port with
`EADDRINUSE`, with or without `exclusive: true` — so this was ephemeral-port
churn, not port hijacking.

The handshake now runs over a **named pipe** (Windows) or a Unix socket, which
has no port to recycle and nothing in `TIME_WAIT`. It is the same real
handshake: same certificates, same SNI, same verification against the CA. Over
60 consecutive runs it did not fail once.

## [0.5.6] — 2026-09-15

### Fixed — the gate never ran on the platforms the release builds for

v0.5.5 fixed macOS packaging and both macOS and Linux went green, producing
artifacts for the first time. Windows then failed — at the quality gate, on a
test that passes everywhere else.

- **A bulk insert took 86 seconds on a Windows runner.** `storage.test.ts`
  builds 2050 exchanges to prove `export()` pages past its 2000-row page size,
  one `insert` at a time. Each insert is its own durable commit — WAL is
  unsupported by the WASM VFS, so every row pays a full journal round-trip — and
  the inserts are *synchronous*, so the 20-second test timeout could not even
  fire until the block finished: the runner reported 86,034 ms against a 20,000
  ms limit. `HistoryRepo.insertMany` now wraps a batch in one transaction, which
  is the right shape for a bulk load and wrong for captured traffic (which keeps
  committing per request, on purpose). The test: **86,034 ms → 249 ms.**

### Changed

- **`ci.yml` runs the gate on Windows and macOS too**, matching the platforms
  `release.yml` builds on. It ran only on `ubuntu-latest`, and the release
  workflow runs it on all three — so the first time the gate ever saw the other
  two was on a pushed tag. That gap cost two releases in a row: v0.5.3 died on a
  macOS-only path comparison, v0.5.5 on this Windows-only timeout, and a PR run
  on those platforms would have caught both for a few minutes of CI. Building
  and driving the GUI stays Linux-only in its own job — it needs xvfb, and the
  CSP/renderer regressions it catches are not platform-specific; the packaged
  binary is still exercised per-OS by `release.yml`.

## [0.5.5] — 2026-09-15

### Fixed — the release workflow could not sign, so it could not build

v0.5.4 fixed the macOS *quality gate* and the macOS leg went straight on to fail
at **packaging** — a step no cut had ever reached, because the gate had always
died first. Two defects in `release.yml`, both invisible until something got
that far:

- **A Windows Authenticode variable was handed to every runner.** `CSC_LINK` was
  set from `secrets.WINDOWS_CSC_LINK` in a matrix-wide `env:` block. A GitHub
  expression that evaluates to nothing sets the variable to the **empty string**,
  and an empty `CSC_LINK` is not the same as an unset one: electron-builder reads
  it as a path to a certificate, resolves `""` against the working directory, and
  stops with `⨯ <projectDir> not a file`. Windows tolerated it and macOS did not.
  The signing variables are now exported per-OS in the shell, so a runner sees a
  signing variable only when that platform's secret is actually configured, and
  macOS disables identity auto-discovery explicitly when no Apple ID is set —
  unsigned by decision rather than by failed search.
- **electron-builder was publishing on its own.** It warned on every tagged run
  (`Implicit publishing triggered by git tag`) that it would upload to the
  release itself, racing the `draft-release` job for the same release. The build
  now passes `--publish never`; drafting stays the one job that does it.

### Changed

- **`fail-fast` is off for the release matrix.** One runner failing no longer
  cancels the others. It happened twice — v0.5.3 (macOS gate) and v0.5.4 (macOS
  packaging) — and both times Windows and Linux were mid-build and producing
  artifacts when they were cancelled, so neither failure said anything about
  whether those platforms were healthy. `draft-release` still requires every
  leg, so a failure blocks the release exactly as before; what changes is that
  the run now reports on all three.

## [0.5.4] — 2026-09-15

### Fixed — the v0.5.3 release never built

- **The release gate failed on macOS, so no v0.5.3 artifacts were ever
  produced.** `release.yml` on the `v0.5.3` tag failed its quality-gate step on
  `macos-latest`, fail-fast cancelled the Windows and Linux legs, and the
  draft-release job never ran. The failure was in the tests, not the engine:
  `os.tmpdir()` on macOS is `/var/folders/…`, a symlink to
  `/private/var/folders/…`, and the engine resolves every workspace path
  through `fs.realpath` — so `huntFolderLayout.test.ts` compared
  `/private/var/…` against `/var/…`, two spellings of one directory, and failed
  on the one OS where they differ. Every test that derives paths from a temp
  directory now resolves that directory at creation, so the comparison is
  canonical-to-canonical everywhere. `hunt-folder.spec.ts` (E2E, which the
  release matrix also runs on macOS) carried the same latent mismatch and is
  fixed the same way.
- **v0.5.3 was tagged on a branch that never reached `master`.** The tag and
  its record sat on `claude/ca-setup-guide-qaqc`; `master` stayed at 0.5.2,
  itself never tagged. The branch is merged (a fast-forward — nothing diverged)
  and this version is cut from `master`, so the default branch, the tag, and the
  record line up again. The `v0.5.3` tag stays where it is — it was published —
  and marks a version that has no artifacts.

### Changed

- This is the first cut to carry the corrections made after the `v0.5.3` tag:
  the `SECURITY.md`, `RELEASE.md`, `docs/extension-sdk.md` and `docs/testing.md`
  claims that did not match the code, the `package-linux.mjs` executable name,
  and the Mythos thinking/effort coverage note. No shipped behaviour differs
  from what `v0.5.3` would have built.

## [0.5.3] — 2026-09-03

### Added — the certificate step, guided and optional

Trusting the interception CA is the step people get wrong, and getting it wrong
is silent: the proxy runs, the browser browses, and no HTTPS is ever captured.
The old screen was a fingerprint, a warning, and a paragraph of prose the
operator had to translate into a sequence of dialogs, with nothing anywhere
confirming it had worked.

- **Four guided steps** — save the certificate, trust it, point the browser at
  the proxy, verify. Each says what to do and what to expect.
- **A command, not a paragraph.** The trust step gives the exact command for the
  platform, with the saved path already quoted for that shell, plus the by-hand
  route for anyone who would rather see each dialog. Every guide takes the
  narrowest trust that works — current user, login keychain, the browser's own
  NSS store — and none needs administrator rights. **The app still never touches
  the OS trust store**; it hands over a command the operator runs.
- **Removal sits next to installation**, not in a footnote, because a trusted
  interception CA left behind after an engagement is a standing risk.
- **It says it is optional, first.** HTTP is captured with no certificate at
  all. The guide can be skipped, and stands itself down once interception is
  verified instead of nagging an operator who is already set up.
- **Verification reads evidence, not settings** — see below.
- The Firefox/Tor separate-trust-store trap, the single commonest cause of a
  correct-looking install that captures nothing, is called out per platform.

### Fixed

- **"TLS interception is working" could be true when the browser trusted
  nothing.** The evidence count behind that preflight check counted *any* HTTPS
  exchange, including Repeater and Variation traffic — which the engine sends
  over its own TLS stack, never presenting the project's leaf certificate, and
  which succeeds whether or not any client trusts the CA. One HTTPS Repeater
  probe was enough to report interception as working over a browser refusing
  every intercepted connection, and a mesh run's own traffic made the next run's
  recon pass the check. It now counts proxy-decrypted exchanges only.
- **EMERGENCY STOP sent every held request to the target.** Releasing the
  intercept queue resolved each pending message as `forward`, and a held request
  has not been sent yet — so the one control whose entire job is to stop touching
  the target delivered the queue to it, while the UI reported that all automated
  work had been halted. Stopping the proxy did the same. Both now drop, and the
  release action is an explicit argument that defaults to dropping. Switching
  interception off still forwards, which is what that gesture means.
- **The only control that starts the proxy swallowed every failure.** A taken
  port or no open project rejected into an unhandled promise: the chip stayed on
  "Proxy off" and nothing said why.
- **The findings badge counted findings the operator had suppressed.** A
  suppressed finding is stored but not listed, yet it still announced itself, so
  the sidebar count climbed while the Findings list gained nothing.
- **The identity-compliance check could pass on a sample of zero.** It took the
  newest 100 exchanges of *any* source and then filtered to generated traffic, so
  ordinary browsing pushed the Repeater and Variation requests out of the window
  entirely — at which point it reported that every generated request carried the
  required User-Agent, on the strength of no requests at all.
- **HTTP History re-ran a 500-row query on every captured exchange**, decrypting
  every row's headers and inline bodies for a table that shows sizes. Debounced,
  the way the Target Map already was.
- **A rejected engagement profile was left on screen as if saved** — tick
  "enforce" with no User-Agent set and the box stayed ticked over an engine that
  had refused it.
- **The Intercept chip ignored response interception**, reading "Intercept off
  (1)" while a response sat held.
- The main process carried a **verbatim copy** of the engine's per-platform
  install text, so the two could drift while both looked authoritative.

### Changed — AI harness

- **Sonnet 4.6 ran with thinking switched off.** It was listed as accepting the
  effort parameter but not adaptive thinking, and on that generation omitting
  the thinking field means the model does not reason at all — so choosing it for
  a role sent `effort: xhigh` to a non-reasoning turn while the UI showed the
  lever at maximum.
- **Mythos models got neither thinking nor effort.** No entry in the capability
  lists prefix-matched any `claude-mythos-*` id, so a role set to one received no
  `thinking` and no `output_config.effort` at all — the same silent failure as
  Sonnet 4.6, from the same cause. `claude-mythos-5` is now listed for adaptive
  thinking and effort; task budgets remain Fable/Opus/Sonnet only. Fable was
  already covered and is unchanged apart from ordering, and matching is still by
  id prefix, so `claude-fable-5-1` is covered by the `claude-fable-5` entry.
- **"Test connection"** checks the key and the model id before a run exists. It
  counts tokens for a one-word prompt: it authenticates and resolves the model,
  generates nothing, and sends nothing at the target. Without it, a wrong key or
  a mistyped model id first surfaced partway through a live run.
- **API failures name the one thing to fix.** Wrong key, no model access, wrong
  model id, rate limit, and no network are indistinguishable in the raw SDK
  message and lead to completely different fixes; each is now classified and
  reported as a sentence. An operator-initiated abort is still reported as a
  stop, not an error.
- **The per-role output ceiling rose from 16K to 32K** for the standard-effort
  roles. Every request streams, so the timeout that once justified a small cap no
  longer applies, and adaptive thinking shares that budget with the answer — the
  reporter, writing a full engagement report, was the role running out of it.

### Changed — the window is frameless

The app's own top bar is now the title bar. macOS keeps its native traffic
lights floating over the content; Windows and Linux drop the OS frame entirely
and the top bar draws its own minimise, maximise, and close.

### Security

- `browserslist` and `fast-uri` (high) and `@xmldom/xmldom` (moderate) advisories
  cleared (lockfile only). All three are build tooling — vite/postcss and
  electron-builder — and none reaches the shipped runtime, but the release gate
  audits the full tree.

### Fixed — documentation that overstated what the code does

Found by auditing every claim in the repo against the code during the release
cut. This project's standard is "reproducible or it didn't happen", so a doc that
claims a protection or a gate that does not exist is a defect, not a nit.

- **`SECURITY.md` said at-rest encryption was "not yet implemented"** and that
  "HTTP/2/3 interception is not implemented". Both were stale since v0.4.0:
  content is AES-256-GCM encrypted at rest, and HTTP/2 *is* intercepted. Every
  other document in the repo already said so. The known-limitations section now
  states what is actually true, including what encryption does *not* cover.
- **`docs/extension-sdk.md` claimed `sdkVersion` is checked against the host SDK
  version.** Nothing reads that field — an extension declaring an incompatible
  version loads without a warning. Documented as a declaration of intent, not the
  compatibility gate it was described as.
- **`RELEASE.md` claimed a bare `npm run dist` attempts AppImage and fails on
  Windows.** It does not: electron-builder builds host-platform targets only, and
  `release.yml` runs exactly that command on its Windows leg — so the file
  contradicted its own CI instructions.
- Corrected two claims in this changelog's own AI-harness section, and a coverage
  row in `docs/testing.md` that credited an E2E spec with an assertion it does not
  make.

## [0.5.2] — 2026-08-09

### Fixed — QA/QC pass on wiring: controls that looked like they worked

A pass across the whole renderer → IPC → engine chain, cross-referencing every
invokable method and every emitted event against what actually consumes it. The
IPC spine held: allowlist/handler parity is asserted at startup, every method has
a wrapper, and every wrapper is reachable. Everything below was at the edges —
and every one of them was confirmed by driving the real app, not by reading.

- **The scope editor saved wider rules than it displayed.** Ports, scheme, and
  path prefix were uncontrolled inputs, so adding a rule reset the draft while
  the boxes kept showing what had been typed. The next rule was then stored with
  no port, no scheme, and no path while all three were still on screen — a rule
  strictly wider than the one the operator was looking at, in the fail-closed gate
  that decides whether a request is authorized. Every field is now controlled off
  the draft and clears on add.
- **Concurrent mesh runs multiplied the request budget.** The active-request cap
  is enforced per run and nothing serialized runs, so three runs with a cap of 3
  sent nine requests to the target while every number the operator could see still
  read "within budget". The orchestrator now refuses to start a run while one is
  in flight, and says what is already spending.
- **A mesh run could be left running with no way to stop it.** The AI view's only
  handle on a run was a ref that did not survive leaving the view, so returning to
  it showed an idle screen — Stop greyed out, Start apparently available — over a
  run still sending traffic, reachable only by emergency stop. The view now
  reattaches to the run in flight, restoring its steps and report.
- **"Save CA certificate" failed silently on a revoked CA.** The main process
  correctly refuses to write a 0-byte `.crt`, but that rejection went nowhere: the
  button stayed enabled and the click produced no visible response at all, which
  reads as success. The revoked state is now stated where the fingerprint goes,
  the button is disabled, and the error is surfaced.
- **`ca-changed` and `engagement-changed` were emitted to nobody.** Neither the
  Certificate nor the Engagement view listened, so a CA rotated or revoked from
  elsewhere — including by the mesh when it holds cert ops mid-run — left both
  screens presenting an interception setup that no longer existed. Both now follow
  the events.
- **Two effects keyed on the whole store object.** The store value changes on every
  captured exchange, so Intercept re-fetched its state three times per proxied
  request, and a toast restarted its dismiss timer on each one — staying pinned for
  as long as traffic kept arriving.
- **Silent failures on the Variation job controls** (pause/resume/stop dropped
  errors into a dead promise) and a **stale finding detail pane** after suppressing,
  which kept offering to suppress a finding that already was.
- **The welcome screen claimed "nothing is sent to external services"**, which the
  AI mesh made untrue. It now says what leaves the machine and when.

### Security

- `js-yaml` and `nanoid` advisories cleared (lockfile only). Both were build
  tooling — electron-builder/eslint and vite→postcss — and neither reaches the
  shipped runtime, but the release gate audits the full tree.

## [0.5.1] — 2026-08-04

### Fixed — every long AI turn died before it was sent

- **The provider never streamed, so the SDK refused the request.** With a large
  output budget a non-streaming call could exceed the 10-minute HTTP ceiling, and
  the SDK rejects that up front rather than sending it: *"Streaming is required
  for operations that may take longer than 10 minutes."* The turn died with no
  output. The agentic roles run at `xhigh` effort, which is exactly the shape that
  trips it, so in practice the planner failed every run. Turns now stream, and
  text reaches the operator as it is generated instead of in one lump at the end.
- **The output budget was sized to dodge that timeout, not to fit the work.** At
  8192 tokens a planner at `xhigh` could spend the whole allowance thinking and
  return a truncated plan. Streaming removes the ceiling, so the default is now
  64000.
- **A paused turn ended the run silently.** The SDK's tool runner does not resume
  on `pause_turn` — it only continues after a tool returns a result — so a paused
  turn ended the loop with no error and the truncated answer was reported as the
  role's finished work. It now resumes.
- **Added a test that drives the real provider** against a local server speaking
  the Anthropic SSE format. The existing mesh tests all use a fake provider, so
  nothing exercised the actual SDK call — the suite was green while every real
  turn failed.

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
