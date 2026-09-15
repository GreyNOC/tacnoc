# Release process

TACNOC follows a real quality gate — security review, checks/tests,
SBOM, versioned changelog, tagged commit, CI gate, checksummed artifacts, and a
drafted (not auto-published) release.

## Pre-release checklist

1. **Security review** of the diff since the last tag (scope gate, redaction,
   CA/secret handling, at-rest encryption, extension isolation still intact).
2. **Quality gate:** `npm run ci` (format check, lint, typecheck, tests) — must
   be green. Run `npm run test:e2e` on a machine with a display.
3. **Dependency audit:** `npm run audit` (full tree, high+). Electron is a
   `devDependency` for packaging purposes but is the shipped runtime, so it must
   not be omitted from the release audit.
4. **SBOM:** `npm run sbom` → `sbom.json` (CycloneDX 1.5).
5. **Version + changelog:** bump `version` in `package.json`, move items from
   *Unreleased* to the new version in `CHANGELOG.md`.
6. **Tag:** commit, then `git tag vX.Y.Z` and push the tag.

`npm run release:prepare` runs the quality gate + full audit + SBOM in one step.

## Building installers

```bash
npm run dist        # builds the app, then electron-builder → dist/ (all configured targets)
npm run checksums   # writes dist/SHA256SUMS-<os>.txt (per-OS: windows/macos/linux)
```

**Windows one-shot:** `npm run dist:win` deletes previous releases from `dist/`,
rebuilds, then produces both Windows artifacts and their checksum manifest:

- `TACNOC-<version>-Portable-x64.exe` — portable, runs without installing.
- `TACNOC-<version>-Setup-x64.exe` — NSIS installer.

**Order matters when you build both.** `dist:win` deletes everything in `dist/`
before it starts, so running it *after* `dist:linux` silently destroys the Linux
archive you just built — and the checksum manifest is rewritten without it, so
nothing complains. Build Windows first, Linux second. (`dist:linux` does not
clean `dist/`, which is what makes that order work.)

**Linux one-shot:** `npm run dist:linux` rebuilds and produces
`TACNOC-<version>-linux-x64.tar.gz` — extract it and run `./greynoc-tacnoc`.
(The executable takes its name from the package `name`, not the `productName`,
so it is `greynoc-tacnoc` rather than `tacnoc`. Verified against the built
archive, not assumed.)

### Which Linux target can be built where

| Target | On Linux | On Windows |
|---|---|---|
| `tar.gz` | yes | **yes** — electron-builder downloads the Linux Electron binary and repackages the app directory; no Linux-only tooling is involved |
| `AppImage` | yes | **no** — packaging creates symlinks inside the image, and Windows refuses those without Developer Mode or elevation, so the build fails with `EPERM` |

A Windows workstation can therefore cut the portable `.exe` **and** a runnable
Linux `tar.gz`, but not an AppImage. Build AppImage on Linux
(`npx electron-builder --linux AppImage`) or through the `release.yml` matrix.

Note that a bare `npm run dist` builds only the **host platform's** configured
targets — on Windows that is `nsis` + `portable`, and it succeeds. It does *not*
attempt AppImage: that is a `linux:` target, reached only when `--linux` is
passed, which is why `release.yml` can run a bare `npm run dist` on every matrix
leg. Use the per-OS scripts above for what they add on top — a cleaned `dist/`,
pinned target flags, and the checksum manifest in one step — and `dist:linux`
specifically for the Linux `tar.gz`, which a bare `npm run dist` on Windows will
not produce.

Build on each target OS (or via the `release.yml` GitHub Actions matrix). Output
goes to `dist/`. `node_modules/node-sqlite3-wasm` is unpacked from the asar
(`asarUnpack`) because it ships a `.wasm` asset read at runtime, and the example
extension is shipped under `resources/examples/extensions`.

## Verify the artifact (required — a green test suite is not enough)

After `npm run dist`, run `npm run test:e2e`. `test/e2e/packaged.spec.ts` drives
the **packaged binary** (it auto-skips when `dist/` is absent) and is the only
thing that exercises the packaged-only paths the dev-bundle suite cannot reach:

- SQLite WASM loaded from `app.asar.unpacked` (not `node_modules`),
- the example extension resolved via `process.resourcesPath` (the
  `app.isPackaged` branch in `src/main/ipc.ts`),
- forking the extension host child out of a packaged Electron binary,
- the loopback-only proxy default surviving packaging.

A packaging mistake in any of these ships an app that fails on first use while
every unit/dev-E2E test stays green. Do not cut a release without this passing.

## Signing — an explicit operator decision

**Code signing is intentionally NOT configured.** Shipping unsigned artifacts is
a decision for the operator:

- **Windows:** set an Authenticode certificate (`CSC_LINK` / `CSC_KEY_PASSWORD`).
- **macOS:** set a Developer ID identity and enable `hardenedRuntime` +
  notarization.
- **Linux:** AppImage/tar.gz are typically distributed with detached checksums.

### CI signing activation

`release.yml` passes signing secrets to `electron-builder` as env vars. Signing
activates **automatically and only** when the matching secrets are set in the
repository; with none set, artifacts are UNSIGNED (the build does not fail) and a
`::warning::` is emitted. Configure:

| Purpose | Repository secrets |
|---|---|
| Windows Authenticode | `WINDOWS_CSC_LINK` (base64 .pfx), `WINDOWS_CSC_KEY_PASSWORD` |
| macOS Developer ID + notarization | `APPLE_ID`, `APPLE_APP_SPECIFIC_PASSWORD`, `APPLE_TEAM_ID` |

For macOS notarization also enable `mac.hardenedRuntime` and `mac.notarize` in
`electron-builder.yml` (left off by default so unsigned/dev builds don't fail).

Until signing is configured, distribute checksummed builds **knowingly**, and
keep the GitHub release in **draft** (the `release.yml` workflow does this) so a
human reviews before publishing. Do not silently ship unsigned installers as if
they were signed.

### Cutting the tag

```bash
npm run release:prepare      # ci gate + full dependency audit + SBOM
# bump version + update CHANGELOG, then:
git tag vX.Y.Z && git push --tags   # triggers release.yml (drafts the release)
```

### Tag record — correcting this file (2026-09-03)

Two of the entries below say a version "was built and tagged locally". **The tag
part was not true.** Before this cut, `git tag` and `git ls-remote --tags origin`
both listed only `v0.4.0` and `v0.4.1`, against the ten versions `CHANGELOG.md`
recorded at the time; with `v0.5.3` they now list three tags against eleven
versions. Everything from v0.4.2 through v0.5.2 was built and recorded here but
never tagged, and since `release.yml` triggers on a `v*` tag, **no draft GitHub
release was ever produced for any of them.** The artifacts and hashes below are
still accurate for what was built locally — what was wrong is the claim that a
tag existed.

The entries are left in place rather than rewritten, with this correction above
them, because the point of this file is an accurate record and quietly editing
the history would defeat it.

### Tag record — second correction (2026-09-15)

The 2026-09-03 correction above was itself incomplete, and the release it
described did not happen:

- **`v0.5.3` never produced artifacts.** The `release.yml` run on that tag
  failed its quality-gate step on `macos-latest`: `huntFolderLayout.test.ts`
  compared a `/private/var/…` path the engine had resolved through `fs.realpath`
  against the `/var/…` spelling `os.tmpdir()` returns, and only macOS puts a
  symlink between the two. Fail-fast cancelled the Windows and Linux legs and
  `draft-release` never ran. The local artifacts and hashes in the v0.5.3 record
  are real, the tag exists, and nothing was ever attached to a release. The tag
  is left where it is because it was published.
- **`v0.5.3` was tagged off `master`.** The tag and its record sat on
  `claude/ca-setup-guide-qaqc`, two commits ahead of a `master` that stayed at
  0.5.2 — a version that was itself never tagged. The branch fast-forwarded onto
  `master`; nothing had diverged.
- **Six tags existed only in this workstation's clone.** `v0.1.0`, `v0.2.0`,
  `v0.4.2`, `v0.4.3`, `v0.5.0` and `v0.5.1` were created here — annotated tags
  dated July and August — and never pushed;
  the 2026-09-03 correction was written from a checkout that did not have them.
  They are pushed after the v0.5.4 run completes, and each push triggers
  `release.yml` against a commit that cannot pass it — v0.4.2 through v0.5.1
  predate `.gitattributes` and die on Windows `format:check`, all six predate
  the macOS fix, and v0.1.0/v0.2.0 are older still — so expect a failed Release
  run on every one of those tags. They are the record, not releases. `v0.5.2` is
  tagged retroactively at `3599afa`, the `master` commit whose `package.json`
  says 0.5.2, on the same reasoning.

### v0.5.4 — cut UNSIGNED, built by CI (operator decision, 2026-09-15)

`v0.5.4` is the v0.5.3 work plus the fixes that let it actually build, cut from
`master` and tagged on the merge commit — the "re-tag on the merge commit" the
v0.5.3 record asks for, done as a new version rather than by moving a published
tag. No shipped behaviour differs from what v0.5.3 would have built (see
`CHANGELOG.md`).

Gate, run on this workstation before tagging: `npm run ci` green (format, lint,
typecheck, 28 test files / 368 tests). Full-tree `npm audit` reports **0
vulnerabilities at every level** after two lockfile-only bumps — `js-yaml`
4.3.1 → 4.3.2 (high, GHSA-2883-xcg3-v3hh; reached only through
`electron-builder` and `eslint`) and `vitest`/`@vitest/coverage-v8` 4.1.10 →
4.1.11 (moderate, GHSA-82fw-gwwq-j7x9; the test runner) — neither is in the
shipped runtime, whose ten SBOM components are unchanged; `sbom.json`
regenerated. `npm run test:e2e` on this workstation: all 10 specs green in the
real Electron runtime, including `hunt-folder.spec.ts` as changed. Note that
`packaged.spec.ts` ran here against the `dist/` already on disk — the v0.5.2
local build; nothing was packaged for 0.5.4 on this host — so the packaged-path
check against the 0.5.4 binaries is the one the release matrix performs.

The macOS failure could not be reproduced here. Windows needs Developer Mode to
create a directory symlink (`EPERM` without it), and a directory junction is not
resolved by Node's `fs.realpath`, so the string split that fails on macOS cannot
be manufactured on this host. The fix is verified by the `macos-latest` leg of
the release run below — the only place the defect ever showed.

**This release produced no artifacts.** The tagged `release.yml` run
(`35010044815`) failed. The macOS fix worked — the quality gate passed on
`macos-latest` for the first time, which is precisely what had failed on v0.5.3
— and the leg then failed one step later, at packaging, on a defect in the
workflow that no cut had ever reached:

```
• empty password will be used for code signing  reason=CSC_KEY_PASSWORD is not defined
⨯ /Users/runner/work/tacnoc/tacnoc not a file
```

`CSC_LINK` (Windows Authenticode) was set from a matrix-wide `env:` block on all
three runners. An unset GitHub secret substitutes the **empty string**, not
nothing, and electron-builder takes `CSC_LINK` as a path to a certificate:
`""` resolved against the working directory is the project root, which is not a
file. `fail-fast` then cancelled Windows and Linux — Linux was mid-build with
`TACNOC-0.5.4-linux-x86_64.AppImage` and `TACNOC-0.5.4-linux-x64.tar.gz` already
building, so nothing here indicates a problem on either. Fixed in v0.5.5; the
`v0.5.4` tag stays where it is, and marks a second version with no artifacts.

### v0.5.5 — cut UNSIGNED, built by CI (operator decision, 2026-09-15)

`v0.5.5` is v0.5.4 plus the `release.yml` fixes that let the matrix package: the
signing variables are exported per-OS in the shell rather than in `env:` (so an
empty one is never seen by a runner that has no such secret), macOS identity
auto-discovery is disabled explicitly when no Apple ID is configured, the build
passes `--publish never` so electron-builder stops racing `draft-release` for
the same release, and `fail-fast` is off so one leg cannot cancel the others.
No application code changed.

Gate on this workstation: `npm run ci` green, `npm run test:e2e` 10/10 in the
real Electron runtime, full-tree `npm audit` 0 at every level, SBOM regenerated.
The macOS packaging path cannot be exercised here at all — this is a Windows
host — so, as with the v0.5.4 test fix, the `macos-latest` leg of the release
run is the verification.

**The macOS fix worked. This release still produced no artifacts.** Run
`35020717338`: `macos-latest` **passed** in 3m15s and `ubuntu-latest` **passed**
in 6m21s — both built, verified the packaged binary, checksummed and uploaded —
and `windows-latest` failed at the quality gate, so `draft-release` (which
needs every leg) did not run. `fail-fast: false` is what made that legible:
under the old setting the first failure would have cancelled the two green legs
and the run would have said nothing about either.

The Windows failure was `storage.test.ts` spending 86,034 ms against a 20,000 ms
timeout on 2050 row-at-a-time inserts — synchronous, so the timeout could not
fire until they finished. Fixed in v0.5.6, along with the reason it reached a
tag at all: `ci.yml` ran the gate only on `ubuntu-latest`. The `v0.5.5` tag
stays where it is, and marks a third version with no artifacts.

### v0.5.6 — cut UNSIGNED, built by CI (operator decision, 2026-09-15)

`v0.5.6` is v0.5.5 plus a bulk-insert path (`HistoryRepo.insertMany`, one
transaction instead of 2050 durable commits) and a `ci.yml` that runs the gate
on all three platforms `release.yml` builds for, so the next platform-specific
defect is caught in a pull request rather than on a tag. No application
behaviour changed.

Gate on this workstation: `npm run ci` green, `npm run test:e2e` 10/10 in the
real Electron runtime, full-tree `npm audit` 0 at every level, SBOM regenerated.
The previously-failing test measured **86,034 ms on CI Windows → 249 ms here**
after batching.

**That fix worked, and this release still produced no artifacts.** Run
`35022131106`: Windows failed the quality gate again, on a different test —
`ca.test.ts`'s real-TLS-handshake case — and intermittently, since the same
commit's PR run had passed on `windows-latest` minutes earlier. Reproduced
locally at roughly 1 run in 25. Fixed in v0.5.7. The `v0.5.6` tag stays where it
is, and marks a fourth version with no artifacts.

### v0.5.7 — cut UNSIGNED, built by CI (operator decision, 2026-09-15)

`v0.5.7` moves that handshake off loopback TCP and onto a named pipe (Unix
socket off Windows), removing the ephemeral-port churn the test was
inadvertently exercising. Same certificates, same SNI, same verification — no
port to recycle. No application code changed.

Evidence, gathered before changing anything rather than after: 199 of 200
handshakes verified over TCP (the one failure a socket disconnect, chain
intact); 60 of 60 with freshly minted CAs in isolation; and a direct check
refuting port hijacking, since Windows returns `EADDRINUSE` for a second bind
with or without `exclusive: true`. After the change, 60 consecutive runs passed.
At the observed TCP failure rate a clean run of 60 would happen by chance about
9% of the time, so the mechanism — no port, no `TIME_WAIT` — is the argument,
and the 60 runs are corroboration rather than proof.

Gate on this workstation: `npm run ci` green, `npm run test:e2e` 10/10 in the
real Electron runtime, full-tree `npm audit` 0 at every level, SBOM regenerated.

**The flake fix worked. Windows and Linux both passed — and macOS found a real
bug.** Run `35024875199`: `windows-latest` passed in 5m18s (the TLS handshake
case included) and `ubuntu-latest` in 5m54s, both building and verifying their
artifacts; `macos-latest` failed the quality gate on the same handshake test,
but for an entirely different reason — `tls.createSecureContext` rejecting a
minted leaf with `asn1 encoding routines::illegal padding`. That is not a test
problem. It is an interception defect that hit about 1 host in 512, fixed in
v0.5.8. The `v0.5.7` tag stays where it is, and marks a fifth version with no
artifacts.

Worth stating plainly, because it is the argument for the whole three-OS gate:
this bug had been in every release since the CA existed, it is invisible on
Windows and Linux most of the time, and it took a macOS runner drawing an
unlucky 16 bytes to expose it.

### v0.5.8 — cut UNSIGNED, built by CI (operator decision, 2026-09-15)

`v0.5.8` fixes the certificate serial-number encoding. See `CHANGELOG.md`; the
short version is that serials were `'00' + 15 random bytes`, which is positive
but not always *minimally* encoded, and OpenSSL 3 refuses a non-minimal INTEGER.
Measured: 9 certificates rejected out of 6000 with the old generator, 0 out of
6000 with the new one. Two deterministic regression tests cover it — the
round-trip one fails on the first leaf under the old generator, which was
verified by reverting the fix and re-running rather than assumed.

This is the first change in the v0.5.3–0.5.8 sequence that alters shipped
behaviour: certificates minted after it will differ from ones minted before, and
an operator who happened to hit the bad path will find interception working for
a host that previously failed. No CA needs reissuing — an existing CA that works
is unaffected — but a CA that was *never* usable should be reissued.

Gate on this workstation: `npm run ci` green, `npm run test:e2e` 10/10 in the
real Electron runtime, full-tree `npm audit` 0 at every level, SBOM regenerated.
The run, the artifacts, and their SHA-256 manifests are recorded below once it
completes.

### v0.5.3 — cut UNSIGNED (operator decision, 2026-09-03)

`v0.5.3` (the certificate-setup pass — see `CHANGELOG.md`) is built and tagged
with **no code signing**, the same deliberate operator decision as every cut
before it, and it is the first version since v0.4.1 to actually carry a tag.

> **The `v0.5.3` tag points at commit `796c551`, which is one commit behind the
> artifacts recorded below.** A release-record audit run after tagging found
> several documentation claims in this repo that did not match the code —
> including two in this file and two in the v0.5.3 changelog entry — and
> correcting them produced a follow-up commit. The delta is documentation, tests,
> and one source comment: **no shipped behaviour differs** between the tagged
> commit and the built artifacts. Re-tag on the merge commit so the tag and the
> record line up again.

Gate: 368 unit/integration tests green, all 10 E2E specs green **including
`packaged.spec.ts` against the binaries below**, full-tree `npm audit` clean
(three build-tooling advisories — `browserslist`, `fast-uri`, `@xmldom/xmldom` —
cleared in the lockfile; none reaches the shipped runtime), SBOM regenerated.
`electron-builder` logs `signing with signtool.exe`; with no certificate
configured nothing is applied, and `Get-AuthenticodeSignature` on both Windows
artifacts reports `NotSigned`. Verified rather than assumed.

Built on a Windows x64 host — both Windows targets natively, and the Linux
`tar.gz` cross-built (electron-builder downloads the Linux Electron and
repackages the app directory; no Linux-only tooling is involved):

| Artifact | SHA-256 |
|---|---|
| `TACNOC-0.5.3-Portable-x64.exe` (portable) | `c36cddfbf300c0853b6fd29a380d3fce4945873d37e62780a75020585d95fa88` |
| `TACNOC-0.5.3-Setup-x64.exe` (NSIS) | `de010b59b6e6c79dfddfc9f80db61b64b797c7af0954b50d70c2d7e741deff9c` |
| `TACNOC-0.5.3-linux-x64.tar.gz` (portable, cross-built) | `0ec0d11ae01943cd65284ef16c0a5f5d2bf8d7327b5509850bdb466feb1b7358` |

Manifest: `dist/SHA256SUMS-windows.txt`. **That filename names the build host,
not the target** — `scripts/checksums.mjs` labels the manifest by
`process.platform`, so this one Windows-built manifest covers all three artifacts
including the cross-built Linux archive. On the `release.yml` matrix each OS
builds its own targets and the names line up with the contents; a local
cross-build is the case where they do not. Nothing is missing from the manifest,
but do not go looking for a `SHA256SUMS-linux.txt` from this cut.

The Linux archive was verified by listing it: it unpacks to
`TACNOC-0.5.3-linux-x64/` containing the `greynoc-tacnoc` executable. **AppImage
was not built** — Windows cannot produce one (see the target table above) — and
**no macOS artifact was built on this host.** The unsigned-install caveats below
apply identically to this cut; the Linux archive carries no signature of any kind
and the SHA-256 above is its only integrity check.

Two findings in this release are worth reading before deploying it, because both
changed a safety behaviour rather than adding a feature:

- **Emergency stop and proxy shutdown now DROP held requests** instead of
  forwarding them. If any local workflow depended on the queue being flushed to
  the target on shutdown, it will not be any more — by design.
- **The `ca-trust` preflight check counts proxy-decrypted HTTPS only.** A project
  that previously reported "TLS interception is working" on the strength of
  Repeater traffic will now correctly report that it is not.

### v0.5.2 — built UNSIGNED, never tagged (operator decision, 2026-08-09)

`v0.5.2` (the wiring QA/QC pass — see `CHANGELOG.md`) was built locally with **no
code signing**, the same deliberate operator decision as every cut before it. It
was **not** tagged — see the correction above.
`electron-builder` logs `signing with signtool.exe` during the
build; with no certificate configured nothing is applied, and
`Get-AuthenticodeSignature` on the artifacts reports `NotSigned`. Verified rather
than assumed.

Gate: 333 unit tests green, all 9 E2E specs green **including
`packaged.spec.ts` against the binaries below**, full-tree `npm audit` clean
(the `js-yaml` and `nanoid` advisories were cleared in the lockfile — both build
tooling, neither in the shipped runtime), SBOM regenerated. Windows x64:

| Artifact | SHA-256 |
|---|---|
| `TACNOC-0.5.2-Portable-x64.exe` (portable) | `05c7c74fc75ac43852d49166d010951a581ffe6c0ad07c5ceec7c952fcb9a4e8` |
| `TACNOC-0.5.2-Setup-x64.exe` (NSIS) | `e5476730132e56e0ee58821698a848dc6abcb11591384028eaaf30cafc646e0f` |

Manifest: `dist/SHA256SUMS-windows.txt`. macOS/Linux artifacts were not built on
this host. The unsigned-install caveats below apply identically to this cut.

This is the first cut where `npm run ci` passes in full. `format:check` had been
failing on every file on any Windows checkout — Git for Windows checks out CRLF,
prettier is pinned to `endOfLine: lf` — which is what killed the v0.4.0 and
v0.4.1 release builds on `windows-latest` ("Code style issues found in 130
files") and left both without artifacts. A `.gitattributes` with
`* text=auto eol=lf` fixes the checkout; the index was already LF, so nothing was
reformatted. `ci.yml` also triggered only on `main` while the default branch is
`master`, so the gate had never run on a push or PR at all; both branch names are
now listed.

### v0.2.0 — cut UNSIGNED (operator decision, 2026-07-17)

> Built and shipped before the app was renamed to TACNOC — the artifacts below
> are genuinely named `GreyNOC Belcher-...`; that's what those SHA-256 hashes
> were computed against, so the old name is kept here for accuracy.

`v0.2.0` (the QA/QC pass — see `CHANGELOG.md`) was built and tagged locally with
**no code signing**, a deliberate operator decision. Quality gate green (138
unit/integration tests), production `npm audit` clean, and the packaged binary
verified via `test/e2e/packaged.spec.ts`. Windows x64 artifacts:

| Artifact | SHA-256 |
|---|---|
| `GreyNOC Belcher-0.2.0-x64.exe` (NSIS) | `be673d0c2dcc006dd901afad342d52c5d785b8bccb959d2989a518dda4397ce8` |
| `GreyNOC Belcher-0.2.0-x64.zip` (portable) | `8cf0285cfe76b40a35ccb924af1cad582e5761b31abff03eca68b925e98e407f` |

Manifest: `dist/SHA256SUMS-windows.txt`. macOS/Linux artifacts were not built on
this host. The unsigned-install caveats below (SmartScreen/Gatekeeper, no
in-binary proof of origin) apply identically to this cut.

### v0.1.0 — cut UNSIGNED (operator decision, 2026-07-16)

> Also predates the TACNOC rename — same accuracy note as v0.2.0 above.

`v0.1.0` was built and tagged locally with **no code signing**, a deliberate
operator decision recorded here rather than silently shipped. Windows x64
artifacts, verified against the packaged binary (see above):

| Artifact | SHA-256 |
|---|---|
| `GreyNOC Belcher-0.1.0-x64.exe` (NSIS) | `a112539d46e91e19a8643d72c1349c4cc7408c5ce5d9885d850395e961f9e395` |
| `GreyNOC Belcher-0.1.0-x64.zip` (portable) | `7fe649c96a623116a99ff056c7f4038f0e5e5eff468b2be55bf41f605c002a72` |

Manifest: `dist/SHA256SUMS-windows.txt`. macOS/Linux artifacts were not built on
this host.

**What unsigned means for anyone installing this build:**

- Windows SmartScreen shows "Windows protected your PC" / unknown publisher;
  installing requires an explicit *More info → Run anyway*.
- macOS Gatekeeper blocks the app outright (unsigned + unnotarized).
- There is **no cryptographic proof of origin or integrity in the binary
  itself** — the SHA-256 manifest above is the only integrity check, and it is
  only meaningful if obtained over a channel independent of the artifact.

Verify before running:

```bash
sha256sum -c SHA256SUMS-windows.txt          # Linux/macOS/Git Bash
Get-FileHash '.\GreyNOC Belcher-0.1.0-x64.exe' -Algorithm SHA256   # PowerShell
```

Configure the signing secrets above to have CI produce signed artifacts for the
next cut.

## CI

- `ci.yml` runs the quality gate + build + full dependency audit + SBOM on every push
  and PR to `master` (the default branch) or `main`.
- `release.yml` (on a `v*` tag) builds installers across Windows/macOS/Linux,
  checksums them, generates the SBOM, and **drafts** a GitHub release with the
  artifacts attached.

## Reproducibility

- **The builds are not bit-reproducible.** Packaging the same commit twice
  produces artifacts of identical size but different SHA-256 — electron-builder
  embeds build-time metadata. So a recorded hash identifies *one specific build*,
  not "the build of this commit": re-cutting a release invalidates the hashes
  already published for it. Record the hashes from the artifacts you actually
  ship, and re-record them if you rebuild.
- `package-lock.json` pins the dependency tree; CI uses `npm ci`.
- `sbom.json` and per-OS `SHA256SUMS-<os>.txt` manifests accompany each release
  for verification.
- No native build step is required (SQLite is WASM; the CA is pure JS).
