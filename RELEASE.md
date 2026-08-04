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

**Linux one-shot:** `npm run dist:linux` rebuilds and produces
`TACNOC-<version>-linux-x64.tar.gz` — extract it and run `./tacnoc`.

### Which Linux target can be built where

| Target | On Linux | On Windows |
|---|---|---|
| `tar.gz` | yes | **yes** — electron-builder downloads the Linux Electron binary and repackages the app directory; no Linux-only tooling is involved |
| `AppImage` | yes | **no** — packaging creates symlinks inside the image, and Windows refuses those without Developer Mode or elevation, so the build fails with `EPERM` |

A Windows workstation can therefore cut the portable `.exe` **and** a runnable
Linux `tar.gz`, but not an AppImage. Build AppImage on Linux
(`npx electron-builder --linux AppImage`) or through the `release.yml` matrix.

Note that a bare `npm run dist` builds every configured target for the host
platform, so on Windows it will attempt AppImage and fail — use the per-OS
scripts above.

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
  and PR to `main`.
- `release.yml` (on a `v*` tag) builds installers across Windows/macOS/Linux,
  checksums them, generates the SBOM, and **drafts** a GitHub release with the
  artifacts attached.

## Reproducibility

- `package-lock.json` pins the dependency tree; CI uses `npm ci`.
- `sbom.json` and per-OS `SHA256SUMS-<os>.txt` manifests accompany each release
  for verification.
- No native build step is required (SQLite is WASM; the CA is pure JS).
