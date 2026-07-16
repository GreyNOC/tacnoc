# Release process

GreyNOC Belcher follows a real quality gate — security review, checks/tests,
SBOM, versioned changelog, tagged commit, CI gate, checksummed artifacts, and a
drafted (not auto-published) release.

## Pre-release checklist

1. **Security review** of the diff since the last tag (scope gate, redaction,
   CA/secret handling, at-rest encryption, extension isolation still intact).
2. **Quality gate:** `npm run ci` (format check, lint, typecheck, tests) — must
   be green. Run `npm run test:e2e` on a machine with a display.
3. **Dependency audit:** `npm audit --omit=dev --audit-level=high`.
4. **SBOM:** `npm run sbom` → `sbom.json` (CycloneDX 1.5).
5. **Version + changelog:** bump `version` in `package.json`, move items from
   *Unreleased* to the new version in `CHANGELOG.md`.
6. **Tag:** commit, then `git tag vX.Y.Z` and push the tag.

`npm run release:prepare` runs the gate + SBOM in one step.

## Building installers

```bash
npm run dist        # builds the app, then electron-builder → dist/
npm run checksums   # writes dist/SHA256SUMS.txt
```

Build on each target OS (or via the `release.yml` GitHub Actions matrix). Output
goes to `dist/`. `node_modules/node-sqlite3-wasm` is unpacked from the asar
(`asarUnpack`) because it ships a `.wasm` asset read at runtime, and the example
extension is shipped under `resources/examples/extensions`.

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
npm run release:prepare      # ci gate + SBOM
# bump version + update CHANGELOG, then:
git tag vX.Y.Z && git push --tags   # triggers release.yml (drafts the release)
```

`v0.1.0` was cut locally as an **unsigned** tag (no signing certificates on the
build host); the CI release workflow will produce signed artifacts once the
secrets above are configured.

## CI

- `ci.yml` runs the quality gate + build + production audit + SBOM on every push
  and PR to `main`.
- `release.yml` (on a `v*` tag) builds installers across Windows/macOS/Linux,
  checksums them, generates the SBOM, and **drafts** a GitHub release with the
  artifacts attached.

## Reproducibility

- `package-lock.json` pins the dependency tree; CI uses `npm ci`.
- `sbom.json` and `SHA256SUMS.txt` accompany each release for verification.
- No native build step is required (SQLite is WASM; the CA is pure JS).
