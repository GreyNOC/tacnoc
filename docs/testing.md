# Testing

The engine and its integration paths are covered by an automated suite
(**Vitest**). Tests **never depend on public targets** — a deliberately-safe
local test server provides all fixtures. UI end-to-end flows use Playwright
(opt-in) and are otherwise validated manually per the Definition of Done.

## Running

```bash
npm test               # run everything (headless, no network)
npm run test:coverage  # with V8 coverage
npm run test:watch     # watch mode
npm run test:e2e       # Playwright UI E2E (requires a built app + display)
```

The suite runs fully offline: every fixture is a `127.0.0.1` server started
in-process. This *is* the "operation without internet access" guarantee — if the
machine had no network at all, these tests would still pass.

## The local test server

`test/server/testServer.ts` starts HTTP and HTTPS servers on random loopback
ports with deliberately-safe endpoints: `/json`, `/echo-body`, `/chunked`,
`/gzip`, `/binary`, `/large?size=N`, `/set-cookie`, `/dup-headers`,
`/missing-headers`, `/secure-headers`, `/reflect?q=`, `/error`, `/banner`,
`/secret-in-body`, `/redirect`, and a minimal WebSocket upgrade. The HTTPS server
uses a throwaway self-signed cert (`test/server/selfSignedCert.ts`).

## Coverage of the required scenarios

| Required scenario | Where |
|---|---|
| Evidence bundle carries **only** the exact host, never a name that merely contains it | `evidenceBundle.test.ts` |
| Evidence bundle redacts credentials by default; raw is opt-in and announced in README, HANDOFF and manifest | `evidenceBundle.test.ts` |
| Evidence bundle never carries a secret store, private key or database | `evidenceBundle.test.ts` |
| Bundle manifest hashes match the bytes shipped, and the reported bundle hash matches the file written | `evidenceBundle.test.ts` |
| Agent handoff leads with a STOP CONDITION when scope is empty or the target is out of scope | `evidenceBundle.test.ts` |
| ZIP round-trips, detects corruption/truncation, and opens in an extractor this project did not write | `zip.test.ts` |
| Handing a target to the mesh is refused by the same gates a manual run faces (empty scope, out-of-scope host, missing key) | `e2e/evidence-handoff.spec.ts` |
| Proxying ordinary HTTP | `proxy.test.ts` |
| HTTPS interception with a temporary CA | `proxy.test.ts`, `ca.test.ts` |
| CONNECT tunnels | `proxy.test.ts` (HTTPS MITM path) |
| Chunked bodies | `proxy.test.ts` |
| Compressed bodies | `proxy.test.ts` (gzip; encoding preserved, bytes unmutated) |
| Binary bodies | `proxy.test.ts` (byte-for-byte) |
| Malformed requests | `proxy.test.ts` (proxy survives, keeps serving) |
| Large-body limits | `proxy.test.ts` (truncates stored copy, forwards full body) |
| Header duplication & unusual casing | `proxy.test.ts`, `storage.test.ts` |
| Scope matching & bypass attempts | `scope.test.ts`, `proxy.test.ts`, `variation.test.ts` |
| Redaction of cookies/authorization/tokens | `redaction.test.ts`, `scanner.test.ts` |
| DB migration & project reopening | `storage.test.ts` |
| Repeater fidelity | `repeater.test.ts` |
| Passive findings | `scanner.test.ts`, `session.test.ts` |
| Rate & concurrency limits | `variation.test.ts` |
| Cancellation & emergency stop | `variation.test.ts`, `session.test.ts` |
| Operation without internet access | entire suite (loopback only) |
| Export/import round-trip | `storage.test.ts` |
| At-rest encryption (ciphertext on disk, no-key blocks reads) | `storage.test.ts`, `crypto.test.ts` |
| HTTP/2 interception (h2 GET/POST → h1 origin) | `proxy.test.ts` |
| WebSocket frame parsing (mask/fragment/control/oversize) | `wsFrame.test.ts` |
| WebSocket frame capture through the proxy (both directions) | `proxy.test.ts` |
| End-to-end capture → scan → findings via the app facade | `session.test.ts` |
| Extension SDK + process isolation (separate PID, no `process`/`require` in `vm`, same-id guard, rollback, fail-closed on child death, malformed-finding survival) | `sdk.test.ts` |
| Real Electron app: boot, create project, proxy, all views | `e2e/smoke.spec.ts`, `e2e/full.spec.ts` |
| Guided CA setup: optional/skippable, and success claimed **only** on proxy-decrypted HTTPS (a Repeater probe must not satisfy it) | `e2e/ca-setup.spec.ts` |
| CA install guide: per-platform install **and** removal command, narrowest-trust scope, path quoting | `qaqc-v053.test.ts` |
| Emergency stop drops the intercept queue instead of forwarding it | `qaqc-v053.test.ts` |
| Interception evidence excludes engine-generated HTTPS | `qaqc-v053.test.ts` |
| AI provider capability coverage + typed API-failure messages + pre-run credential check | `anthropicProvider.test.ts` |
| **Packaged** artifact: WASM SQLite from `app.asar.unpacked`, example extension from `resourcesPath`, extension child fork out of the packaged binary, loopback default | `e2e/packaged.spec.ts` (auto-skips without `dist/`; run after `npm run dist`) |

## Runtime parity (important)

The storage backend is WASM SQLite (`node-sqlite3-wasm`), which we verified runs
**identically** under the test runner's Node and under **Electron's bundled
Node**. (The original driver for a WASM backend was that the then-current
Electron 33 shipped Node 20.18, which lacks `node:sqlite`; the app now pins
Electron 43 on the Node 22.x line, and WASM SQLite remains the backend so the
tests keep verifying exactly what ships.) See
[adr/0003-sqlite-wasm-backend.md](adr/0003-sqlite-wasm-backend.md).

## Writing tests

- Put fixtures in the local test server; do not reach the network.
- Use `InMemorySecretStore` so no CA key touches disk in tests.
- Force-close servers/sockets in `afterAll` (`closeAllConnections()` + destroy
  upgraded sockets) so suites don't hang on keep-alive/tunnels.
- Cover a happy path, a hostile/malformed input, and any safety control touched.
- Resolve a temp directory with `fs.realpath` before comparing anything the
  engine reports against paths derived from it. The engine canonicalises every
  workspace path; on macOS `os.tmpdir()` is `/var/folders/…`, a symlink to
  `/private/var/folders/…`, so an unresolved temp path names the same directory
  and fails the comparison there and nowhere else — which is how the v0.5.3
  release gate died on `macos-latest`.

## Packaging note

When packaging with electron-builder, ship `node_modules/node-sqlite3-wasm`
**unpacked** (`asarUnpack`) and include `examples/extensions/**` under
`resources/`, because the WASM asset and example files are read from disk at
runtime.
