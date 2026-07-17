# Extension SDK

Extensions add capabilities — passive checks, data transforms, read-only editor
tabs, context-menu actions, findings, and sanitized traffic subscriptions —
through a **versioned, capability-based** API. The current SDK version is
`1.0.0`.

## Contract

An extension is a CommonJS module that exports `activate(belcher)`:

```js
function activate(belcher) {
  belcher.log('hello from my extension, sdk ' + belcher.version);
  // register capabilities here (each guarded by a feature check)
}
module.exports = { activate: activate };
```

It ships with a `manifest.json`:

```json
{
  "id": "my-ext",
  "name": "My Extension",
  "version": "1.0.0",
  "description": "What it does.",
  "author": "you",
  "sdkVersion": "1.0.0",
  "permissions": ["passive-checks", "transforms"]
}
```

## Permissions (capabilities)

The host injects **only** the API methods the manifest declares *and* the user
approved. No permission grants filesystem, process, network, or secret access
through the SDK. This is a capability *grant* boundary, not a sandbox guarantee:
the child process itself has ambient Node built-ins (see *Isolation model* below),
so the real protections are the OS process boundary and the redaction of every
exchange handed to an extension — not the absence of these API methods.

| Permission | Grants | Elevated? |
|---|---|---|
| `read-traffic` | `belcher.onTraffic(cb)` — **sanitized** traffic events (redacted headers, no bodies) | ✅ requires explicit approval |
| `passive-checks` | `belcher.registerScannerCheck(check)` | |
| `transforms` | `belcher.registerTransform(t)` | |
| `findings` | `belcher.createFinding(f)` | ✅ requires explicit approval |
| `ui-tabs` | `belcher.registerEditorTab(tab)` — `render()` returns **plain text** | |
| `context-menu` | `belcher.registerContextMenuAction(a)` | |

`belcher.log(msg)` is always available and writes to the redacted local log.

> **Note:** `ui-tabs` and `context-menu` registrations are accepted and validated
> by the host, but the desktop UI does not yet render editor tabs or context-menu
> actions — they are inert until that surface lands. `passive-checks`,
> `transforms`, `read-traffic`, and `findings` are fully wired end-to-end.

## Isolation model — and its limits

Extensions run in a dedicated **child process**, separate from the host. It is
forked from a bootstrap written to a private temp file, with a **minimal
environment** (most env vars scrubbed), a **bounded heap**
(`--max-old-space-size=256`), **no inherited stdio** (extension `console` is
tunneled as log messages), and its **own working directory**. Under Electron it
is forked as plain Node via `ELECTRON_RUN_AS_NODE`.

The host and the extension exchange only IPC messages over a capability RPC
bridge — the extension never receives a reference to any host object (engine,
session, secrets, DB), and it lives in a **separate OS memory space**, so even a
full escape cannot read host-process memory. Inside the child, each extension is
*additionally* evaluated in a Node `vm` context that exposes only the `belcher`
API and a minimal `console`, with no `require`/`process`/`module` in scope,
in-context code generation (`eval`/`new Function`) disabled, and a time-boxed
top-level evaluation.

Passive checks and transforms execute in the child and are invoked by the host
via async RPC (with a timeout so a hung extension can't block the scan pipeline);
findings/evidence come back as plain data and are re-redacted by the host before
storage.

**This is a strong boundary — a separate OS process plus an inner `vm` — but not
a full OS sandbox.** The child process still has Node built-ins, so a determined
escape from the `vm` could use them *within the isolated child* (with no access
to host objects, memory, or the DB). Hardening it further with OS primitives
(seccomp-bpf on Linux, AppContainer on Windows, `sandbox_init` on macOS) is the
planned next step. Only load extensions you trust; elevated permissions require
explicit approval.

## Sanitized traffic events

`onTraffic` handlers receive redacted metadata only — method, URL (sensitive
query params redacted), redacted request/response headers, status, and MIME.
Bodies are intentionally not included. Passive checks registered via
`registerScannerCheck` also receive a **redacted** exchange: request/response
headers and the URL are passed through the redactor and body text is redacted
before it crosses into the child, so the non-elevated `passive-checks` permission
never sees more raw secret material than the sanitized `read-traffic` path. Their
**evidence is re-redacted** by the runner before storage.

## Example extension

A complete, harmless example lives in
[`examples/extensions/header-hygiene/`](../examples/extensions/header-hygiene/):

- a passive check that flags an exposed `X-Debug` header,
- a ROT13 transform,
- a sanitized-traffic counter,
- a read-only "Header Summary" editor tab.

Load it from the **Extensions** view ("Load bundled example"). It is covered by
`test/engine/sdk.test.ts`, which also verifies capability gating and that the
`vm` sandbox blocks `require`.

## Versioning

`sdkVersion` in the manifest is checked against the host SDK version. Breaking
API changes bump the SDK major version; additive changes bump minor. Host getters
(`getScannerChecks`, `getTransforms`, `getEditorTabs`, `getContextMenuActions`,
`drainCreatedFindings`) namespace extension artifacts by extension id.
