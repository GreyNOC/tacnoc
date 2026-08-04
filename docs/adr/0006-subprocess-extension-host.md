# ADR 0006 — Subprocess-isolated extension host

- Status: Accepted
- Date: 2026-07-16
- Supersedes the extension-isolation portion of ADR 0004 and the "Not changed"
  note in ADR 0005.

## Context

Through ADR 0004/0005 the extension boundary was a **worker thread** with an
inner `vm`. A worker thread has its own JS heap but shares the process: it keeps
full Node built-ins (`fs`, `net`, `child_process`, …), so a `vm` escape inside a
worker still lands in a context with ambient authority over the host machine.
That kept extensions at "trusted-extensions-only" and left "OS-sandboxed
subprocess" as the documented next step.

M11a takes that step: extensions now run in a **dedicated child process**, not a
worker thread.

## Decision

`ExtensionHost` (`src/sdk/host.ts`) writes the child bootstrap
(`EXTENSION_HOST_SOURCE`, `src/sdk/subprocessRuntime.ts`) to a private, mode-0600
temp `.cjs` file and `fork()`s it with:

- `env` scrubbed to the launch essentials plus `ELECTRON_RUN_AS_NODE=1`, so it
  runs as plain Node even under Electron (no Electron/app env leaks in);
- `execArgv: ['--max-old-space-size=256']` to bound the heap;
- `stdio: ['ignore','ignore','ignore','ipc']` — no inherited stdio, IPC only;
- `serialization: 'advanced'`, its own `cwd`, and `unref()` so it never keeps the
  app alive.

The host and child exchange **only structured-cloneable IPC messages** — no
shared object references. Inside the child, each extension is still evaluated in
a `vm` context with no `require`/`process`/`module` in scope (defense in depth)
and a 2 s top-level time box. Passive checks, transforms, tab renders and
context-menu actions are invoked over an async RPC bridge with a per-call
timeout; `createFinding()` is delivered immediately as a child→host message.

A separate OS process is a materially stronger boundary than a worker thread: a
full `vm` escape in the child reaches only the child's own process — it cannot
read the engine, session, secret store, DB, or CA in the host process. It is
still **not** a full OS sandbox (no seccomp / AppContainer / `sandbox-exec`); the
child retains Node built-ins, so "only load extensions you trust" remains the
posture, now with a much smaller blast radius. A kernel-level sandbox is the
remaining future step.

## Lifecycle / fail-closed

- The host tracks the child; on **unexpected** death it drops ALL extension
  capabilities (checks/transforms/tabs/actions/traffic subscribers) and logs an
  error, so the app never advertises checks that can no longer run (fail-closed,
  not a silent detection bypass). Reload re-establishes them.
- `dispose()` on `TacnocSession` — wired to the Electron `before-quit` — stops
  automated work, closes the project, and `terminate()`s the child (SIGKILL
  fallback after a graceful `shutdown`), then removes the temp bootstrap dir. The
  extension host lives for the whole session, so it is torn down only here.

## M11c — second-round adversarial review (confirmed, fixed with tests)

A second multi-agent review fanned out to refute the subprocess host and the
release config. Confirmed and fixed:

1. **`ready` could become an unhandled rejection** if the child died before
   emitting `ready`. Fix: single-settle guard + a swallowing `.catch` on the
   internal promise; awaiters still see the rejection.
2. **Extension host child + temp dir leaked per app launch** — nothing terminated
   it. Fix: `TacnocSession.dispose()` → `ExtensionHost.terminate()`, wired to
   `before-quit`.
3. **Failed-`activate()` rollback deleted a same-id extension's live
   registrations.** Fix: snapshot the registries before `activate()` and roll back
   only the delta this activation added. (Also guarded at the host: a duplicate
   id is now rejected before it reaches the child.)
4. **`runChecks` shared one mutable exchange across all checks**, letting one
   check perturb what later checks (even `appliesTo`) observe. Fix: each check
   gets its own `structuredClone` of the exchange.
5. **A malformed child IPC message / finding could crash the host** listener. Fix:
   the `message` handler is fully wrapped; findings are shape-validated and every
   field is coerced defensively in `materialize()`.
6. **Silent capability loss on child crash.** Fix: fail-closed clearing + loud
   error (above); RPCs then reject fast instead of hanging.
7. **`terminate()` could hang** when the child was killed by a signal (`exitCode`
   stays `null`). Fix: early-resolve on the `dead` flag the exit handler sets.
8. **Per-OS `SHA256SUMS.txt` collided** in the flattened release upload (three
   OS legs, one basename). Fix: write `SHA256SUMS-<os>.txt`; generate/upload the
   lockfile-derived SBOM once (on Linux).
9. **Checksum manifest listed non-distributed files** (`latest*.yml`,
   `.blockmap`). Fix: narrow the artifact set to the installers/archives actually
   uploaded.

Regressions live in `test/engine/sdk.test.ts` (same-id guard, malformed-finding
survival, field coercion, fail-closed on child death) and the checksums script
was exercised end-to-end.

## Consequences

- Extension escapes are contained to a throwaway child process with a bounded
  heap and scrubbed env; host secrets/engine/DB are unreachable across the IPC
  boundary.
- The `vm` remains a defense-in-depth layer, no longer the boundary.
- Residual risk: not a kernel sandbox; trusted-extensions-only stands. Documented
  in THREAT_MODEL.md and docs/extension-sdk.md.
