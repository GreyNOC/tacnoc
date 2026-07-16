# Contributing

Thanks for helping build GreyNOC Belcher. This project holds a high bar:
**reproducible or it didn't happen**, and safety controls are features, not
disclaimers.

## Ground rules

- **Authorized-use framing only.** Do not add stealth, persistence, malware,
  phishing, credential-stuffing, DoS, destructive, CAPTCHA-bypass, or
  monitoring-evasion capabilities. Dual-use features must keep the safety
  controls (scope gate, rate limits, audit, emergency stop) intact.
- **No fabrication.** Every finding, indicator, or metric must be reproducible
  from evidence. Passive checks report what they can observe; anything uncertain
  is an *observation* at tentative confidence.
- **No telemetry, ever.** Never add a network sink for logs or captured data.
- **Keep the layers separated** behind the documented interfaces
  (see [ARCHITECTURE.md](ARCHITECTURE.md)). The engine must stay
  Electron-free and headlessly testable.

## Development setup

```bash
npm install
npm run dev            # run the app
npm test               # run the suite
npm run ci             # format:check + lint + typecheck + test (run before PRs)
```

- TypeScript strict mode; ESLint with a **zero-warning** policy; Prettier.
- ESM throughout; import local modules with explicit `.js` extensions (they
  resolve to `.ts` under the bundler and Vitest).
- Storage goes through the `Database` wrapper only; schema changes are **new,
  append-only** migrations (never edit a shipped migration).

## Tests are mandatory

New behavior needs tests. The suite must not depend on public targets — use the
local test server (`test/server/testServer.ts`). See
[docs/testing.md](docs/testing.md). Cover at least: the happy path, a malformed/
hostile input, and any safety control you touch (scope, limits, redaction,
emergency stop).

## Empirical verification

Passing tests is necessary but not sufficient. For engine changes, exercise the
actual behavior (drive the proxy, reopen a project, run a scan). A change that
passes tests but doesn't work when exercised is not done.

## Architecture Decision Records

Significant decisions (stack, storage, trust boundaries, protocol handling) get
an ADR in `docs/adr/`. Superseded ADRs are amended, not deleted.

## Commit / PR expectations

- Small, reviewable changes with a clear rationale.
- Update docs alongside code (README limitations, threat model, relevant
  `docs/*`).
- State plainly what works and what remains incomplete. Never describe an
  unimplemented feature as complete.
