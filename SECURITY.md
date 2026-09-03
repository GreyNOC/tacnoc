# Security policy

## Intended use

TACNOC is for **authorized** security research only: sanctioned
engagements, your own systems, CTFs, and defensive/educational work. Using it
against systems you are not authorized to test may be illegal. See
[docs/authorization-and-scope.md](docs/authorization-and-scope.md).

## Security properties (by design)

- **No telemetry.** There is no analytics, no usage reporting, no update check,
  and no network sink for logging. The tool never phones home.
- **One outbound path exists, and only when you switch it on — the AI mesh.**
  From v0.4.0, TACNOC can drive an LLM to help work an engagement. When it does,
  **captured request and response content — including any secrets, cookies, and
  PII it contains — and the documents in the engagement folder are sent to the
  configured model provider.** It is disabled by default and refuses to start
  without a per-project egress acknowledgement; the acknowledgement is written to
  the audit log, and optional best-effort redaction can mask secrets first. If
  your rules of engagement forbid third-party processing of captured data, leave
  the mesh off — every other part of TACNOC is entirely local. See
  [docs/engagement-and-hunting.md](docs/engagement-and-hunting.md).
- **Loopback-first.** The proxy binds `127.0.0.1` by default; other binds are
  flagged.
- **Fail-closed scope** for all automated request generation, enforced in the
  engine.
- **Emergency stop + audit log** for automated work.
- **Secret redaction** in logs, findings evidence, and exports; **warn-before-
  reveal** for cookies/authorization/tokens.
- **Local CA**, key held in OS secure storage; the app never modifies OS trust.
- **Hardened renderer**: `contextIsolation`, `sandbox`, `nodeIntegration:false`,
  strict CSP, external links opened in the OS browser, in-app navigation blocked.
- **Captured content is never executed** — shown as inert text/hex.

## Handling secrets

- Do not commit project folders, `*.tacnocproj`, CA certs/keys, or exports. These
  are covered by `.gitignore`.
- Exported project files may contain captured request/response bodies. Redaction
  applies to logs and findings evidence; **the raw project export includes
  captured bytes** for fidelity — treat exports as sensitive and share
  deliberately.
- Prefer sanitized report export when sharing findings externally.

## Reporting a vulnerability

If you find a security issue in TACNOC itself, please report it
privately to the GreyNOC maintainers rather than opening a public issue. Include
reproduction steps and affected version/commit. We follow coordinated
disclosure.

## Dependency & supply-chain hygiene

- `package-lock.json` pins the dependency tree; use `npm ci` for reproducible
  installs.
- `npm run audit` runs `npm audit` on production dependencies.
- No native build steps are required (SQLite is WASM, the CA is pure JS),
  reducing build-time supply-chain surface.

## Known limitations relevant to security

See [THREAT_MODEL.md](THREAT_MODEL.md) — notably:

- **At-rest encryption covers message *content*** (bodies, headers, WebSocket
  payloads, AES-256-GCM under a per-project key in OS secure storage) but **not
  operational metadata** — host, URL, method, status, MIME, timing, and tags stay
  plaintext so history remains searchable. Project **exports are deliberately
  plaintext**; treat them as sensitive.
- **The extension sandbox is a separate child process** (scrubbed env, bounded
  heap, IPC-only bridge) with an inner `vm`. That is a strong boundary but **not
  a hardened OS sandbox** (no seccomp/AppContainer) — only load extensions you
  trust.
- **HTTP/3 / QUIC interception is not implemented.** HTTP/2 *is* intercepted, via
  ALPN `h2` and translated to HTTP/1.1 upstream.
- **The interception CA is trusted only where you install it.** The app never
  modifies an OS trust store; installing and removing it is a manual step.
