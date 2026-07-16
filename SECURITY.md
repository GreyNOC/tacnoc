# Security policy

## Intended use

GreyNOC Belcher is for **authorized** security research only: sanctioned
engagements, your own systems, CTFs, and defensive/educational work. Using it
against systems you are not authorized to test may be illegal. See
[docs/authorization-and-scope.md](docs/authorization-and-scope.md).

## Security properties (by design)

- **No telemetry / no external calls.** The tool never sends captured traffic,
  logs, or diagnostics to analytics, telemetry, or external AI services. Logging
  has no network sink.
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

- Do not commit project folders, `*.gnbproj`, CA certs/keys, or exports. These
  are covered by `.gitignore`.
- Exported project files may contain captured request/response bodies. Redaction
  applies to logs and findings evidence; **the raw project export includes
  captured bytes** for fidelity — treat exports as sensitive and share
  deliberately.
- Prefer sanitized report export when sharing findings externally.

## Reporting a vulnerability

If you find a security issue in GreyNOC Belcher itself, please report it
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

See [THREAT_MODEL.md](THREAT_MODEL.md) — notably: at-rest encryption of the
project DB/blobs is not yet implemented; the extension `vm` sandbox is not a
hardened boundary; HTTP/2/3 interception is not implemented.
