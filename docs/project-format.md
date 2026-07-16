# Project format

A GreyNOC Belcher project is a **directory** (conventionally `NAME.gnbproj/`)
plus a **versioned portable export** for sharing/backup.

## On-disk project directory

```
NAME.gnbproj/
  belcher.db          SQLite database (WASM SQLite; metadata, history rows,
                      findings, suppressions, audit log, saved requests, jobs)
  blobs/              content-addressed body store  <aa>/<bb>/<sha256>
  ca.pem              public project CA certificate (safe to share)
  secrets.enc.json    CA private key, encrypted via OS secure storage
                      (only present with the safeStorage backend)
  secrets.json/.key   file-fallback secret store (headless/CI only; NOT secure)
```

- **Bodies** are stored in `blobs/`, deduplicated, so `belcher.db` stays small.
  Small bodies are inlined in the DB. In an encrypted project the blob id
  (filename) is a **keyed HMAC** under a subkey of the project data key — NOT a
  plaintext SHA-256 — so a keyless attacker who copies the folder cannot compute
  or confirm blob ids from candidate plaintext. (In the unencrypted low-level
  path used only by tests, a plain SHA-256 is used.)
- **Encryption at rest:** bodies (blob files + inline BLOBs), request/response
  header JSON, and WebSocket payloads are AES-256-GCM encrypted under a
  per-project data key held in the SecretStore (OS secure storage). Metadata
  columns (host, URL, method, status, MIME, timing, tags) stay plaintext so
  history remains searchable. Without the key, content is unreadable; a wrong
  key or tampering is detected by the GCM auth tag. See THREAT_MODEL.md.
- **Reopening** a project applies any pending migrations and restores all
  captured data. Migrations are additive and tracked by `PRAGMA user_version`
  (see `src/engine/storage/migrations.ts`); the current schema version is 2
  (adds `ws_messages`).

### Database schema (v1)

Tables: `project_meta` (info/scope/config as JSON), `exchanges` (flattened
request/response with indexes on time/host/status/method/scope/source/mime),
`findings`, `suppressions`, `audit_log`, `saved_requests`, `variation_jobs`.

## Portable export/import

`export` produces a single **versioned JSON** document
(`*.gnbexport.json`) that can be re-imported into a new project directory.

```jsonc
{
  "format": "greynoc-belcher-project",
  "formatVersion": 1,
  "exportedAt": 1730000000000,
  "info":   { "name": "...", "createdAt": 0, "formatVersion": 1, "appVersion": "0.1.0" },
  "scope":  { "include": [ ... ], "exclude": [ ... ] },
  "config": { "listener": { ... }, "limits": { ... }, "redaction": { ... } },
  "exchanges": [
    {
      "id": "...", "scheme": "https", "host": "...", "port": 443,
      "request":  { "method": "GET", "target": "/", "headers": [ ... ] },
      "requestBody":  { "size": 0, "truncated": false, "dataB64": "..." },
      "response": { "statusCode": 200, "headers": [ ... ] },
      "responseBody": { "size": 12, "truncated": false, "dataB64": "..." }
    }
  ],
  "findings": [ ... ],
  "suppressions": [ ... ],
  "savedRequests": [ ... ],
  "audit": [ ... ]
}
```

### Notes

- Bodies are base64-inlined for fidelity. Bodies larger than the export cap
  (default 25 MiB) are marked `"omitted": true` and carried as metadata only.
- Import **refuses** exports whose `formatVersion` is newer than the running app
  supports, and rebuilds the DB + blob store from the document.
- **Exports contain captured bytes** (headers and bodies). Redaction applies to
  logs and findings evidence, *not* to the raw export — treat exports as
  sensitive. Use the sanitized report export when sharing findings externally.

## Compatibility

The on-disk DB evolves via forward-only migrations; a project created by an older
build opens in a newer build. The portable export is versioned independently
(`formatVersion`) so a document can be validated before import.
