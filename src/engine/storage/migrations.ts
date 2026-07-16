/**
 * Versioned schema migrations.
 *
 * Migrations are applied in order inside a transaction; `PRAGMA user_version`
 * tracks the applied schema version. Never edit a shipped migration — add a new
 * one. This is what makes "close and reopen the project without losing data"
 * safe across releases.
 */

import type { Database } from './database.js';

export interface Migration {
  version: number;
  name: string;
  up: (db: Database) => void;
}

const migration001: Migration = {
  version: 1,
  name: 'initial schema',
  up(db) {
    db.exec(`
      CREATE TABLE project_meta (
        key   TEXT PRIMARY KEY,
        value TEXT NOT NULL
      );

      CREATE TABLE exchanges (
        id                TEXT PRIMARY KEY,
        created_at        INTEGER NOT NULL,
        source            TEXT NOT NULL,
        scheme            TEXT NOT NULL,
        host              TEXT NOT NULL,
        port              INTEGER NOT NULL,
        in_scope          INTEGER NOT NULL,
        automated         INTEGER NOT NULL DEFAULT 0,
        job_id            TEXT,

        method            TEXT NOT NULL,
        target            TEXT NOT NULL,
        url               TEXT NOT NULL,
        req_http_version  TEXT NOT NULL,
        req_headers       TEXT NOT NULL,
        req_body_size     INTEGER NOT NULL DEFAULT 0,
        req_body_trunc    INTEGER NOT NULL DEFAULT 0,
        req_body_enc      TEXT,
        req_body_blob     TEXT,
        req_body_inline   BLOB,

        status_code       INTEGER,
        status_message    TEXT,
        res_http_version  TEXT,
        res_headers       TEXT,
        res_body_size     INTEGER NOT NULL DEFAULT 0,
        res_body_trunc    INTEGER NOT NULL DEFAULT 0,
        res_body_enc      TEXT,
        res_body_blob     TEXT,
        res_body_inline   BLOB,
        mime              TEXT,

        timing_started    INTEGER,
        timing_ttfb       INTEGER,
        timing_duration   INTEGER,

        notes             TEXT,
        tags              TEXT NOT NULL DEFAULT '[]',
        error             TEXT
      );

      CREATE INDEX idx_exchanges_created ON exchanges(created_at);
      CREATE INDEX idx_exchanges_host    ON exchanges(host);
      CREATE INDEX idx_exchanges_status  ON exchanges(status_code);
      CREATE INDEX idx_exchanges_method  ON exchanges(method);
      CREATE INDEX idx_exchanges_scope   ON exchanges(in_scope);
      CREATE INDEX idx_exchanges_source  ON exchanges(source);
      CREATE INDEX idx_exchanges_mime    ON exchanges(mime);

      CREATE TABLE findings (
        id             TEXT PRIMARY KEY,
        exchange_id    TEXT NOT NULL,
        dedupe_key     TEXT NOT NULL,
        title          TEXT NOT NULL,
        severity       TEXT NOT NULL,
        confidence     TEXT NOT NULL,
        module         TEXT NOT NULL,
        module_version TEXT NOT NULL,
        description    TEXT NOT NULL,
        remediation    TEXT NOT NULL,
        evidence       TEXT NOT NULL,
        created_at     INTEGER NOT NULL,
        suppressed     INTEGER NOT NULL DEFAULT 0,
        note           TEXT,
        FOREIGN KEY (exchange_id) REFERENCES exchanges(id) ON DELETE CASCADE
      );

      CREATE INDEX idx_findings_exchange ON findings(exchange_id);
      CREATE INDEX idx_findings_dedupe   ON findings(dedupe_key);
      CREATE INDEX idx_findings_severity ON findings(severity);

      CREATE TABLE suppressions (
        id         TEXT PRIMARY KEY,
        module     TEXT,
        dedupe_key TEXT,
        host       TEXT,
        reason     TEXT NOT NULL,
        created_at INTEGER NOT NULL
      );

      CREATE TABLE audit_log (
        id      INTEGER PRIMARY KEY AUTOINCREMENT,
        ts      INTEGER NOT NULL,
        actor   TEXT NOT NULL,
        action  TEXT NOT NULL,
        target  TEXT,
        detail  TEXT,
        job_id  TEXT
      );

      CREATE INDEX idx_audit_ts  ON audit_log(ts);
      CREATE INDEX idx_audit_job ON audit_log(job_id);

      CREATE TABLE saved_requests (
        id         TEXT PRIMARY KEY,
        name       TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        scheme     TEXT NOT NULL,
        host       TEXT NOT NULL,
        port       INTEGER NOT NULL,
        raw        TEXT NOT NULL,
        notes      TEXT
      );

      CREATE TABLE variation_jobs (
        id          TEXT PRIMARY KEY,
        created_at  INTEGER NOT NULL,
        name        TEXT NOT NULL,
        base_url    TEXT NOT NULL,
        status      TEXT NOT NULL,
        total       INTEGER NOT NULL DEFAULT 0,
        completed   INTEGER NOT NULL DEFAULT 0,
        config      TEXT NOT NULL
      );
    `);
  },
};

const migration002: Migration = {
  version: 2,
  name: 'websocket messages',
  up(db) {
    db.exec(`
      CREATE TABLE ws_messages (
        id          TEXT PRIMARY KEY,
        exchange_id TEXT NOT NULL,
        seq         INTEGER NOT NULL,
        direction   TEXT NOT NULL,          -- 'c2s' | 's2c'
        kind        TEXT NOT NULL,          -- text | binary | ping | pong | close
        size        INTEGER NOT NULL,       -- full payload size on the wire
        truncated   INTEGER NOT NULL DEFAULT 0,
        payload     BLOB,                   -- captured payload (encrypted at rest)
        created_at  INTEGER NOT NULL,
        FOREIGN KEY (exchange_id) REFERENCES exchanges(id) ON DELETE CASCADE
      );
      CREATE INDEX idx_ws_exchange ON ws_messages(exchange_id, seq);
    `);
  },
};

/** Ordered list of all migrations. Append-only. */
export const MIGRATIONS: Migration[] = [migration001, migration002];

export const CURRENT_SCHEMA_VERSION = MIGRATIONS[MIGRATIONS.length - 1]!.version;

export function applyMigrations(db: Database): void {
  const current = db.getUserVersion();
  for (const migration of MIGRATIONS) {
    if (migration.version > current) {
      db.transaction(() => {
        migration.up(db);
      });
      db.setUserVersion(migration.version);
    }
  }
}
