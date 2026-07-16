/**
 * Thin wrapper over SQLite. Backed by `node-sqlite3-wasm` — a pure-WASM SQLite
 * build with a synchronous API and real on-disk persistence.
 *
 * Why WASM (see ADR 0002/0003): it runs identically under the test runner's Node
 * AND under Electron's bundled Node, with NO native rebuild and NO dependency on
 * a specific Node version's built-in `node:sqlite` (which Electron's Node lacks).
 * That makes the tests verify exactly what ships.
 */

import { createRequire } from 'node:module';
import { applyMigrations, CURRENT_SCHEMA_VERSION } from './migrations.js';

export type SqlParam = string | number | bigint | null | Uint8Array;
export type Row = Record<string, SqlParam>;

interface WasmDatabase {
  exec(sql: string): void;
  run(sql: string, params?: unknown[]): { changes: number; lastInsertRowid: number | bigint };
  get(sql: string, params?: unknown[]): Record<string, SqlParam> | undefined;
  all(sql: string, params?: unknown[]): Record<string, SqlParam>[];
  close(): void;
}
interface WasmModule {
  Database: new (location: string, options?: { fileMustExist?: boolean }) => WasmDatabase;
}

// Loaded via createRequire so bundlers don't try to statically process the wasm.
const nodeRequire = createRequire(import.meta.url);
const { Database: WasmDb } = nodeRequire('node-sqlite3-wasm') as WasmModule;

export class Database {
  private constructor(private readonly db: WasmDatabase) {}

  static open(location: string): Database {
    const db = new WasmDb(location);
    // WAL is unsupported by the WASM VFS (it falls back to rollback journaling);
    // we use the default durable journal and enable FK enforcement.
    db.exec('PRAGMA foreign_keys = ON;');
    const wrapper = new Database(db);
    applyMigrations(wrapper);
    return wrapper;
  }

  static openInMemory(): Database {
    const db = new WasmDb(':memory:');
    db.exec('PRAGMA foreign_keys = ON;');
    const wrapper = new Database(db);
    applyMigrations(wrapper);
    return wrapper;
  }

  exec(sql: string): void {
    this.db.exec(sql);
  }

  run(sql: string, ...params: SqlParam[]): { changes: number; lastInsertRowid: number | bigint } {
    const result = params.length ? this.db.run(sql, params) : this.db.run(sql);
    return { changes: Number(result.changes), lastInsertRowid: result.lastInsertRowid };
  }

  get<T = Row>(sql: string, ...params: SqlParam[]): T | undefined {
    return (params.length ? this.db.get(sql, params) : this.db.get(sql)) as T | undefined;
  }

  all<T = Row>(sql: string, ...params: SqlParam[]): T[] {
    return (params.length ? this.db.all(sql, params) : this.db.all(sql)) as T[];
  }

  /** Run `fn` inside an IMMEDIATE transaction, rolling back on any throw. */
  transaction<T>(fn: () => T): T {
    this.db.exec('BEGIN IMMEDIATE;');
    try {
      const out = fn();
      this.db.exec('COMMIT;');
      return out;
    } catch (err) {
      try {
        this.db.exec('ROLLBACK;');
      } catch {
        /* ignore rollback failure */
      }
      throw err;
    }
  }

  getUserVersion(): number {
    const row = this.db.get('PRAGMA user_version') as { user_version: number } | undefined;
    return row?.user_version ?? 0;
  }

  setUserVersion(version: number): void {
    // PRAGMA does not accept bound params.
    this.db.exec(`PRAGMA user_version = ${Math.trunc(version)}`);
  }

  get schemaVersion(): number {
    return CURRENT_SCHEMA_VERSION;
  }

  close(): void {
    this.db.close();
  }
}
