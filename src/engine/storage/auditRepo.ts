/**
 * Append-only audit log for automated actions. The variation engine, CA
 * export, and other side-effectful automation record here. Detail objects are
 * redacted before storage.
 */

import type { AuditEntry } from '../../shared/project.js';
import type { Database } from './database.js';
import { Redactor } from '../redaction/redactor.js';

const redactor = new Redactor({
  maskCookies: true,
  maskAuthorization: true,
  maskSecretPatterns: true,
});

export class AuditRepo {
  constructor(private readonly db: Database) {}

  append(entry: AuditEntry): void {
    const detail = entry.detail
      ? JSON.parse(redactor.redactText(JSON.stringify(entry.detail)))
      : null;
    this.db.run(
      `INSERT INTO audit_log (ts, actor, action, target, detail, job_id)
       VALUES (?, ?, ?, ?, ?, ?)`,
      entry.ts,
      entry.actor,
      entry.action,
      entry.target ? redactor.redactUrl(entry.target) : null,
      detail ? JSON.stringify(detail) : null,
      entry.jobId ?? null,
    );
  }

  list(limit = 500, jobId?: string): AuditEntry[] {
    const rows = jobId
      ? this.db.all<AuditRow>(
          'SELECT * FROM audit_log WHERE job_id = ? ORDER BY id DESC LIMIT ?',
          jobId,
          limit,
        )
      : this.db.all<AuditRow>('SELECT * FROM audit_log ORDER BY id DESC LIMIT ?', limit);
    return rows.map(rowToEntry);
  }
}

interface AuditRow {
  id: number;
  ts: number;
  actor: string;
  action: string;
  target: string | null;
  detail: string | null;
  job_id: string | null;
}

function rowToEntry(row: AuditRow): AuditEntry {
  return {
    id: row.id,
    ts: row.ts,
    actor: row.actor,
    action: row.action,
    ...(row.target ? { target: row.target } : {}),
    ...(row.detail ? { detail: JSON.parse(row.detail) as Record<string, unknown> } : {}),
    ...(row.job_id ? { jobId: row.job_id } : {}),
  };
}
