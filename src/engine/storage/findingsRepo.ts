/** Findings + suppression-rule persistence. */

import type { Finding, FindingEvidence, SuppressionRule, Severity } from '../../shared/findings.js';
import { SEVERITY_ORDER } from '../../shared/findings.js';
import type { Database } from './database.js';

interface FindingRow {
  id: string;
  exchange_id: string;
  dedupe_key: string;
  title: string;
  severity: string;
  confidence: string;
  module: string;
  module_version: string;
  description: string;
  remediation: string;
  evidence: string;
  created_at: number;
  suppressed: number;
  note: string | null;
}

export interface FindingsQuery {
  exchangeId?: string;
  minSeverity?: Severity;
  includeSuppressed?: boolean;
}

export class FindingsRepo {
  constructor(private readonly db: Database) {}

  /**
   * Insert a finding unless an identical one (same exchange + dedupeKey) already
   * exists. Returns true if inserted. Applies suppression rules on insert.
   *
   * `host` is the exchange host, supplied by callers that know it so host-scoped
   * suppression rules can be enforced. When omitted, host-scoped rules do NOT
   * match (fail-safe: a finding is shown rather than silently hidden).
   */
  upsert(finding: Finding, host?: string): boolean {
    const existing = this.db.get<{ id: string }>(
      'SELECT id FROM findings WHERE exchange_id = ? AND dedupe_key = ?',
      finding.exchangeId,
      finding.dedupeKey,
    );
    if (existing) return false;

    const suppressed = finding.suppressed || this.matchesSuppression(finding, host);
    this.db.run(
      `INSERT INTO findings (
        id, exchange_id, dedupe_key, title, severity, confidence, module,
        module_version, description, remediation, evidence, created_at, suppressed, note
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      finding.id,
      finding.exchangeId,
      finding.dedupeKey,
      finding.title,
      finding.severity,
      finding.confidence,
      finding.module,
      finding.moduleVersion,
      finding.description,
      finding.remediation,
      JSON.stringify(finding.evidence),
      finding.createdAt,
      suppressed ? 1 : 0,
      finding.note ?? null,
    );
    return true;
  }

  list(query: FindingsQuery = {}): Finding[] {
    const clauses: string[] = [];
    const params: (string | number)[] = [];
    if (query.exchangeId) {
      clauses.push('exchange_id = ?');
      params.push(query.exchangeId);
    }
    if (!query.includeSuppressed) {
      clauses.push('suppressed = 0');
    }
    const where = clauses.length ? `WHERE ${clauses.join(' AND ')}` : '';
    const rows = this.db.all<FindingRow>(
      `SELECT * FROM findings ${where} ORDER BY created_at DESC`,
      ...params,
    );
    let findings = rows.map(rowToFinding);
    if (query.minSeverity) {
      const min = SEVERITY_ORDER[query.minSeverity];
      findings = findings.filter((f) => SEVERITY_ORDER[f.severity] >= min);
    }
    return findings;
  }

  setSuppressed(id: string, suppressed: boolean): void {
    this.db.run('UPDATE findings SET suppressed = ? WHERE id = ?', suppressed ? 1 : 0, id);
  }

  setNote(id: string, note: string | null): void {
    this.db.run('UPDATE findings SET note = ? WHERE id = ?', note, id);
  }

  count(includeSuppressed = false): number {
    const where = includeSuppressed ? '' : 'WHERE suppressed = 0';
    return this.db.get<{ n: number }>(`SELECT COUNT(*) AS n FROM findings ${where}`)?.n ?? 0;
  }

  // --- suppression rules ---

  addSuppression(rule: SuppressionRule): void {
    this.db.run(
      `INSERT INTO suppressions (id, module, dedupe_key, host, reason, created_at)
       VALUES (?, ?, ?, ?, ?, ?)`,
      rule.id,
      rule.module ?? null,
      rule.dedupeKey ?? null,
      rule.host ?? null,
      rule.reason,
      rule.createdAt,
    );
  }

  listSuppressions(): SuppressionRule[] {
    const rows = this.db.all<{
      id: string;
      module: string | null;
      dedupe_key: string | null;
      host: string | null;
      reason: string;
      created_at: number;
    }>('SELECT * FROM suppressions ORDER BY created_at DESC');
    return rows.map((r) => ({
      id: r.id,
      ...(r.module ? { module: r.module } : {}),
      ...(r.dedupe_key ? { dedupeKey: r.dedupe_key } : {}),
      ...(r.host ? { host: r.host } : {}),
      reason: r.reason,
      createdAt: r.created_at,
    }));
  }

  removeSuppression(id: string): void {
    this.db.run('DELETE FROM suppressions WHERE id = ?', id);
  }

  private matchesSuppression(finding: Finding, host?: string): boolean {
    for (const rule of this.listSuppressions()) {
      // A rule with NO populated matcher must never match everything. (Guards the
      // documented "empty fields are wildcards" semantics from degenerating into
      // "a host-only or empty rule mutes all findings on every host".)
      if (!rule.module && !rule.dedupeKey && !rule.host) continue;
      if (rule.module && rule.module !== finding.module) continue;
      if (rule.dedupeKey && rule.dedupeKey !== finding.dedupeKey) continue;
      if (rule.host) {
        // host is only known when the caller passes it; if unknown, or it doesn't
        // match, this rule does not apply (do not suppress).
        if (host === undefined || host.toLowerCase() !== rule.host.toLowerCase()) continue;
      }
      return true;
    }
    return false;
  }
}

function rowToFinding(row: FindingRow): Finding {
  return {
    id: row.id,
    exchangeId: row.exchange_id,
    dedupeKey: row.dedupe_key,
    title: row.title,
    severity: row.severity as Severity,
    confidence: row.confidence as Finding['confidence'],
    module: row.module,
    moduleVersion: row.module_version,
    description: row.description,
    remediation: row.remediation,
    evidence: JSON.parse(row.evidence) as FindingEvidence[],
    createdAt: row.created_at,
    suppressed: row.suppressed === 1,
    ...(row.note ? { note: row.note } : {}),
  };
}
