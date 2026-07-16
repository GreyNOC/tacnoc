/**
 * Passive-scanner finding model. Findings never contain unredacted secrets:
 * evidence strings are passed through the redactor before storage/export.
 */

export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';

export type Confidence = 'tentative' | 'firm' | 'certain';

export const SEVERITY_ORDER: Record<Severity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

export interface FindingEvidence {
  /** Where in the exchange the evidence was found. */
  location: 'request-headers' | 'response-headers' | 'response-body' | 'url' | 'tls';
  /** Redacted excerpt demonstrating the issue. */
  excerpt: string;
  /** Optional header name / field this relates to. */
  field?: string;
}

export interface Finding {
  id: string;
  /** Exchange this finding was derived from. */
  exchangeId: string;
  /** Stable key used for de-duplication and false-positive suppression. */
  dedupeKey: string;
  title: string;
  severity: Severity;
  confidence: Confidence;
  /** Scanner module that produced this finding, and its version. */
  module: string;
  moduleVersion: string;
  description: string;
  remediation: string;
  evidence: FindingEvidence[];
  createdAt: number;
  /** User-controlled suppression: suppressed findings are hidden but retained. */
  suppressed: boolean;
  /** Optional free-form note from the analyst. */
  note?: string;
}

export interface SuppressionRule {
  id: string;
  /** Match by module and/or dedupeKey and/or host. Empty fields are wildcards. */
  module?: string;
  dedupeKey?: string;
  host?: string;
  reason: string;
  createdAt: number;
}
