/**
 * Passive scanner interfaces.
 *
 * A ScannerCheck inspects ONE already-observed exchange and returns zero or more
 * findings. Checks never generate network traffic. The scanner runner fills in
 * ids/timestamps, redacts evidence, and de-duplicates.
 */

import type { HttpExchange } from '../../shared/model.js';
import type { Confidence, FindingEvidence, Severity } from '../../shared/findings.js';
import type { Redactor } from '../redaction/redactor.js';

export interface ScanContext {
  exchange: HttpExchange;
  /** Best-effort decoded request body text (empty if binary/absent). */
  requestBodyText: string;
  /** Best-effort decoded response body text, decompressed if gzip. */
  responseBodyText: string;
  redactor: Redactor;
}

export interface RawFinding {
  /** Stable key (module-relative) for de-dupe + suppression. */
  dedupeKey: string;
  title: string;
  severity: Severity;
  confidence: Confidence;
  description: string;
  remediation: string;
  evidence: FindingEvidence[];
}

export interface ScannerCheck {
  module: string;
  version: string;
  /** Optional gate: skip the check entirely when it returns false. */
  appliesTo?: (exchange: HttpExchange) => boolean;
  run: (ctx: ScanContext) => RawFinding[];
}
