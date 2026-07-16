/**
 * Controlled request-variation types (Phase 4).
 *
 * Payloads come from user-provided lists, numeric ranges, or a curated set of
 * SAFE STRUCTURAL test strings (boundary/encoding values). There are NO built-in
 * password lists, credential dictionaries, injection/exploit payloads, or
 * destructive/DoS workflows — by design.
 */

import type { AutomationLimits } from './config.js';
import type { Scheme } from './model.js';

export type VariationMode = 'sniper' | 'batteringram' | 'pitchfork' | 'clusterbomb';

export type PayloadSource =
  | { kind: 'list'; values: string[] }
  | { kind: 'range'; from: number; to: number; step: number }
  | { kind: 'builtin'; set: 'safe-structural' };

export interface VariationPosition {
  /** Placeholder marker present in the base raw request, e.g. "{{0}}". */
  marker: string;
  source: PayloadSource;
  /** Value used for this position when another position is being varied (sniper). */
  baseValue?: string;
}

export interface VariationBaseRequest {
  scheme: Scheme;
  host: string;
  port: number;
  /** Raw request text containing the position markers. */
  raw: string;
}

export interface VariationPlan {
  name: string;
  base: VariationBaseRequest;
  positions: VariationPosition[];
  mode: VariationMode;
  limits: AutomationLimits;
  /** Optional regex strings extracted from responses and shown as markers. */
  responseMarkers?: string[];
}

export type JobStatus = 'created' | 'running' | 'paused' | 'completed' | 'stopped' | 'error';

export interface VariationResultRow {
  index: number;
  payloads: string[];
  requestId: string;
  status: number;
  responseLength: number;
  durationMs: number;
  ttfbMs: number;
  inScope: boolean;
  skipped?: boolean;
  error?: string;
  markerHits?: string[];
}

export interface JobProgress {
  id: string;
  name: string;
  status: JobStatus;
  total: number;
  completed: number;
  skipped: number;
  errors: number;
  startedAt?: number;
  finishedAt?: number;
}
