/** Project-level shared types (metadata, audit, saved requests, jobs). */

export interface ProjectInfo {
  name: string;
  createdAt: number;
  /** On-disk project format version (see docs/project-format.md). */
  formatVersion: number;
  /** App version that created the project. */
  appVersion: string;
  /** Free-form engagement/authorization reference recorded by the researcher. */
  authorizationRef?: string;
}

export interface AuditEntry {
  id?: number;
  ts: number;
  /** Who/what performed the action, e.g. "variation-engine", "user". */
  actor: string;
  /** Machine-readable action, e.g. "job.start", "job.stop", "ca.export". */
  action: string;
  /** The affected target (URL/host) when applicable. */
  target?: string;
  /** Structured detail; redacted before storage. */
  detail?: Record<string, unknown>;
  jobId?: string;
}

export interface SavedRequest {
  id: string;
  name: string;
  createdAt: number;
  scheme: string;
  host: string;
  port: number;
  /** Raw request text as edited in the repeater. */
  raw: string;
  notes?: string;
}

export type VariationJobStatus =
  'created' | 'running' | 'paused' | 'completed' | 'stopped' | 'error';

export interface VariationJobRecord {
  id: string;
  createdAt: number;
  name: string;
  baseUrl: string;
  status: VariationJobStatus;
  total: number;
  completed: number;
  /** Serialized job configuration (positions, payloads, limits). */
  config: string;
}
