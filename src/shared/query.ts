/** History search/filter criteria shared between UI and engine. */

import type { MessageSource } from './model.js';

export interface HistoryFilter {
  /** Case-insensitive substring across url/host/method. */
  text?: string;
  method?: string;
  host?: string;
  /** Exact status code. */
  status?: number;
  /** Status class: 1..5 → 1xx..5xx. */
  statusClass?: number;
  /** Case-insensitive substring on the response MIME type. */
  mime?: string;
  source?: MessageSource;
  inScopeOnly?: boolean;
  automatedOnly?: boolean;
  /** Epoch-ms lower/upper bounds on createdAt. */
  since?: number;
  until?: number;
  limit?: number;
  offset?: number;
  sort?: 'asc' | 'desc';
}

export interface HistoryPage<T> {
  rows: T[];
  total: number;
  limit: number;
  offset: number;
}

/** Lightweight row for the history table (no bodies over IPC). */
export interface ExchangeSummary {
  id: string;
  createdAt: number;
  source: MessageSource;
  scheme: string;
  host: string;
  port: number;
  method: string;
  url: string;
  path: string;
  inScope: boolean;
  automated: boolean;
  statusCode?: number;
  mime?: string;
  responseLength: number;
  durationMs?: number;
  hasResponse: boolean;
  error?: string;
  tags: string[];
}
