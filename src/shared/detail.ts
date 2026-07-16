/** DTOs for sending a full exchange (with bodies as base64) to the renderer. */

import type { HttpHeader, MessageSource, Scheme } from './model.js';

export interface SensitivitySummary {
  hasCookies: boolean;
  hasAuthorization: boolean;
  hasTokens: boolean;
  fields: string[];
}

export interface MessageDetail {
  headers: HttpHeader[];
  bodyBase64: string;
  bodySize: number;
  bodyTruncated: boolean;
  /** True if the body was too large to fully include for viewing. */
  truncatedForView: boolean;
  contentEncoding?: string;
  sensitive: SensitivitySummary;
}

export interface RequestDetail extends MessageDetail {
  method: string;
  target: string;
  url: string;
  httpVersion: string;
}

export interface ResponseDetail extends MessageDetail {
  statusCode: number;
  statusMessage: string;
  httpVersion: string;
}

export interface ExchangeDetail {
  id: string;
  createdAt: number;
  source: MessageSource;
  scheme: Scheme;
  host: string;
  port: number;
  inScope: boolean;
  automated: boolean;
  jobId?: string;
  error?: string;
  tags: string[];
  notes?: string;
  timing?: { startedAt: number; ttfbMs?: number; durationMs?: number };
  request: RequestDetail;
  response?: ResponseDetail;
}
