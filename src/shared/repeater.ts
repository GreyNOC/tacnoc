/** Shared types for the repeater workflow and TLS/connection info. */

import type { HttpExchange, Scheme } from './model.js';

export interface TlsInfo {
  protocol: string | null;
  cipherName?: string;
  authorized: boolean;
  authorizationError?: string;
  subjectCN?: string;
  issuerCN?: string;
  validFrom?: string;
  validTo?: string;
  fingerprint256?: string;
}

export interface RepeaterTarget {
  scheme: Scheme;
  host: string;
  port: number;
  /** Full raw request text (request line + headers + blank line + body). */
  raw: string;
}

export interface RepeaterOptions {
  followRedirects: boolean;
  maxRedirects: number;
  timeoutMs: number;
  /** Apply/collect cookies via a jar for this session. */
  useCookieJar: boolean;
}

export interface RedirectHop {
  url: string;
  status: number;
}

export interface RepeaterResult {
  exchange: HttpExchange;
  redirects: RedirectHop[];
  tls?: TlsInfo;
  /** Total wall-clock time including any redirects. */
  totalMs: number;
}
