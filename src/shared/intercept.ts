/** Interception views and decisions shared between engine and UI. */

import type { HttpHeader, Scheme } from './model.js';

export interface InterceptState {
  interceptRequests: boolean;
  interceptResponses: boolean;
}

export interface InterceptedRequestView {
  id: string;
  createdAt: number;
  scheme: Scheme;
  host: string;
  port: number;
  inScope: boolean;
  method: string;
  target: string;
  httpVersion: string;
  headers: HttpHeader[];
  /** Base64 of the captured request body (may be truncated). */
  bodyBase64: string;
  bodyTruncated: boolean;
}

export interface RequestEdit {
  method?: string;
  target?: string;
  headers?: HttpHeader[];
  bodyBase64?: string;
}

export type RequestDecision = { action: 'forward'; edit?: RequestEdit } | { action: 'drop' };

export interface InterceptedResponseView {
  id: string;
  createdAt: number;
  scheme: Scheme;
  host: string;
  port: number;
  /** Request context for display. */
  method: string;
  target: string;
  statusCode: number;
  statusMessage: string;
  httpVersion: string;
  headers: HttpHeader[];
  bodyBase64: string;
  bodyTruncated: boolean;
}

export interface ResponseEdit {
  statusCode?: number;
  statusMessage?: string;
  headers?: HttpHeader[];
  bodyBase64?: string;
}

export type ResponseDecision = { action: 'forward'; edit?: ResponseEdit } | { action: 'drop' };
