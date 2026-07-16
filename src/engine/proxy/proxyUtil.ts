/**
 * Helpers for forwarding captured messages upstream/downstream while preserving
 * fidelity (header order/casing/duplicates) and stripping hop-by-hop headers
 * that must not be forwarded by an intermediary (RFC 9110 §7.6.1).
 */

import type { OutgoingHttpHeaders } from 'node:http';
import type { HttpHeader } from '../../shared/model.js';

/** Headers that are connection-specific and must not be forwarded. */
export const HOP_BY_HOP = new Set([
  'connection',
  'proxy-connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
]);

/**
 * Convert a captured header list into a Node OutgoingHttpHeaders object.
 *
 * - Drops hop-by-hop headers and Content-Length (the runtime recomputes framing
 *   from the body we actually write, which is correct even if the body was
 *   edited).
 * - Preserves duplicates by collecting same-key values into arrays.
 * - Preserves the original casing of the FIRST occurrence of each key.
 */
export function buildOutboundHeaders(headers: readonly HttpHeader[]): OutgoingHttpHeaders {
  const out: OutgoingHttpHeaders = {};
  const casing = new Map<string, string>(); // lower -> original casing to emit
  for (const h of headers) {
    // HTTP/2 pseudo-headers (":method", ":path", …) must never be forwarded to
    // an HTTP/1.1 origin.
    if (h.name.startsWith(':')) continue;
    const lower = h.name.toLowerCase();
    if (HOP_BY_HOP.has(lower) || lower === 'content-length') continue;
    const key = casing.get(lower) ?? h.name;
    casing.set(lower, key);
    const existing = out[key];
    if (existing === undefined) {
      out[key] = h.value;
    } else if (Array.isArray(existing)) {
      existing.push(h.value);
    } else {
      out[key] = [String(existing), h.value];
    }
  }
  return out;
}

/** Parse an "host:port" authority, applying a default port. */
export function parseAuthority(
  authority: string,
  defaultPort: number,
): { host: string; port: number } {
  // IPv6 literal in brackets: [::1]:8443
  if (authority.startsWith('[')) {
    const close = authority.indexOf(']');
    const host = authority.slice(1, close);
    const rest = authority.slice(close + 1);
    const port = rest.startsWith(':') ? Number(rest.slice(1)) : defaultPort;
    return { host, port: Number.isFinite(port) ? port : defaultPort };
  }
  const colon = authority.lastIndexOf(':');
  if (colon === -1) return { host: authority, port: defaultPort };
  const host = authority.slice(0, colon);
  const port = Number(authority.slice(colon + 1));
  return { host, port: Number.isFinite(port) ? port : defaultPort };
}

/** Build an absolute URL from parts, keeping default ports implicit. */
export function buildUrl(scheme: string, host: string, port: number, target: string): string {
  const defaultPort = scheme === 'https' ? 443 : 80;
  const authority = port === defaultPort ? host : `${host}:${port}`;
  // target may already be absolute-form (plain HTTP proxy); normalize.
  if (/^https?:\/\//i.test(target)) return target;
  const path = target.startsWith('/') ? target : `/${target}`;
  return `${scheme}://${authority}${path}`;
}

/** Extract the origin-form path from a possibly absolute-form request target. */
export function originForm(target: string): string {
  const m = /^https?:\/\/[^/]+(\/.*)?$/i.exec(target);
  if (m) return m[1] && m[1].length > 0 ? m[1] : '/';
  return target || '/';
}
