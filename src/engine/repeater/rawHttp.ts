/**
 * Parse and serialize raw HTTP/1.1 request text for the manual request editor.
 * Preserves header order, casing, and duplicates so editing round-trips
 * faithfully ("raw request editing with structured synchronization").
 */

import type { HttpHeader } from '../../shared/model.js';

export interface ParsedRawRequest {
  method: string;
  target: string;
  httpVersion: string;
  headers: HttpHeader[];
  body: string;
}

/** Parse raw request text. Tolerant of LF-only line endings. */
export function parseRawRequest(raw: string): ParsedRawRequest {
  const normalized = raw.replace(/\r\n/g, '\n');
  const sepIndex = normalized.indexOf('\n\n');
  const headSection = sepIndex === -1 ? normalized : normalized.slice(0, sepIndex);
  const body = sepIndex === -1 ? '' : normalized.slice(sepIndex + 2);

  const lines = headSection.split('\n');
  const requestLine = lines.shift() ?? '';
  const m = /^(\S+)\s+(\S+)\s+(HTTP\/\d(?:\.\d)?)\s*$/.exec(requestLine);
  if (!m) throw new Error(`malformed request line: ${JSON.stringify(requestLine)}`);

  const headers: HttpHeader[] = [];
  for (const line of lines) {
    if (line.trim() === '') continue;
    const colon = line.indexOf(':');
    if (colon <= 0) throw new Error(`malformed header line: ${JSON.stringify(line)}`);
    headers.push({ name: line.slice(0, colon).trim(), value: line.slice(colon + 1).trim() });
  }

  return {
    method: m[1] as string,
    target: m[2] as string,
    httpVersion: m[3] as string,
    headers,
    body,
  };
}

export function serializeRawRequest(parts: ParsedRawRequest): string {
  const lines = [`${parts.method} ${parts.target} ${parts.httpVersion}`];
  for (const h of parts.headers) lines.push(`${h.name}: ${h.value}`);
  return lines.join('\r\n') + '\r\n\r\n' + parts.body;
}

/** Build editable raw request text from structured parts (structured→raw sync). */
export function toRawRequest(
  method: string,
  target: string,
  headers: HttpHeader[],
  body = '',
  httpVersion = 'HTTP/1.1',
): string {
  return serializeRawRequest({ method, target, httpVersion, headers, body });
}
