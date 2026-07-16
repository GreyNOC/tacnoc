/**
 * Encoder / decoder / hash / transform utilities.
 *
 * These are the building blocks for the workbench "encoder-decoder" tool and are
 * also exposed to extensions as registrable data transformations. All functions
 * are pure and side-effect free.
 *
 * SECURITY NOTE on JWT: `inspectJwt` DECODES a token for inspection only. It
 * never verifies, re-signs, strips, or downgrades the signature/alg — there is
 * deliberately no "none-alg" or signature-bypass helper here.
 */

import * as crypto from 'node:crypto';
import * as zlib from 'node:zlib';

export type TransformCategory = 'encode' | 'decode' | 'hash' | 'compress' | 'inspect';

export interface TextTransform {
  id: string;
  label: string;
  category: TransformCategory;
  /** Transform text→text. Throws on invalid input (callers surface the error). */
  transform: (input: string) => string;
}

// --- URL ---
export function urlEncode(input: string): string {
  return encodeURIComponent(input);
}
export function urlDecode(input: string): string {
  return decodeURIComponent(input);
}
/** Percent-encode every byte (useful for building test payloads). */
export function urlEncodeAll(input: string): string {
  return [...Buffer.from(input, 'utf8')].map((b) => '%' + b.toString(16).padStart(2, '0')).join('');
}

// --- Base64 ---
export function base64Encode(input: string): string {
  return Buffer.from(input, 'utf8').toString('base64');
}
export function base64Decode(input: string): string {
  return Buffer.from(input, 'base64').toString('utf8');
}
export function base64UrlEncode(input: string): string {
  return Buffer.from(input, 'utf8').toString('base64url');
}
export function base64UrlDecode(input: string): string {
  return Buffer.from(input, 'base64url').toString('utf8');
}

// --- Hex ---
export function hexEncode(input: string): string {
  return Buffer.from(input, 'utf8').toString('hex');
}
export function hexDecode(input: string): string {
  const cleaned = input.replace(/\s+/g, '');
  if (cleaned.length % 2 !== 0 || /[^0-9a-fA-F]/.test(cleaned)) {
    throw new Error('invalid hex input');
  }
  return Buffer.from(cleaned, 'hex').toString('utf8');
}

// --- HTML entities ---
const HTML_ENCODE_MAP: Record<string, string> = {
  '&': '&amp;',
  '<': '&lt;',
  '>': '&gt;',
  '"': '&quot;',
  "'": '&#39;',
};
export function htmlEncode(input: string): string {
  return input.replace(/[&<>"']/g, (c) => HTML_ENCODE_MAP[c] as string);
}
export function htmlDecode(input: string): string {
  return input
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#0*39;|&#x0*27;|&apos;/gi, "'")
    .replace(/&#(\d+);/g, (_m, d: string) => String.fromCodePoint(Number(d)))
    .replace(/&#x([0-9a-fA-F]+);/g, (_m, h: string) => String.fromCodePoint(parseInt(h, 16)));
}

// --- Hashes ---
export function hash(algo: 'md5' | 'sha1' | 'sha256' | 'sha512', input: string): string {
  return crypto.createHash(algo).update(input, 'utf8').digest('hex');
}

// --- Gzip (binary → base64 wrapper) ---
export function gzipToBase64(input: string): string {
  return zlib.gzipSync(Buffer.from(input, 'utf8')).toString('base64');
}
export function gunzipFromBase64(inputB64: string): string {
  return zlib.gunzipSync(Buffer.from(inputB64, 'base64')).toString('utf8');
}

// --- Timestamps ---
export function epochToIso(input: string): string {
  const n = Number(input.trim());
  if (!Number.isFinite(n)) throw new Error('not a numeric epoch');
  // Heuristic: treat 10-digit values as seconds, 13-digit as milliseconds.
  const ms = input.trim().length <= 11 ? n * 1000 : n;
  return new Date(ms).toISOString();
}
export function isoToEpochMs(input: string): string {
  const ms = Date.parse(input.trim());
  if (Number.isNaN(ms)) throw new Error('unparseable date');
  return String(ms);
}

// --- JWT inspection (decode only; NO signature bypass) ---
export interface JwtInspection {
  header: unknown;
  payload: unknown;
  /** The raw signature segment, presented as-is. Never verified or removed. */
  signatureB64Url: string;
  /** True only if all three segments are present. */
  wellFormed: boolean;
  note: string;
}

export function inspectJwt(token: string): JwtInspection {
  const parts = token.trim().split('.');
  const decodeSegment = (seg: string): unknown => {
    try {
      return JSON.parse(Buffer.from(seg, 'base64url').toString('utf8'));
    } catch {
      return { _raw: seg, _error: 'not valid base64url JSON' };
    }
  };
  return {
    header: parts[0] ? decodeSegment(parts[0]) : null,
    payload: parts[1] ? decodeSegment(parts[1]) : null,
    signatureB64Url: parts[2] ?? '',
    wellFormed: parts.length === 3,
    note: 'Decoded for inspection only. Signature is NOT verified and is never altered.',
  };
}

/** Registry of text transforms surfaced in the UI and to extensions. */
export const BUILTIN_TRANSFORMS: TextTransform[] = [
  { id: 'url.encode', label: 'URL encode', category: 'encode', transform: urlEncode },
  {
    id: 'url.encode-all',
    label: 'URL encode (all bytes)',
    category: 'encode',
    transform: urlEncodeAll,
  },
  { id: 'url.decode', label: 'URL decode', category: 'decode', transform: urlDecode },
  { id: 'base64.encode', label: 'Base64 encode', category: 'encode', transform: base64Encode },
  { id: 'base64.decode', label: 'Base64 decode', category: 'decode', transform: base64Decode },
  {
    id: 'base64url.encode',
    label: 'Base64URL encode',
    category: 'encode',
    transform: base64UrlEncode,
  },
  {
    id: 'base64url.decode',
    label: 'Base64URL decode',
    category: 'decode',
    transform: base64UrlDecode,
  },
  { id: 'hex.encode', label: 'Hex encode', category: 'encode', transform: hexEncode },
  { id: 'hex.decode', label: 'Hex decode', category: 'decode', transform: hexDecode },
  { id: 'html.encode', label: 'HTML entity encode', category: 'encode', transform: htmlEncode },
  { id: 'html.decode', label: 'HTML entity decode', category: 'decode', transform: htmlDecode },
  { id: 'gzip.compress', label: 'Gzip → Base64', category: 'compress', transform: gzipToBase64 },
  {
    id: 'gzip.decompress',
    label: 'Base64 → Gunzip',
    category: 'compress',
    transform: gunzipFromBase64,
  },
  { id: 'hash.md5', label: 'MD5', category: 'hash', transform: (s) => hash('md5', s) },
  { id: 'hash.sha1', label: 'SHA-1', category: 'hash', transform: (s) => hash('sha1', s) },
  { id: 'hash.sha256', label: 'SHA-256', category: 'hash', transform: (s) => hash('sha256', s) },
  { id: 'hash.sha512', label: 'SHA-512', category: 'hash', transform: (s) => hash('sha512', s) },
  {
    id: 'time.epoch-to-iso',
    label: 'Epoch → ISO 8601',
    category: 'inspect',
    transform: epochToIso,
  },
  {
    id: 'time.iso-to-epoch',
    label: 'ISO 8601 → Epoch (ms)',
    category: 'inspect',
    transform: isoToEpochMs,
  },
];

export function applyTransform(id: string, input: string): string {
  const t = BUILTIN_TRANSFORMS.find((x) => x.id === id);
  if (!t) throw new Error(`unknown transform: ${id}`);
  return t.transform(input);
}
