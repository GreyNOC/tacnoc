/**
 * Secret redaction.
 *
 * Two responsibilities:
 *  1. REDACT — remove likely secrets from any text/headers before they are
 *     written to logs, stored in findings evidence, or placed in exports.
 *  2. DETECT — report whether a message likely contains credentials so the UI
 *     can WARN before revealing or exporting cookies/authorization/tokens.
 *
 * Patterns are conservative: it is better to occasionally miss an exotic secret
 * than to mangle large amounts of normal traffic. The proxy/history still store
 * the real bytes (in the encrypted-at-rest project, see THREAT_MODEL.md);
 * redaction protects the *derived* artifacts (logs, evidence, diagnostics).
 */

import * as zlib from 'node:zlib';
import type { HttpHeader } from '../../shared/model.js';
import type { RedactionConfig } from '../../shared/config.js';

export const REDACTION_MASK = '[REDACTED]';

/** Header names whose entire value is a credential. */
const CREDENTIAL_HEADERS = new Set([
  'authorization',
  'proxy-authorization',
  'cookie',
  'set-cookie',
  'x-api-key',
  'x-auth-token',
  'x-amz-security-token',
  'x-csrf-token',
  'x-xsrf-token',
]);

/** Credential headers governed by their own dedicated toggle (handled above). */
const OWN_TOGGLE_HEADERS = new Set([
  'cookie',
  'set-cookie',
  'authorization',
  'proxy-authorization',
]);

/** Query/param names commonly carrying secrets. */
const SENSITIVE_PARAM_NAMES =
  /^(?:access_?token|id_?token|refresh_?token|api[_-]?key|apikey|secret|client_?secret|password|passwd|pwd|auth|session|sig|signature|code)$/i;

interface SecretPattern {
  kind: string;
  re: RegExp;
}

/**
 * Conservative secret patterns. Each `re` is global so `String.replace` masks
 * every occurrence. Ordering matters: more specific patterns run first.
 */
const SECRET_PATTERNS: SecretPattern[] = [
  {
    kind: 'private-key',
    re: /-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----[\s\S]+?-----END (?:[A-Z ]+ )?PRIVATE KEY-----/g,
  },
  { kind: 'jwt', re: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}\b/g },
  { kind: 'aws-access-key', re: /\bAKIA[0-9A-Z]{16}\b/g },
  { kind: 'google-api-key', re: /\bAIza[0-9A-Za-z_-]{35}\b/g },
  { kind: 'github-token', re: /\bgh[posru]_[A-Za-z0-9]{20,}\b/g },
  { kind: 'slack-token', re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g },
  { kind: 'stripe-key', re: /\b(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{16,}\b/g },
  // LLM provider keys. TACNOC prompts for one of these itself, which makes it
  // the credential most likely to end up pasted into a note, a captured
  // request, or an engagement document — and hunt memory is a durable,
  // cross-engagement store that redacts on the way in.
  { kind: 'anthropic-key', re: /\bsk-ant-[A-Za-z0-9_-]{16,}/g },
  { kind: 'openai-key', re: /\bsk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{16,}/g },
  { kind: 'bearer', re: /\bBearer\s+[A-Za-z0-9\-._~+/]{12,}=*/gi },
  { kind: 'basic', re: /\bBasic\s+[A-Za-z0-9+/]{12,}={0,2}/gi },
  // Generic key=value where the key name is sensitive. Masks the value only.
  {
    kind: 'sensitive-assignment',
    re: /\b([A-Za-z0-9_-]*(?:password|passwd|pwd|secret|api[_-]?key|apikey|token|auth)[A-Za-z0-9_-]*)(["']?\s*[:=]\s*["']?)([^\s"'&,;}]{6,})/gi,
  },
];

export class Redactor {
  constructor(private readonly config: RedactionConfig) {}

  /** Redact free text: applies secret patterns when enabled. */
  redactText(input: string): string {
    if (!this.config.maskSecretPatterns) return input;
    let out = input;
    for (const p of SECRET_PATTERNS) {
      if (p.kind === 'sensitive-assignment') {
        out = out.replace(p.re, (_m, key: string, sep: string) => `${key}${sep}${REDACTION_MASK}`);
      } else {
        out = out.replace(p.re, REDACTION_MASK);
      }
    }
    return out;
  }

  /** Redact a single header value according to config. */
  redactHeaderValue(name: string, value: string): string {
    const lower = name.toLowerCase();
    if (this.config.maskCookies && (lower === 'cookie' || lower === 'set-cookie')) {
      return redactCookieHeader(lower, value);
    }
    if (
      this.config.maskAuthorization &&
      (lower === 'authorization' || lower === 'proxy-authorization')
    ) {
      return REDACTION_MASK;
    }
    // Other whole-value credential headers (x-api-key, x-auth-token, x-csrf-token,
    // …) are gated on maskAuthorization — NOT maskSecretPatterns. They are entire
    // credentials, not free-text patterns, so disabling pattern scanning (to avoid
    // mangling normal traffic) must not leak them. cookie/authorization are
    // excluded here because they are governed by their own toggles above.
    if (
      this.config.maskAuthorization &&
      CREDENTIAL_HEADERS.has(lower) &&
      !OWN_TOGGLE_HEADERS.has(lower)
    ) {
      return REDACTION_MASK;
    }
    return this.redactText(value);
  }

  redactHeaders(headers: readonly HttpHeader[]): HttpHeader[] {
    return headers.map((h) => ({ name: h.name, value: this.redactHeaderValue(h.name, h.value) }));
  }

  /** Redact sensitive query-string parameter values in a URL. */
  redactUrl(url: string): string {
    const qIndex = url.indexOf('?');
    if (qIndex === -1) return this.redactText(url);
    // Redact the base too: a secret embedded in the PATH (JWT/API key in a REST
    // segment) must be masked even when a query string is also present — else the
    // same secret is masked without a query but leaks with one.
    const base = this.redactText(url.slice(0, qIndex));
    const query = url.slice(qIndex + 1);
    const parts = query.split('&').map((pair) => {
      const eq = pair.indexOf('=');
      if (eq === -1) return pair;
      const key = pair.slice(0, eq);
      const rawKey = safeDecode(key);
      if (SENSITIVE_PARAM_NAMES.test(rawKey)) return `${key}=${REDACTION_MASK}`;
      return `${key}=${this.redactText(pair.slice(eq + 1))}`;
    });
    return `${base}?${parts.join('&')}`;
  }

  /** Redact a byte body for evidence/log purposes (decodes as UTF-8 leniently). */
  redactBodyText(bytes: Uint8Array, maxChars = 4096): string {
    const text = Buffer.from(bytes.subarray(0, maxChars * 4))
      .toString('utf8')
      .slice(0, maxChars);
    return this.redactText(text);
  }
}

/** Mask cookie values while preserving names and attributes. */
function redactCookieHeader(headerName: string, value: string): string {
  if (headerName === 'set-cookie') {
    // name=value; Attr=...; ... — mask only the first name=value pair's value.
    const semi = value.indexOf(';');
    const nameValue = semi === -1 ? value : value.slice(0, semi);
    const rest = semi === -1 ? '' : value.slice(semi);
    const eq = nameValue.indexOf('=');
    if (eq === -1) return value;
    return `${nameValue.slice(0, eq)}=${REDACTION_MASK}${rest}`;
  }
  // Cookie: a=1; b=2 — mask each value, keep names.
  return value
    .split(';')
    .map((pair) => {
      const eq = pair.indexOf('=');
      if (eq === -1) return pair;
      return `${pair.slice(0, eq)}=${REDACTION_MASK}`;
    })
    .join(';');
}

export interface SensitivityReport {
  hasCookies: boolean;
  hasAuthorization: boolean;
  hasTokens: boolean;
  /** Header/param names that triggered the report (for the warning dialog). */
  fields: string[];
}

/**
 * Structurally redact an arbitrary AI-mesh tool result before it egresses to the
 * model provider. Unlike a flat text pass, this decodes `bodyBase64` fields and
 * masks patterns in the DECODED bytes (so secrets in POST bodies / JSON responses
 * are actually caught, not left as reversible base64), and masks structured
 * `headers` arrays via the header rules (so cookies / Authorization / credential
 * headers are stripped even though JSON structure breaks key:value adjacency).
 * Everything else is walked recursively and pattern-masked. Best-effort on body
 * contents (pattern-based), thorough on headers.
 */
export function redactAiValue(value: unknown, redactor: Redactor): unknown {
  if (typeof value === 'string') return redactor.redactText(value);
  if (Array.isArray(value)) return value.map((v) => redactAiValue(v, redactor));
  if (value && typeof value === 'object') {
    const obj = value as Record<string, unknown>;
    const encoding = typeof obj.contentEncoding === 'string' ? obj.contentEncoding : undefined;
    const out: Record<string, unknown> = {};
    for (const [key, v] of Object.entries(obj)) {
      if (key === 'headers' && isHeaderArray(v)) {
        out[key] = redactor.redactHeaders(v);
      } else if (key === 'bodyBase64' && typeof v === 'string') {
        // Decompress (if encoded) so patterns match the real bytes, redact, re-encode.
        const body = redactBase64Body(v, redactor, encoding);
        out.bodyBase64 = body.bodyBase64;
        out.contentEncoding = body.contentEncoding; // undefined once decompressed
      } else if (key === 'contentEncoding') {
        // Emitted alongside bodyBase64 above; keep it only when there is no body.
        if (!('bodyBase64' in obj)) out.contentEncoding = v;
      } else if ((key === 'url' || key === 'target') && typeof v === 'string') {
        // redactUrl masks sensitive query params (session=, sig=, code=, token=…).
        out[key] = redactor.redactUrl(v);
      } else {
        out[key] = redactAiValue(v, redactor);
      }
    }
    return out;
  }
  return value;
}

function isHeaderArray(v: unknown): v is HttpHeader[] {
  return (
    Array.isArray(v) &&
    v.every(
      (h) =>
        !!h &&
        typeof h === 'object' &&
        typeof (h as HttpHeader).name === 'string' &&
        typeof (h as HttpHeader).value === 'string',
    )
  );
}

const MAX_DECOMPRESSED = 8 * 1024 * 1024; // guard against decompression bombs

/**
 * Best-effort decompress a captured body by Content-Encoding; null if it cannot.
 *
 * Exported because the evidence bundle needs exactly this and used to have
 * nothing: it UTF-8-decoded the stored bytes, which for a gzip or br response —
 * nearly every HTTPS response there is — destroyed the body it was shipping as
 * evidence. A second decompressor would be a second place to forget
 * `maxOutputLength`, so there is one, and it is this.
 */
export function tryDecompress(raw: Buffer, encoding?: string): Buffer | null {
  if (!encoding) return null;
  const e = encoding.trim().toLowerCase();
  const opts = { maxOutputLength: MAX_DECOMPRESSED };
  try {
    if (e === 'gzip' || e === 'x-gzip') return zlib.gunzipSync(raw, opts);
    if (e === 'br') return zlib.brotliDecompressSync(raw, { maxOutputLength: MAX_DECOMPRESSED });
    if (e === 'deflate') {
      try {
        return zlib.inflateSync(raw, opts);
      } catch {
        return zlib.inflateRawSync(raw, opts);
      }
    }
  } catch {
    return null;
  }
  return null;
}

/**
 * Redact a base64 body: decompress first when Content-Encoded (so patterns match
 * the plaintext), pattern-redact byte-safely (latin1), and re-encode. When a body
 * was decompressed the returned `contentEncoding` is undefined (it now holds
 * plaintext); otherwise the original encoding is preserved.
 */
function redactBase64Body(
  b64: string,
  redactor: Redactor,
  encoding?: string,
): { bodyBase64: string; contentEncoding: string | undefined } {
  try {
    const raw = Buffer.from(b64, 'base64');
    const decompressed = tryDecompress(raw, encoding);
    const bytes = decompressed ?? raw;
    const redacted = redactor.redactText(bytes.toString('latin1'));
    return {
      bodyBase64: Buffer.from(redacted, 'latin1').toString('base64'),
      contentEncoding: decompressed ? undefined : encoding,
    };
  } catch {
    return { bodyBase64: b64, contentEncoding: encoding };
  }
}

/**
 * Inspect headers (and optionally a decoded body) to decide whether the UI
 * should warn before revealing/exporting. Does NOT mutate anything.
 */
export function detectSensitive(
  headers: readonly HttpHeader[],
  bodyText?: string,
): SensitivityReport {
  const report: SensitivityReport = {
    hasCookies: false,
    hasAuthorization: false,
    hasTokens: false,
    fields: [],
  };
  for (const h of headers) {
    const lower = h.name.toLowerCase();
    if (lower === 'cookie' || lower === 'set-cookie') {
      report.hasCookies = true;
      report.fields.push(h.name);
    } else if (lower === 'authorization' || lower === 'proxy-authorization') {
      report.hasAuthorization = true;
      report.fields.push(h.name);
    } else if (CREDENTIAL_HEADERS.has(lower)) {
      report.hasTokens = true;
      report.fields.push(h.name);
    }
  }
  const haystack = bodyText ?? '';
  for (const p of SECRET_PATTERNS) {
    p.re.lastIndex = 0;
    if (haystack && p.re.test(haystack)) {
      report.hasTokens = true;
      report.fields.push(p.kind);
    }
  }
  return report;
}

function safeDecode(s: string): string {
  try {
    return decodeURIComponent(s);
  } catch {
    return s;
  }
}
