/**
 * Built-in passive checks. Each is conservative and reports what it can observe
 * without generating traffic. Reflected-input is reported as an OBSERVATION only
 * (tentative confidence), never as a confirmed vulnerability.
 */

import { getHeader, getHeaders, mimeType, type HttpExchange } from '../../shared/model.js';
import type { ScannerCheck, RawFinding } from './types.js';

function endpointKey(ex: HttpExchange): string {
  try {
    const u = new URL(ex.request.url);
    return `${ex.host}:${ex.port}${u.pathname}`;
  } catch {
    return `${ex.host}:${ex.port}`;
  }
}

function isHtml(ex: HttpExchange): boolean {
  const mt = ex.response ? mimeType(ex.response.headers) : undefined;
  return mt === 'text/html' || mt === 'application/xhtml+xml';
}

const securityHeaders: ScannerCheck = {
  module: 'security-headers',
  version: '1.0.0',
  appliesTo: (ex) => !!ex.response && ex.response.statusCode < 400,
  run(ctx) {
    const ex = ctx.exchange;
    const res = ex.response!;
    const findings: RawFinding[] = [];
    const required: {
      header: string;
      title: string;
      severity: RawFinding['severity'];
      remediation: string;
    }[] = [
      {
        header: 'content-security-policy',
        title: 'Missing Content-Security-Policy header',
        severity: 'medium',
        remediation:
          'Define a restrictive Content-Security-Policy to mitigate XSS and data injection.',
      },
      {
        header: 'x-content-type-options',
        title: 'Missing X-Content-Type-Options header',
        severity: 'low',
        remediation: 'Send "X-Content-Type-Options: nosniff" to prevent MIME sniffing.',
      },
      {
        header: 'x-frame-options',
        title: 'Missing X-Frame-Options (or CSP frame-ancestors)',
        severity: 'low',
        remediation: 'Set X-Frame-Options: DENY/SAMEORIGIN or a CSP frame-ancestors directive.',
      },
      {
        header: 'referrer-policy',
        title: 'Missing Referrer-Policy header',
        severity: 'info',
        remediation:
          'Set a Referrer-Policy such as no-referrer or strict-origin-when-cross-origin.',
      },
    ];
    // HSTS only meaningful over https
    if (ex.scheme === 'https' && !getHeader(res.headers, 'strict-transport-security')) {
      findings.push({
        dedupeKey: `${endpointKey(ex)}|hsts`,
        title: 'Missing Strict-Transport-Security header',
        severity: 'low',
        confidence: 'firm',
        description:
          'The HTTPS response does not set HSTS, so browsers may allow downgrade to HTTP.',
        remediation:
          'Send Strict-Transport-Security with an appropriate max-age (and includeSubDomains where safe).',
        evidence: [
          {
            location: 'response-headers',
            excerpt: 'Strict-Transport-Security: <absent>',
            field: 'Strict-Transport-Security',
          },
        ],
      });
    }
    if (isHtml(ex)) {
      for (const r of required) {
        if (!getHeader(res.headers, r.header)) {
          findings.push({
            dedupeKey: `${endpointKey(ex)}|${r.header}`,
            title: r.title,
            severity: r.severity,
            confidence: 'firm',
            description: `The HTML response is missing the ${r.header} response header.`,
            remediation: r.remediation,
            evidence: [
              { location: 'response-headers', excerpt: `${r.header}: <absent>`, field: r.header },
            ],
          });
        }
      }
    }
    return findings;
  },
};

const insecureCookies: ScannerCheck = {
  module: 'insecure-cookies',
  version: '1.0.0',
  appliesTo: (ex) => !!ex.response && getHeaders(ex.response.headers, 'set-cookie').length > 0,
  run(ctx) {
    const ex = ctx.exchange;
    const findings: RawFinding[] = [];
    for (const raw of getHeaders(ex.response!.headers, 'set-cookie')) {
      const name = (raw.split('=', 1)[0] ?? 'cookie').trim();
      const attrs = raw.toLowerCase();
      const problems: string[] = [];
      if (ex.scheme === 'https' && !/;\s*secure/.test(attrs)) problems.push('Secure');
      if (!/;\s*httponly/.test(attrs)) problems.push('HttpOnly');
      if (!/;\s*samesite=/.test(attrs)) problems.push('SameSite');
      if (problems.length) {
        findings.push({
          dedupeKey: `${endpointKey(ex)}|cookie|${name}|${problems.join(',')}`,
          title: `Cookie "${name}" missing ${problems.join(', ')} attribute(s)`,
          severity: problems.includes('Secure') ? 'medium' : 'low',
          confidence: 'firm',
          description: `The Set-Cookie for "${name}" lacks: ${problems.join(', ')}.`,
          remediation:
            'Add Secure (over HTTPS), HttpOnly, and an explicit SameSite attribute to session cookies.',
          evidence: [
            {
              location: 'response-headers',
              excerpt: ctx.redactor.redactHeaderValue('set-cookie', raw),
              field: 'Set-Cookie',
            },
          ],
        });
      }
    }
    return findings;
  },
};

const corsCheck: ScannerCheck = {
  module: 'cors',
  version: '1.0.0',
  appliesTo: (ex) =>
    !!ex.response && !!getHeader(ex.response.headers, 'access-control-allow-origin'),
  run(ctx) {
    const ex = ctx.exchange;
    const acao = getHeader(ex.response!.headers, 'access-control-allow-origin') ?? '';
    const acac =
      (getHeader(ex.response!.headers, 'access-control-allow-credentials') ?? '').toLowerCase() ===
      'true';
    const reqOrigin = getHeader(ex.request.headers, 'origin');
    const findings: RawFinding[] = [];
    if (acao === '*' && acac) {
      findings.push({
        dedupeKey: `${endpointKey(ex)}|cors|wildcard-credentials`,
        title: 'CORS allows any origin together with credentials',
        severity: 'high',
        confidence: 'firm',
        description:
          'Access-Control-Allow-Origin: * with Allow-Credentials: true is an invalid, unsafe combination that can expose credentialed data.',
        remediation:
          'Reflect only explicitly allowed origins and avoid combining wildcard origin with credentials.',
        evidence: [
          {
            location: 'response-headers',
            excerpt: `Access-Control-Allow-Origin: *; Allow-Credentials: true`,
            field: 'Access-Control-Allow-Origin',
          },
        ],
      });
    } else if (acac && reqOrigin && acao && acao === reqOrigin) {
      // The exploitable, common misconfiguration: the server echoes the
      // caller-supplied Origin AND allows credentials, so ANY origin can read
      // credentialed responses. Browsers forbid '*'+credentials, which is why
      // reflection — not '*' — is the real account-takeover-grade CORS bug.
      findings.push({
        dedupeKey: `${endpointKey(ex)}|cors|reflected-credentials`,
        title: 'CORS reflects the request Origin with credentials',
        severity: 'high',
        confidence: 'firm',
        description:
          'Access-Control-Allow-Origin reflects the request Origin while Access-Control-Allow-Credentials is true, so any site can make credentialed cross-origin reads of this resource.',
        remediation:
          'Validate the Origin against a fixed allowlist; never reflect an arbitrary Origin together with credentials.',
        evidence: [
          {
            location: 'response-headers',
            excerpt: `Access-Control-Allow-Origin: ${acao} (reflected request Origin); Allow-Credentials: true`,
            field: 'Access-Control-Allow-Origin',
          },
        ],
      });
    } else if (acac && acao.toLowerCase() === 'null') {
      // "null" origin + credentials is reachable from sandboxed iframes / data
      // URLs and is likewise exploitable.
      findings.push({
        dedupeKey: `${endpointKey(ex)}|cors|null-credentials`,
        title: 'CORS allows the "null" origin with credentials',
        severity: 'high',
        confidence: 'firm',
        description:
          'Access-Control-Allow-Origin: null with Allow-Credentials: true lets sandboxed iframes and other "null"-origin contexts read credentialed responses.',
        remediation: 'Do not allow the "null" origin together with credentials.',
        evidence: [
          {
            location: 'response-headers',
            excerpt: 'Access-Control-Allow-Origin: null; Allow-Credentials: true',
            field: 'Access-Control-Allow-Origin',
          },
        ],
      });
    } else if (acao === '*') {
      findings.push({
        dedupeKey: `${endpointKey(ex)}|cors|wildcard`,
        title: 'Permissive CORS policy (Access-Control-Allow-Origin: *)',
        severity: 'info',
        confidence: 'firm',
        description:
          'The endpoint permits cross-origin reads from any origin. Confirm this is intended for non-sensitive data.',
        remediation:
          'Restrict Access-Control-Allow-Origin to specific trusted origins when the resource is sensitive.',
        evidence: [
          {
            location: 'response-headers',
            excerpt: 'Access-Control-Allow-Origin: *',
            field: 'Access-Control-Allow-Origin',
          },
        ],
      });
    }
    return findings;
  },
};

const mixedContent: ScannerCheck = {
  module: 'mixed-content',
  version: '1.0.0',
  appliesTo: (ex) => ex.scheme === 'https' && isHtml(ex),
  run(ctx) {
    const matches = [
      ...ctx.responseBodyText.matchAll(/(?:src|href)\s*=\s*["']?(http:\/\/[^"'\s>]+)/gi),
    ].slice(0, 5);
    if (matches.length === 0) return [];
    return [
      {
        dedupeKey: `${endpointKey(ctx.exchange)}|mixed-content`,
        title: 'Mixed content: HTTPS page references HTTP resources',
        severity: 'medium',
        confidence: 'firm',
        description:
          'An HTTPS page includes resources over plaintext HTTP, which browsers may block or which can be tampered with.',
        remediation: 'Serve all subresources over HTTPS.',
        evidence: matches.map((m) => ({
          location: 'response-body' as const,
          excerpt: ctx.redactor.redactText(m[1] ?? ''),
        })),
      },
    ];
  },
};

const sensitiveInUrl: ScannerCheck = {
  module: 'sensitive-in-url',
  version: '1.0.0',
  run(ctx) {
    const ex = ctx.exchange;
    let url: URL;
    try {
      url = new URL(ex.request.url);
    } catch {
      return [];
    }
    const sensitive =
      /^(access_?token|id_?token|refresh_?token|api[_-]?key|apikey|secret|password|passwd|pwd|auth|session|sig|signature)$/i;
    const hits = [...url.searchParams.keys()].filter((k) => sensitive.test(k));
    if (hits.length === 0) return [];
    return [
      {
        dedupeKey: `${endpointKey(ex)}|sensitive-url|${hits.sort().join(',')}`,
        title: 'Sensitive data in URL query string',
        severity: 'medium',
        confidence: 'firm',
        description: `The request URL carries sensitive-looking parameters (${hits.join(', ')}). URLs are logged by proxies, servers, and browser history.`,
        remediation: 'Move secrets/tokens out of URLs into headers or request bodies.',
        evidence: [
          {
            location: 'url',
            excerpt: ctx.redactor.redactUrl(ex.request.url),
            field: hits.join(','),
          },
        ],
      },
    ];
  },
};

const cacheControl: ScannerCheck = {
  module: 'cache-control',
  version: '1.0.0',
  appliesTo: (ex) => !!ex.response,
  run(ctx) {
    const ex = ctx.exchange;
    const looksSensitive =
      getHeader(ex.request.headers, 'authorization') !== undefined ||
      getHeaders(ex.response!.headers, 'set-cookie').length > 0;
    if (!looksSensitive) return [];
    const cc = (getHeader(ex.response!.headers, 'cache-control') ?? '').toLowerCase();
    if (cc.includes('no-store') || cc.includes('private')) return [];
    return [
      {
        dedupeKey: `${endpointKey(ex)}|cache-control`,
        title: 'Sensitive response may be cacheable',
        severity: 'low',
        confidence: 'tentative',
        description:
          'A response tied to authentication/cookies does not set Cache-Control: no-store or private and may be cached by intermediaries.',
        remediation: 'Set Cache-Control: no-store (or private) on authenticated responses.',
        evidence: [
          {
            location: 'response-headers',
            excerpt: `Cache-Control: ${cc || '<absent>'}`,
            field: 'Cache-Control',
          },
        ],
      },
    ];
  },
};

const verboseErrors: ScannerCheck = {
  module: 'verbose-errors',
  version: '1.0.0',
  appliesTo: (ex) => !!ex.response,
  run(ctx) {
    const ex = ctx.exchange;
    const body = ctx.responseBodyText;
    const markers =
      /(stack trace|stacktrace|Exception in|Traceback \(most recent call last\)|NullReferenceException|at [\w.$]+\([\w.]+:\d+:\d+\)|SQLSTATE\[|ORA-\d{5}|Warning: \w+\(\) )/i;
    const m = markers.exec(body);
    if (!m && ex.response!.statusCode < 500) return [];
    if (!m) return [];
    return [
      {
        dedupeKey: `${endpointKey(ex)}|verbose-error`,
        title: 'Verbose error / stack trace disclosed in response',
        severity: 'medium',
        confidence: 'firm',
        description:
          'The response body contains internal error/stack-trace details that can aid an attacker.',
        remediation: 'Return generic error messages to clients and log details server-side only.',
        evidence: [
          {
            location: 'response-body',
            excerpt: ctx.redactor.redactText((m[0] ?? '').slice(0, 200)),
          },
        ],
      },
    ];
  },
};

const bannerDisclosure: ScannerCheck = {
  module: 'banner-disclosure',
  version: '1.0.0',
  appliesTo: (ex) => !!ex.response,
  run(ctx) {
    const ex = ctx.exchange;
    const findings: RawFinding[] = [];
    for (const header of ['server', 'x-powered-by', 'x-aspnet-version', 'x-generator']) {
      const val = getHeader(ex.response!.headers, header);
      if (val && /\d/.test(val)) {
        findings.push({
          dedupeKey: `${endpointKey(ex)}|banner|${header}`,
          title: `Version/banner disclosure via ${header}`,
          severity: 'info',
          confidence: 'firm',
          description: `The ${header} header reveals software/version information (${val}).`,
          remediation: 'Suppress or genericize version banners in responses.',
          evidence: [{ location: 'response-headers', excerpt: `${header}: ${val}`, field: header }],
        });
      }
    }
    return findings;
  },
};

const secretsInResponse: ScannerCheck = {
  module: 'secrets-in-response',
  version: '1.0.0',
  appliesTo: (ex) => !!ex.response,
  run(ctx) {
    const body = ctx.responseBodyText;
    if (!body) return [];
    const patterns: { kind: string; re: RegExp }[] = [
      { kind: 'AWS access key', re: /\bAKIA[0-9A-Z]{16}\b/ },
      { kind: 'JWT', re: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}\b/ },
      { kind: 'private key block', re: /-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----/ },
      { kind: 'Google API key', re: /\bAIza[0-9A-Za-z_-]{35}\b/ },
    ];
    const findings: RawFinding[] = [];
    for (const p of patterns) {
      if (p.re.test(body)) {
        findings.push({
          dedupeKey: `${endpointKey(ctx.exchange)}|secret|${p.kind}`,
          title: `Possible ${p.kind} in response body`,
          severity: 'high',
          confidence: 'tentative',
          description: `The response body appears to contain a ${p.kind}. Verify whether this is a real secret exposed to the client.`,
          remediation: 'Never return secrets to clients; rotate any exposed credentials.',
          evidence: [
            { location: 'response-body', excerpt: `${p.kind} pattern matched (value redacted)` },
          ],
        });
      }
    }
    return findings;
  },
};

const cleartextCredentials: ScannerCheck = {
  module: 'cleartext-credentials',
  version: '1.0.0',
  appliesTo: (ex) => ex.scheme === 'http',
  run(ctx) {
    const ex = ctx.exchange;
    const hasAuth = getHeader(ex.request.headers, 'authorization') !== undefined;
    const hasCookie = getHeader(ex.request.headers, 'cookie') !== undefined;
    if (!hasAuth && !hasCookie) return [];
    return [
      {
        dedupeKey: `${endpointKey(ex)}|cleartext-creds`,
        title: 'Credentials sent over cleartext HTTP',
        severity: 'high',
        confidence: 'firm',
        description:
          'Authorization and/or Cookie headers were transmitted over plaintext HTTP and are exposed to network observers.',
        remediation: 'Serve the application over HTTPS and set the Secure attribute on cookies.',
        evidence: [
          {
            location: 'request-headers',
            excerpt: hasAuth
              ? 'Authorization: [REDACTED] over http'
              : 'Cookie: [REDACTED] over http',
          },
        ],
      },
    ];
  },
};

const reflectedInput: ScannerCheck = {
  module: 'reflected-input',
  version: '1.0.0',
  appliesTo: (ex) =>
    !!ex.response &&
    (isHtml(ex) || (ex.response ? (mimeType(ex.response.headers) ?? '').includes('json') : false)),
  run(ctx) {
    const ex = ctx.exchange;
    let url: URL;
    try {
      url = new URL(ex.request.url);
    } catch {
      return [];
    }
    const body = ctx.responseBodyText;
    if (!body) return [];
    const findings: RawFinding[] = [];
    for (const [key, value] of url.searchParams.entries()) {
      if (value.length < 4) continue; // avoid noise from tiny values
      if (body.includes(value)) {
        findings.push({
          dedupeKey: `${endpointKey(ex)}|reflected|${key}`,
          title: `Observation: request parameter "${key}" reflected in response`,
          severity: 'info',
          confidence: 'tentative',
          description:
            'The value of a request parameter appears verbatim in the response body. This is an OBSERVATION only — it is not confirmed to be exploitable. Manual review is required to determine whether output is safely encoded.',
          remediation:
            'Ensure reflected input is contextually output-encoded; this check does not test for injection.',
          evidence: [
            {
              location: 'response-body',
              excerpt: ctx.redactor.redactText(`reflected value of "${key}"`),
            },
          ],
        });
        if (findings.length >= 5) break;
      }
    }
    return findings;
  },
};

export const BUILTIN_CHECKS: ScannerCheck[] = [
  securityHeaders,
  insecureCookies,
  corsCheck,
  mixedContent,
  sensitiveInUrl,
  cacheControl,
  verboseErrors,
  bannerDisclosure,
  secretsInResponse,
  cleartextCredentials,
  reflectedInput,
];
