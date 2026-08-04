/**
 * The engagement layer: the paperwork of a bug-bounty or pentest engagement,
 * expressed as data the engine can enforce.
 *
 * A program's rules of engagement usually carry two mechanical requirements
 * beyond "stay in scope":
 *
 *  1. **Identify your traffic.** Most platforms ask researchers to send a
 *     recognisable `User-Agent` (and sometimes an extra header such as
 *     `X-Bug-Bounty: <handle>`) so the target's blue team can tell authorized
 *     testing apart from a real attack. Getting this wrong gets researchers
 *     blocked, or worse, reported. It is enforced here in the engine — on the
 *     Repeater and the Variation engine — not left to the operator to remember
 *     on every request.
 *  2. **Know your interception state.** TLS interception only works while the
 *     project CA is valid and trusted by the test browser. A silently expired
 *     or revoked CA looks exactly like "the target has no traffic".
 *
 * Both are checked by the preflight report before any planning happens.
 *
 * These types are shared by engine, main, and renderer, so they stay pure data
 * plus pure validators — no I/O, no Node built-ins.
 */

/** A required identification header, e.g. `X-Bug-Bounty: greynoc`. */
export interface IdentityHeader {
  name: string;
  value: string;
}

/**
 * Program-mandated User-Agent. `required` empty means "not applicable" — plenty
 * of programs do not ask for one, and preflight reports that honestly rather
 * than inventing a requirement.
 */
export interface UserAgentPolicy {
  /** Exact User-Agent the program requires. Empty = no requirement. */
  required: string;
  /**
   * The master enforcement switch for engagement identity. When true the engine
   * REWRITES every request it generates (Repeater + Variation) to carry the
   * required User-Agent and all identity headers. When false the requirement is
   * advisory: preflight still reports compliance, but nothing is rewritten.
   */
  enforce: boolean;
}

export interface EngagementProfile {
  /** Program name, e.g. "Acme Public Bounty". Free text, for the report header. */
  program: string;
  /** Platform the program is run on, e.g. "hackerone". Free text. */
  platform: string;
  /** Researcher handle used on that platform. */
  handle: string;
  /**
   * Where the signed authorization / scope document lives. `ProjectInfo` carries
   * one too (set at project creation); this is the engagement-level reference
   * that preflight reports on and the mesh cites in the report.
   */
  authorizationRef: string;
  userAgent: UserAgentPolicy;
  /** Extra headers the program requires on all testing traffic. */
  identityHeaders: IdentityHeader[];
  /**
   * Folder the AI may read while preparing an engagement — program policy,
   * scope PDFs exported to text, prior reports, engagement notes. Empty means
   * "the project directory itself". Operator-set only: nothing in the AI layer
   * can point this somewhere new.
   */
  workspaceDir: string;
  /** Operator notes surfaced to the mesh during recon. */
  notes: string;
}

export function defaultEngagementProfile(): EngagementProfile {
  return {
    program: '',
    platform: '',
    handle: '',
    authorizationRef: '',
    userAgent: { required: '', enforce: false },
    identityHeaders: [],
    workspaceDir: '',
    notes: '',
  };
}

// ---- validation -------------------------------------------------------------
//
// Header names and values reach Node's HTTP layer and are written into the wire
// bytes of every generated request. A CR or LF smuggled into either would let a
// profile inject an extra header — or an entire extra request — into traffic
// aimed at a third party's production system. Validate at the boundary where a
// human or a model can set these, and refuse rather than sanitize: silently
// stripping a newline would send a request the operator did not write.

/** RFC 9110 token: the only characters legal in a field name. */
const TOKEN_RE = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;

/**
 * Field values may not carry CR, LF, NUL, or other control characters.
 * Matching control characters is the entire purpose here — this pattern is what
 * stops a header value from smuggling in a second header, or a second request.
 */
// eslint-disable-next-line no-control-regex
const CTL_RE = /[\0-\x08\x0A-\x1F\x7F]/;

/** The character set Node's HTTP layer will actually put on the wire. */
const TRANSPORTABLE_VALUE_RE = /^[\t\x20-\x7e\x80-\xff]*$/;

/**
 * Headers a profile may not set.
 *
 * Two groups. The framing headers are set by the engine and forging them
 * corrupts the request. `cookie` and `authorization` are here for a sharper
 * reason: they are **credentials, and identity headers are applied per request
 * regardless of destination.** The Repeater deliberately strips both on a
 * cross-host redirect so a token is not handed to whatever host the target
 * redirected to — and a profile-supplied `Authorization` would be re-applied on
 * the very next hop, walking the credential straight to an attacker-controlled
 * destination. Credentials belong in the request or the cookie jar, which are
 * host-aware; identity headers are not.
 */
const RESERVED_HEADERS = new Set([
  'host',
  'content-length',
  'transfer-encoding',
  'connection',
  'upgrade',
  'te',
  'trailer',
  'proxy-authorization',
  'proxy-connection',
  'cookie',
  'authorization',
]);

export const MAX_IDENTITY_HEADERS = 16;
export const MAX_HEADER_VALUE_LENGTH = 1024;

export function validateHeaderName(name: string): string | null {
  if (!name) return 'header name is empty';
  if (!TOKEN_RE.test(name)) {
    return `"${name}" is not a valid header name (letters, digits and !#$%&'*+-.^_\`|~ only)`;
  }
  if (RESERVED_HEADERS.has(name.toLowerCase())) {
    return `"${name}" is set by the engine and cannot be overridden by the engagement profile`;
  }
  return null;
}

export function validateHeaderValue(name: string, value: string): string | null {
  if (CTL_RE.test(value)) {
    return `the value for "${name}" contains a control character (CR/LF/NUL); header injection is refused`;
  }
  // Node refuses anything outside tab, printable ASCII, and Latin-1 at send time
  // with an opaque ERR_INVALID_CHAR. Catching it here means the operator is told
  // which field is wrong instead of every generated request failing later.
  if (!TRANSPORTABLE_VALUE_RE.test(value)) {
    return `the value for "${name}" contains a character the HTTP layer cannot send (only tab, printable ASCII, and Latin-1 are allowed)`;
  }
  if (value.length > MAX_HEADER_VALUE_LENGTH) {
    return `the value for "${name}" is ${value.length} characters; the limit is ${MAX_HEADER_VALUE_LENGTH}`;
  }
  return null;
}

/**
 * Validate a whole profile. Returns the list of problems — empty means valid.
 * `setEngagementProfile` refuses to persist a profile with any problem, so the
 * enforcement path never has to defend against a malformed one.
 */
export function validateEngagementProfile(profile: EngagementProfile): string[] {
  const problems: string[] = [];
  const ua = profile.userAgent?.required ?? '';
  const uaProblem = validateHeaderValue('User-Agent', ua);
  if (uaProblem) problems.push(uaProblem);
  const headers = profile.identityHeaders ?? [];
  if (profile.userAgent?.enforce && !ua.trim() && headers.length === 0) {
    problems.push(
      'Identity enforcement is on but nothing would be applied: set a User-Agent, an identity header, or turn enforcement off.',
    );
  }

  if (headers.length > MAX_IDENTITY_HEADERS) {
    problems.push(
      `${headers.length} identity headers configured; the limit is ${MAX_IDENTITY_HEADERS}.`,
    );
  }
  const seen = new Set<string>();
  for (const header of headers) {
    const nameProblem = validateHeaderName(header.name ?? '');
    if (nameProblem) {
      problems.push(nameProblem);
      continue;
    }
    const valueProblem = validateHeaderValue(header.name, header.value ?? '');
    if (valueProblem) problems.push(valueProblem);
    const lower = header.name.toLowerCase();
    if (lower === 'user-agent') {
      problems.push('Set the User-Agent through the User-Agent policy, not as an identity header.');
    }
    if (seen.has(lower)) problems.push(`duplicate identity header "${header.name}"`);
    seen.add(lower);
  }
  return problems;
}

// ---- CA lifecycle -----------------------------------------------------------

/** One entry in the project's CA revocation history. Append-only, audited. */
export interface CaRevocation {
  fingerprint: string;
  serial: string;
  revokedAt: number;
  reason: string;
  /** 'revoke' destroyed the CA outright; 'rotate' replaced it with a fresh one. */
  action: 'revoke' | 'rotate';
}

export interface CaCertStatus {
  subject: string;
  issuer: string;
  serial: string;
  fingerprint: string;
  notBefore: number;
  notAfter: number;
  /** Whole days until notAfter; negative once expired. */
  daysRemaining: number;
  expired: boolean;
  /** True within 30 days of expiry — reissue before the engagement stalls. */
  expiringSoon: boolean;
}

export interface CaStatus {
  certificate?: CaCertStatus;
  /**
   * False after `revokeCa`. TLS interception is off: CONNECT tunnels pass
   * through opaquely and HTTPS traffic is no longer captured until the CA is
   * reissued. This is a deliberate, testable state, not an error.
   */
  interceptionEnabled: boolean;
  revokedAt?: number;
  revokedReason?: string;
  /** How the CA private key is held (OS secure storage vs. file fallback). */
  secureBackend: boolean;
  backendName: string;
  /** Most recent revocations/rotations first. */
  history: CaRevocation[];
  /**
   * Evidence that interception actually works, read from captured traffic:
   * decrypted HTTPS exchanges seen in this project. Zero with a running proxy
   * and browsing activity means the CA is almost certainly not trusted by the
   * test browser.
   */
  observedHttpsExchanges: number;
  installInstructions: string;
}

// ---- preflight --------------------------------------------------------------

export type PreflightSeverity = 'blocker' | 'warning' | 'ok';

export interface PreflightCheck {
  id: string;
  title: string;
  severity: PreflightSeverity;
  detail: string;
  /** What the operator (or the mesh) should do about it. */
  remedy?: string;
}

export interface IdentityCompliance {
  /** Whether a User-Agent requirement applies at all. */
  applicable: boolean;
  required: string;
  enforced: boolean;
  /** Automated exchanges inspected from recent history. */
  sampled: number;
  /** How many carried the required User-Agent and identity headers. */
  compliant: number;
  /** Distinct User-Agent values observed on automated traffic. */
  observedUserAgents: string[];
  missingHeaders: string[];
}

export interface WorkspaceSummary {
  root: string;
  /** True when the workspace is the project directory itself. */
  isProjectDir: boolean;
  fileCount: number;
  totalBytes: number;
  /** Documents most likely to hold rules of engagement, newest first. */
  notableFiles: string[];
  /** Set when the folder could not be read (missing, permissions). */
  error?: string;
}

export interface PreflightReport {
  generatedAt: number;
  project?: {
    name: string;
    directory: string;
    authorizationRef?: string;
    encryptedAtRest: boolean;
  };
  scope: {
    includeRules: number;
    excludeRules: number;
    hosts: string[];
    /** True when nothing is in scope, so every automated request would be refused. */
    failClosed: boolean;
  };
  ca: CaStatus;
  identity: IdentityCompliance;
  proxy: { running: boolean; host?: string; port?: number; loopbackOnly: boolean };
  workspace: WorkspaceSummary;
  history: { exchanges: number; findings: number };
  checks: PreflightCheck[];
  /** True when no check is a blocker: the engagement is ready to test. */
  ready: boolean;
}
