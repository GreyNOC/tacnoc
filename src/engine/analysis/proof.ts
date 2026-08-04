/**
 * Proof of exploit — the differential the engine computes for itself.
 *
 * The precision rule this enforces comes from GreyIQ's BugHunter: **the model
 * proposes, the engine proves.** A model asserting "this endpoint leaks another
 * user's order" is a hypothesis, and a hypothesis written confidently reads
 * exactly like a finding. So the mesh cannot mark anything proven by saying so.
 * It must name two exchanges it already captured — a CONTROL (the request as the
 * legitimate user, or without the change) and a TEST (the one thing varied) —
 * and this module reads both and reports what actually differs.
 *
 * That flips the failure mode. Before, a fabricated finding costs the operator
 * hours of disproving it. Now a fabricated finding fails here, because the two
 * exchanges either differ in the claimed way or they do not, and the model does
 * not get a vote.
 *
 * Deliberately conservative:
 *  - It grades a differential, never a vulnerability. "The response differs" is
 *    a fact; "this is an IDOR" is an interpretation, and stays the analyst's
 *    claim rather than something this function blesses.
 *  - Two identical responses REFUTE the hypothesis. That is a real result and
 *    is recorded as one — a refuted hypothesis is how a hunt stops repeating
 *    itself.
 *  - Anything ambiguous grades `inconclusive` rather than rounding up.
 *
 * Pure and offline.
 */

import type { ExchangeDetail } from '../../shared/detail.js';
import { diffLines } from '../compare/compare.js';

export type ProofOutcome = 'confirmed' | 'refuted' | 'inconclusive';

export interface ProofDifferential {
  statusChanged: boolean;
  controlStatus?: number;
  testStatus?: number;
  /** Response body length in bytes, decoded. */
  controlLength: number;
  testLength: number;
  lengthDelta: number;
  /** Number of differing lines between the two decoded bodies. */
  changedLines: number;
  /** First few differing lines, truncated — the human-readable core of the proof. */
  excerpt: string[];
  /** Response headers present in one and not the other. */
  headerDifferences: string[];
  bodiesIdentical: boolean;
}

export interface ProofResult {
  outcome: ProofOutcome;
  /** Why the engine graded it this way, in one sentence. */
  reason: string;
  controlExchangeId: string;
  testExchangeId: string;
  /** Echoed back so the record says what was being tested. */
  claim: string;
  differential: ProofDifferential;
  /** Cautions the operator must read before treating this as a finding. */
  caveats: string[];
}

const MAX_EXCERPT_LINES = 12;
const MAX_EXCERPT_CHARS = 300;

function bodyBytes(detail: ExchangeDetail, which: 'request' | 'response'): Buffer {
  const message = which === 'request' ? detail.request : detail.response;
  if (!message) return Buffer.alloc(0);
  try {
    return Buffer.from(message.bodyBase64, 'base64');
  } catch {
    return Buffer.alloc(0);
  }
}

/**
 * Header name AND value, for comparison.
 *
 * Comparing only the set of header NAMES made whole vulnerability classes
 * invisible: an open redirect changes `Location`'s value, session fixation
 * changes `Set-Cookie`'s flags, a CORS or CSP defect changes a policy value —
 * none of them add or remove a header. All of those graded "refuted", and
 * `record_hunt_outcome` then carried the false disproof into future hunts.
 */
function headerPairs(detail: ExchangeDetail): string[] {
  return (detail.response?.headers ?? []).map((h) => `${h.name.toLowerCase()}: ${h.value}`);
}

/**
 * Headers that differ between almost any two responses and say nothing about
 * the application's behaviour. Excluded so a `Date` cannot manufacture a
 * finding — and, equally, so its presence cannot block a refutation.
 */
const INCIDENTAL_HEADERS = new Set([
  'date',
  'age',
  'expires',
  'keep-alive',
  'report-to',
  'x-request-id',
  'x-trace-id',
  'x-correlation-id',
  'x-amzn-requestid',
  'cf-ray',
  'x-served-by',
  'x-timer',
]);

function meaningfulHeaderDifferences(control: ExchangeDetail, test: ExchangeDetail): string[] {
  const controlPairs = new Set(headerPairs(control));
  const testPairs = new Set(headerPairs(test));
  const incidental = (pair: string): boolean =>
    INCIDENTAL_HEADERS.has(pair.slice(0, Math.max(0, pair.indexOf(':'))));
  return [
    ...[...testPairs].filter((p) => !controlPairs.has(p)).map((p) => ({ sign: '+', pair: p })),
    ...[...controlPairs].filter((p) => !testPairs.has(p)).map((p) => ({ sign: '-', pair: p })),
  ]
    .filter((entry) => !incidental(entry.pair))
    .map((entry) => `${entry.sign}${entry.pair}`)
    .slice(0, 20);
}

/**
 * How the two REQUESTS differ. A differential is only attributable when exactly
 * one thing changed: comparing `/a` against `/completely/unrelated` and calling
 * the difference a finding is how a hypothesis gets confirmed by accident, and
 * comparing a request against an identical copy of itself measures the
 * endpoint's nondeterminism rather than its behaviour.
 */
function requestDelta(control: ExchangeDetail, test: ExchangeDetail): string[] {
  const delta: string[] = [];
  if (control.request.method !== test.request.method) delta.push('method');
  if (control.host !== test.host) delta.push('host');
  if (control.request.url !== test.request.url) delta.push('URL');
  if (control.request.bodyBase64 !== test.request.bodyBase64) delta.push('request body');
  if (JSON.stringify(control.request.headers) !== JSON.stringify(test.request.headers)) {
    delta.push('request headers');
  }
  return delta;
}

/**
 * Compare a control and a test exchange and grade the differential.
 *
 * `claim` is what the caller says the difference would demonstrate. It is
 * recorded verbatim and never interpreted — grading depends only on the bytes.
 */
export function proveDifferential(
  control: ExchangeDetail,
  test: ExchangeDetail,
  claim: string,
): ProofResult {
  const controlBytes = bodyBytes(control, 'response');
  const testBytes = bodyBytes(test, 'response');
  const controlText = controlBytes.toString('utf8');
  const testText = testBytes.toString('utf8');
  const controlStatus = control.response?.statusCode;
  const testStatus = test.response?.statusCode;

  const lines = diffLines(controlText, testText);
  const changed = lines.filter((l) => l.type !== 'equal');
  const excerpt = changed.slice(0, MAX_EXCERPT_LINES).map((l) => {
    const text =
      l.text.length > MAX_EXCERPT_CHARS ? `${l.text.slice(0, MAX_EXCERPT_CHARS)}…` : l.text;
    return `${l.type === 'add' ? '+' : '-'} ${text}`;
  });

  const headerDifferences = meaningfulHeaderDifferences(control, test);
  // Compare BYTES, not decoded text. Two different binary or differently
  // compressed bodies decode to the same replacement characters, which read as
  // identical; and gzip of the same plaintext at two levels reads as different.
  const bodiesIdentical = controlBytes.equals(testBytes);
  const statusChanged = controlStatus !== testStatus;

  const differential: ProofDifferential = {
    statusChanged,
    ...(controlStatus !== undefined ? { controlStatus } : {}),
    ...(testStatus !== undefined ? { testStatus } : {}),
    controlLength: controlBytes.byteLength,
    testLength: testBytes.byteLength,
    lengthDelta: testBytes.byteLength - controlBytes.byteLength,
    changedLines: changed.length,
    excerpt,
    headerDifferences,
    bodiesIdentical,
  };

  const caveats: string[] = [];
  const inconclusive = (reason: string): ProofResult => ({
    outcome: 'inconclusive',
    reason,
    controlExchangeId: control.id,
    testExchangeId: test.id,
    claim,
    differential,
    caveats,
  });

  if (control.id === test.id) {
    return inconclusive(
      'The control and test are the same exchange, so nothing was compared. Capture a genuine control before claiming a differential.',
    );
  }
  if (!control.response || !test.response) {
    return inconclusive(
      'One of the two exchanges has no response (it errored or was never completed), so there is nothing to compare.',
    );
  }

  // Attributability. A difference only means something if you can say what
  // caused it, and that requires exactly one changed variable.
  const delta = requestDelta(control, test);
  if (delta.length === 0) {
    return inconclusive(
      'The two requests are identical, so any difference between the responses measures how nondeterministic the endpoint is, not how it behaves. Vary exactly one thing and capture a fresh test.',
    );
  }
  if (delta.length > 1) {
    caveats.push(
      `More than one variable differs between the requests (${delta.join(', ')}). A difference here cannot be attributed to any single one of them — isolate a single change and re-test.`,
    );
  }
  if (control.request.method !== test.request.method) {
    caveats.push(
      `The method differs (${control.request.method} vs ${test.request.method}), so different handlers may have run.`,
    );
  }
  if (control.host !== test.host) {
    caveats.push(
      `The host differs (${control.host} vs ${test.host}) — comparing across hosts rarely isolates anything.`,
    );
  }
  if (testStatus === 429 || controlStatus === 429) {
    caveats.push(
      'A 429 is in play: this difference may be rate limiting, not application behaviour.',
    );
  }
  if ((testStatus ?? 0) >= 500 || (controlStatus ?? 0) >= 500) {
    caveats.push(
      'A 5xx is in play: a server error is not by itself a finding, and it may be incidental.',
    );
  }
  if (control.response.bodyTruncated || test.response.bodyTruncated) {
    caveats.push(
      'At least one body was truncated at capture, so the comparison covers only the captured prefix.',
    );
  }
  if (changed.length > 0 && !bodiesIdentical && looksDynamic(changed.map((l) => l.text))) {
    caveats.push(
      'The differing lines look like per-response values (tokens, nonces, timestamps, ids). Confirm the difference is not just the page changing between requests.',
    );
  }

  if (bodiesIdentical && !statusChanged && headerDifferences.length === 0) {
    return {
      outcome: 'refuted',
      reason:
        'Status, meaningful response headers, and body bytes are all identical. The hypothesis is refuted — record it so the hunt does not retry it.',
      controlExchangeId: control.id,
      testExchangeId: test.id,
      claim,
      differential,
      caveats,
    };
  }

  if (statusChanged || !bodiesIdentical || headerDifferences.length > 0) {
    const parts: string[] = [];
    if (statusChanged) parts.push(`status ${String(controlStatus)} → ${String(testStatus)}`);
    if (!bodiesIdentical) {
      parts.push(
        `${changed.length} body line(s) changed (${differential.lengthDelta >= 0 ? '+' : ''}${differential.lengthDelta} bytes)`,
      );
    }
    if (headerDifferences.length) parts.push(`${headerDifferences.length} response header(s)`);
    return {
      outcome: 'confirmed',
      reason: `The responses differ: ${parts.join(', ')}.`,
      controlExchangeId: control.id,
      testExchangeId: test.id,
      claim,
      differential,
      caveats,
    };
  }

  return inconclusive(
    'Nothing meaningful differs between the two responses once incidental headers are set aside.',
  );
}

/** Heuristic: do the differing lines look like per-response noise? */
function looksDynamic(texts: string[]): boolean {
  const joined = texts.join(' ');
  return /(csrf|nonce|token|timestamp|request[_-]?id|session|expires)/i.test(joined);
}
