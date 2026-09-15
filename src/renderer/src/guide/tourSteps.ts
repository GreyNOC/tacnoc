/**
 * The walkthrough's content.
 *
 * One step per feature, each one switching to the view it describes so the
 * operator reads the description with the thing in front of them. Kept as data
 * rather than markup so the order, the count and the routing can be asserted in
 * a test — every step has to name a view that exists.
 *
 * Bump TOUR_VERSION in @shared/guide.js when steps are added or rewritten.
 */

import type { ViewId } from '../store.js';

export interface TourStep {
  /** Stable across reorderings; used in tests and for resuming. */
  id: string;
  /** The view brought forward while this step is shown. */
  view: ViewId;
  title: string;
  body: string;
}

export const TOUR_STEPS: readonly TourStep[] = [
  {
    id: 'setup',
    view: 'setup',
    title: 'Setup is the readiness check',
    body:
      'Every blocker between you and a legal, working engagement lives here — authorization, ' +
      'scope, the CA, the proxy. It is the same preflight the AI mesh runs before it will do ' +
      'anything, so if this page is green, the engine agrees you are ready.',
  },
  {
    id: 'engagement',
    view: 'engagement',
    title: 'Engagement — who you are and what you may touch',
    body:
      'Program, platform, your researcher handle, and the authorization reference that ends up ' +
      'in the report. Point the engagement folder at the program policy and prior notes, and ' +
      'TACNOC will read them and propose a scope you still have to tick host by host.',
  },
  {
    id: 'scope',
    view: 'scope',
    title: 'Scope is fail-closed',
    body:
      'Nothing automated runs against a host that is not explicitly in scope — an empty scope ' +
      'refuses everything rather than defaulting to permissive. Exclude rules always beat ' +
      'include rules, so carve-outs cannot be overridden by a broader wildcard.',
  },
  {
    id: 'certificate',
    view: 'certificate',
    title: 'Certificate — the CA that makes HTTPS readable',
    body:
      'Generate the project CA and install it in the trust store you are testing from. It mints ' +
      'a leaf per host. Rotate or revoke it here; revoking stops interception immediately, and ' +
      'the guide only claims success once it has actually seen HTTPS decrypt.',
  },
  {
    id: 'target',
    view: 'target',
    title: 'Target Map — the attack surface, ranked',
    body:
      'Every host, path and parameter seen so far, ordered by what is most worth your attention. ' +
      'This is where an engagement usually starts once traffic is flowing, and where the evidence ' +
      'bundle for a single target is exported from.',
  },
  {
    id: 'history',
    view: 'history',
    title: 'HTTP History — everything captured',
    body:
      'The full record of what went through the proxy, searchable, with notes and tags you add ' +
      'as you go. Anything here can be sent to Repeater, Variation or Compare.',
  },
  {
    id: 'intercept',
    view: 'intercept',
    title: 'Intercept — stop traffic mid-flight',
    body:
      'Hold a request before it reaches the server, or a response before it reaches the browser, ' +
      'and edit either. Off by default: turn it on only while you need it, or normal browsing ' +
      'stalls behind the queue.',
  },
  {
    id: 'repeater',
    view: 'repeater',
    title: 'Repeater — one request, over and over',
    body:
      'Resend a single request with whatever you changed. The workhorse for confirming a finding ' +
      'by hand before you automate anything around it.',
  },
  {
    id: 'variation',
    view: 'variation',
    title: 'Variation — the same request, many payloads',
    body:
      'Drive one request across a payload set as a job you can pause, resume and stop. Every ' +
      'request still passes the scope gate, and Emergency Stop in the top bar kills all of it at once.',
  },
  {
    id: 'sequencer',
    view: 'sequencer',
    title: 'Sequencer — are those tokens actually random?',
    body:
      'Collect session tokens, reset codes or nonces and measure them. Turns "that looks ' +
      'predictable" into a number you can put in a report.',
  },
  {
    id: 'encoder',
    view: 'encoder',
    title: 'Encoder / Decoder',
    body:
      'Base64, URL, hex, gzip and the rest, chained. Also inspects a JWT — header, claims and ' +
      'algorithm — without sending it anywhere.',
  },
  {
    id: 'compare',
    view: 'compare',
    title: 'Compare — what actually changed',
    body:
      'Diff two responses as text, as JSON, or byte by byte. The fastest way to tell a real ' +
      'behavioural difference from noise.',
  },
  {
    id: 'findings',
    view: 'findings',
    title: 'Findings — what the passive scanner noticed',
    body:
      'Raised from traffic you already captured, never by probing on its own. Suppress the ones ' +
      'that do not apply; the suppression is recorded rather than silently dropped.',
  },
  {
    id: 'ai',
    view: 'ai',
    title: 'AI Mesh — this one is the egress decision',
    body:
      'Off by default, and the only feature that sends anything off this machine. Turning it on ' +
      'sends captured traffic and your engagement folder to the model provider. It still obeys ' +
      'the scope gate, and it will not start until you have acknowledged the egress explicitly.',
  },
  {
    id: 'extensions',
    view: 'extensions',
    title: 'Extensions',
    body:
      'Extensions run in an isolated host process with the permissions they declare and nothing ' +
      'more. If the host dies, capabilities fail closed rather than falling back to trusting it.',
  },
  {
    id: 'audit',
    view: 'audit',
    title: 'Audit — what was done, and when',
    body:
      'An append-only record of the actions that matter: scope changes, CA rotation, exports, ' +
      'mesh runs. Written redacted, so the log itself is safe to hand over.',
  },
  {
    id: 'settings',
    view: 'settings',
    title: 'Settings — and you can replay this tour',
    body:
      'Proxy listener, redaction rules and at-rest encryption live here. So does the button that ' +
      'runs this walkthrough again, whenever you want it.',
  },
];

/**
 * Indexing that survives `noUncheckedIndexedAccess`.
 *
 * TOUR_STEPS is non-empty by construction and a test asserts it, so the throw is
 * a programming error rather than a case callers are expected to handle — but it
 * beats an assertion that would hand a caller `undefined` at runtime.
 */
export function stepAt(index: number): TourStep {
  const clamped = Math.min(Math.max(0, index), TOUR_STEPS.length - 1);
  const step = TOUR_STEPS[clamped];
  if (!step) throw new Error('TOUR_STEPS is empty');
  return step;
}
