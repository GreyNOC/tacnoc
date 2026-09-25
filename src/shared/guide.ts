/**
 * Guided setup — the state behind intake, program setup and the walkthrough.
 *
 * Everything here is pure and total: no file IO, no throwing. The walkthrough is
 * a UI preference that has to survive a corrupt or hand-edited preferences file
 * without taking the app down with it, so `parseUiPreferences` repairs rather
 * than rejects. `src/main/uiPrefs.ts` is the thin file-IO layer over it.
 */

/**
 * Bump when walkthrough steps are added or materially rewritten. An operator who
 * finished or skipped an older tour is offered the new one once — they can skip
 * it again in one click, and a skip at the current version is never re-offered.
 */
export const TOUR_VERSION = 1;

export type TourStatus = 'unseen' | 'in-progress' | 'done' | 'skipped';

export interface TourState {
  status: TourStatus;
  /** Step to resume on. Always a valid index for the current step count. */
  step: number;
  /** Tour version the operator last finished or skipped. */
  version: number;
}

export interface UiPreferences {
  tour: TourState;
}

const STATUSES: readonly TourStatus[] = ['unseen', 'in-progress', 'done', 'skipped'];

export function defaultTourState(): TourState {
  return { status: 'unseen', step: 0, version: TOUR_VERSION };
}

export function defaultUiPreferences(): UiPreferences {
  return { tour: defaultTourState() };
}

/**
 * Read preferences from whatever was on disk.
 *
 * Total by design: a truncated write, a hand edit, or a file from a future
 * version all yield usable preferences rather than an exception on a path that
 * runs before the window is even shown. Unknown fields are dropped, out-of-range
 * values are clamped.
 */
export function parseUiPreferences(raw: unknown): UiPreferences {
  const prefs = defaultUiPreferences();
  if (!isRecord(raw)) return prefs;

  const tour = raw.tour;
  if (!isRecord(tour)) return prefs;

  if (typeof tour.status === 'string' && (STATUSES as readonly string[]).includes(tour.status)) {
    prefs.tour.status = tour.status as TourStatus;
  }
  if (isFiniteNumber(tour.step)) {
    prefs.tour.step = Math.max(0, Math.trunc(tour.step));
  }
  if (isFiniteNumber(tour.version)) {
    // Clamped at both ends. A file claiming a version from the future would
    // otherwise make `shouldOfferTour` false forever, silently suppressing the
    // walkthrough for good.
    prefs.tour.version = Math.min(Math.max(0, Math.trunc(tour.version)), TOUR_VERSION);
  }
  return prefs;
}

/**
 * Whether to put the walkthrough in front of the operator without being asked.
 *
 * Offered when never seen, when it was left part-way through, and once after the
 * content version moves on. Never offered again for a tour that was skipped or
 * finished at the current version — "skippable" has to mean it stays skipped.
 */
export function shouldOfferTour(prefs: UiPreferences, version = TOUR_VERSION): boolean {
  const { status, version: seen } = prefs.tour;
  if (status === 'unseen' || status === 'in-progress') return true;
  return seen < version;
}

/** Where a resumed tour picks up, clamped to the steps that actually exist. */
export function resumeStep(
  prefs: UiPreferences,
  stepCount: number,
  version = TOUR_VERSION,
): number {
  if (stepCount <= 0) return 0;
  if (prefs.tour.status !== 'in-progress') return 0;
  // An index recorded against older content points at a different step now:
  // inserting two steps near the front turned "resume on the egress warning"
  // into "resume on Compare". A valid index is not the same as the right one.
  if (prefs.tour.version < version) return 0;
  return Math.min(Math.max(0, prefs.tour.step), stepCount - 1);
}

/**
 * Move through the tour. Stepping past the last step finishes it; stepping back
 * from the first stays put rather than closing, so Back is never a trapdoor.
 */
export function advanceTour(state: TourState, delta: number, stepCount: number): TourState {
  if (stepCount <= 0) return { ...state, status: 'done', step: 0, version: TOUR_VERSION };
  const next = state.step + delta;
  if (next >= stepCount) return { status: 'done', step: stepCount - 1, version: TOUR_VERSION };
  const step = Math.max(0, next);
  return { status: 'in-progress', step, version: TOUR_VERSION };
}

/** Skip is terminal for this version, from any step. */
export function skipTour(): TourState {
  return { status: 'skipped', step: 0, version: TOUR_VERSION };
}

/** Replaying from Settings starts clean, whatever happened last time. */
export function restartTour(): TourState {
  return { status: 'in-progress', step: 0, version: TOUR_VERSION };
}

// ---- preflight routing ------------------------------------------------------

/**
 * Where the operator has to go to clear a preflight check.
 *
 * Kept here, beside the pure logic, so it can be tested against the check ids
 * `preflight.ts` actually emits — a "Fix this" button that routes nowhere is
 * exactly the kind of wiring rot a checklist invites.
 */
export type SetupDestination =
  'engagement' | 'scope' | 'certificate' | 'history' | 'settings' | 'proxy' | 'none';

/**
 * Every preflight check id, and where the operator has to go to clear it.
 *
 * An explicit table rather than prefix matching, which was a rubber stamp: a
 * route keyed on `id.startsWith('proxy')` sent `proxy-bind` — "the proxy is
 * bound to a non-loopback address" — to a button labelled "Start the proxy",
 * which no-ops, because that check can only fire while the proxy is ALREADY
 * running. The drift guard passed it happily. Listing ids one by one means a
 * new check has to be considered rather than absorbed by a prefix.
 *
 * `'none'` is a deliberate answer, not a fallback: it means there is no button
 * worth offering. `history` says "browse the target through the proxy" — there
 * is no control in this app that does that.
 */
export const CHECK_DESTINATIONS: Readonly<Record<string, SetupDestination>> = {
  project: 'none',
  authorization: 'engagement',
  scope: 'scope',
  'user-agent': 'engagement',
  workspace: 'engagement',
  history: 'none',
  ca: 'certificate',
  'ca-revoked': 'certificate',
  'ca-expired': 'certificate',
  'ca-expiring': 'certificate',
  'ca-key-storage': 'certificate',
  'ca-trust': 'certificate',
  // Not running: the checklist can start it.
  proxy: 'proxy',
  // Bound somewhere it should not be: only the listener config fixes that.
  'proxy-bind': 'settings',
};

export function destinationForCheck(id: string): SetupDestination {
  return CHECK_DESTINATIONS[id] ?? 'none';
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function isFiniteNumber(v: unknown): v is number {
  return typeof v === 'number' && Number.isFinite(v);
}
