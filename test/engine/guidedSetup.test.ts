/**
 * Guided setup: preference repair, walkthrough progression, and the two drift
 * guards that matter.
 *
 * The drift guards are the point of the last block. A "Fix this" button that
 * routes nowhere, or a tour step naming a view that no longer renders, both fail
 * silently — the button does nothing, the step shows the fallback view — so both
 * are asserted against the source that defines the real set.
 */

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import * as path from 'node:path';
import {
  TOUR_VERSION,
  advanceTour,
  defaultUiPreferences,
  destinationForCheck,
  parseUiPreferences,
  restartTour,
  resumeStep,
  shouldOfferTour,
  skipTour,
  type UiPreferences,
} from '@shared/guide.js';
import { TOUR_STEPS } from '../../src/renderer/src/guide/tourSteps.js';

const root = path.resolve(__dirname, '../..');
const prefsWith = (tour: Partial<UiPreferences['tour']>): UiPreferences => ({
  tour: { ...defaultUiPreferences().tour, ...tour },
});

describe('preference repair', () => {
  it('returns defaults for anything that is not a preferences object', () => {
    for (const junk of [null, undefined, 42, 'nope', [], { tour: 'yes' }, { tour: null }]) {
      expect(parseUiPreferences(junk)).toEqual(defaultUiPreferences());
    }
  });

  it('keeps good fields and repairs bad ones in the same object', () => {
    const parsed = parseUiPreferences({
      tour: { status: 'in-progress', step: -4, version: 1.9 },
      somethingFromAFutureVersion: true,
    });
    expect(parsed.tour.status).toBe('in-progress');
    expect(parsed.tour.step).toBe(0); // clamped up from -4
    expect(parsed.tour.version).toBe(1); // truncated, not rounded
    expect(parsed).not.toHaveProperty('somethingFromAFutureVersion');
  });

  it('rejects an unknown status rather than trusting it', () => {
    expect(parseUiPreferences({ tour: { status: 'banana' } }).tour.status).toBe('unseen');
  });

  it('does not treat a non-finite step as a number', () => {
    expect(parseUiPreferences({ tour: { step: Number.NaN } }).tour.step).toBe(0);
    expect(parseUiPreferences({ tour: { step: Infinity } }).tour.step).toBe(0);
  });
});

describe('when the walkthrough is offered', () => {
  it('offers an unseen tour, and resumes one left part-way', () => {
    expect(shouldOfferTour(prefsWith({ status: 'unseen' }))).toBe(true);
    expect(shouldOfferTour(prefsWith({ status: 'in-progress' }))).toBe(true);
  });

  it('STAYS skipped — the whole point of a skip button', () => {
    expect(shouldOfferTour(prefsWith({ status: 'skipped', version: TOUR_VERSION }))).toBe(false);
    expect(shouldOfferTour(prefsWith({ status: 'done', version: TOUR_VERSION }))).toBe(false);
  });

  it('offers again once the content version moves on', () => {
    expect(shouldOfferTour(prefsWith({ status: 'skipped', version: TOUR_VERSION - 1 }))).toBe(true);
    expect(shouldOfferTour(prefsWith({ status: 'done', version: TOUR_VERSION - 1 }))).toBe(true);
  });

  it('resumes only an in-progress tour, and never past the end', () => {
    expect(resumeStep(prefsWith({ status: 'in-progress', step: 3 }), 10)).toBe(3);
    expect(resumeStep(prefsWith({ status: 'in-progress', step: 99 }), 10)).toBe(9);
    expect(resumeStep(prefsWith({ status: 'done', step: 5 }), 10)).toBe(0);
    expect(resumeStep(prefsWith({ status: 'in-progress', step: 5 }), 0)).toBe(0);
  });
});

describe('walkthrough progression', () => {
  const at = (step: number): UiPreferences['tour'] =>
    ({ status: 'in-progress', step, version: TOUR_VERSION }) as const;

  it('advances and marks itself in-progress', () => {
    expect(advanceTour(at(0), 1, 5)).toEqual({
      status: 'in-progress',
      step: 1,
      version: TOUR_VERSION,
    });
  });

  it('Back on the first step stays put instead of closing the tour', () => {
    expect(advanceTour(at(0), -1, 5).step).toBe(0);
    expect(advanceTour(at(0), -1, 5).status).toBe('in-progress');
  });

  it('finishes when stepping past the last step', () => {
    expect(advanceTour(at(4), 1, 5).status).toBe('done');
  });

  it('skip and restart are terminal and clean respectively', () => {
    expect(skipTour()).toEqual({ status: 'skipped', step: 0, version: TOUR_VERSION });
    expect(restartTour()).toEqual({ status: 'in-progress', step: 0, version: TOUR_VERSION });
  });
});

describe('tour content', () => {
  it('has unique ids and no empty copy', () => {
    const ids = TOUR_STEPS.map((s) => s.id);
    expect(new Set(ids).size).toBe(ids.length);
    for (const step of TOUR_STEPS) {
      expect(step.title.trim().length).toBeGreaterThan(0);
      expect(step.body.trim().length).toBeGreaterThan(0);
    }
  });

  it('covers the AI mesh, because that step is the egress warning', () => {
    const ai = TOUR_STEPS.find((s) => s.view === 'ai');
    expect(ai).toBeDefined();
    expect(ai?.body.toLowerCase()).toContain('off by default');
  });

  /**
   * Drift guard. A step pointing at a view `ActiveView` does not handle falls
   * through to the default branch and silently shows HTTP History instead.
   */
  it('names only views the app actually renders', () => {
    const app = readFileSync(path.join(root, 'src/renderer/src/App.tsx'), 'utf8');
    const activeView = app.slice(app.indexOf('function ActiveView'));
    const rendered = new Set([...activeView.matchAll(/case '([a-z]+)':/g)].map((m) => m[1] ?? ''));
    expect(rendered.size).toBeGreaterThan(10);
    for (const step of TOUR_STEPS) {
      expect(rendered, `tour step "${step.id}" targets an unrendered view`).toContain(step.view);
    }
  });
});

describe('setup checklist routing', () => {
  it('sends each kind of check somewhere that can fix it', () => {
    expect(destinationForCheck('scope')).toBe('scope');
    expect(destinationForCheck('authorization')).toBe('engagement');
    expect(destinationForCheck('user-agent')).toBe('engagement');
    expect(destinationForCheck('workspace')).toBe('engagement');
    expect(destinationForCheck('history')).toBe('history');
    expect(destinationForCheck('ca')).toBe('certificate');
    expect(destinationForCheck('ca-expiring')).toBe('certificate');
    expect(destinationForCheck('ca-key-storage')).toBe('certificate');
    expect(destinationForCheck('proxy')).toBe('proxy');
    expect(destinationForCheck('proxy-bind')).toBe('proxy');
  });

  it('falls back rather than throwing on an id it has never seen', () => {
    expect(destinationForCheck('invented-later')).toBe('none');
  });

  /**
   * Drift guard. Preflight is free to add checks; if one arrives with no route,
   * the operator gets an item on the checklist and no way to act on it. `project`
   * is the deliberate exception — it reports the project itself, which is already
   * open by the time anyone can read the checklist.
   */
  it('routes every check id preflight can emit', () => {
    const src = readFileSync(path.join(root, 'src/engine/engagement/preflight.ts'), 'utf8');
    const ids = new Set([...src.matchAll(/\bid: '([a-z0-9-]+)'/g)].map((m) => m[1] ?? ''));
    expect(ids.size).toBeGreaterThan(5);
    const unrouted = [...ids].filter(
      (id) => id !== 'project' && destinationForCheck(id) === 'none',
    );
    expect(unrouted, 'preflight checks with no way to act on them').toEqual([]);
  });
});
