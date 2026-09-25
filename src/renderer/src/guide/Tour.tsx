/**
 * The feature walkthrough.
 *
 * Deliberately NOT a modal: it is docked to the bottom and never covers the view
 * it is describing, so the operator reads each step with the actual feature in
 * front of them and can keep clicking around. Skip is present on every step.
 *
 * Escape is "not now", NOT "never". Because the panel is docked precisely so the
 * operator keeps working, Escape-while-typing is reachable — and Escape to cancel
 * a text field is a reflex — so binding it to a permanent skip spent that choice
 * on a keypress nobody meant as one. It now dismisses for the session, leaving
 * the tour resumable, and is ignored entirely while focus is in a field.
 */

import React, { useEffect, useRef } from 'react';
import { useStore } from '../store.js';
import { TOUR_STEPS, stepAt } from './tourSteps.js';
import { OwlMark } from '../components/OwlMark.js';

export function Tour(): JSX.Element | null {
  const s = useStore();
  const panel = useRef<HTMLDivElement>(null);

  const active = s.tourActive;

  useEffect(() => {
    if (!active) return;
    const onKey = (e: KeyboardEvent): void => {
      if (e.key !== 'Escape') return;
      const el = document.activeElement;
      const typing =
        el instanceof HTMLElement &&
        (el.isContentEditable ||
          el instanceof HTMLInputElement ||
          el instanceof HTMLTextAreaElement ||
          el instanceof HTMLSelectElement);
      // The panel is the one exception: Escape with it focused is unambiguous.
      if (typing && el !== panel.current) return;
      e.preventDefault();
      s.dismissTour();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [active, s]);

  // Move focus to the panel when it opens, so the keyboard lands somewhere
  // sensible instead of wherever it was before the tour appeared.
  useEffect(() => {
    if (active) panel.current?.focus();
  }, [active]);

  if (!active) return null;

  const index = Math.min(Math.max(0, s.tourStep), TOUR_STEPS.length - 1);
  const step = stepAt(index);
  const first = index === 0;
  const last = index === TOUR_STEPS.length - 1;

  return (
    <div
      className="tour"
      role="dialog"
      aria-label="Feature walkthrough"
      aria-describedby="tour-body"
      tabIndex={-1}
      ref={panel}
    >
      {/* The panel persists while its contents are swapped, so without a live
          region a screen reader hears nothing after the first step. */}
      <div className="tour-mark">
        <OwlMark />
      </div>
      <div className="tour-text" aria-live="polite">
        <div className="tour-meta">
          Walkthrough · step {index + 1} of {TOUR_STEPS.length}
        </div>
        <h3 className="tour-title">{step.title}</h3>
        <p className="tour-body" id="tour-body">
          {step.body}
        </p>
      </div>
      <div className="tour-actions">
        <button className="ghost" onClick={s.skipTour} title="Never show this again">
          Skip tour
        </button>
        <button onClick={() => s.stepTour(-1)} disabled={first}>
          Back
        </button>
        <button className="primary" onClick={() => s.stepTour(1)}>
          {last ? 'Finish' : 'Next'}
        </button>
      </div>
      <div className="tour-progress" aria-hidden="true">
        <div
          className="tour-progress-fill"
          style={{ width: `${((index + 1) / TOUR_STEPS.length) * 100}%` }}
        />
      </div>
    </div>
  );
}
