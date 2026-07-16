/**
 * Payload materialization and iteration planning for the variation engine.
 *
 * The built-in payload set is deliberately limited to SAFE STRUCTURAL values
 * (boundaries, encodings, type probes). It intentionally contains no injection,
 * exploit, credential, or destructive strings.
 */

import type { PayloadSource, VariationPlan, VariationPosition } from '../../shared/variation.js';

/** Curated benign structural test strings (NOT attack payloads). */
export const SAFE_STRUCTURAL: string[] = [
  '',
  ' ',
  '0',
  '1',
  '-1',
  '2147483647',
  '9999999999',
  'true',
  'false',
  'null',
  'undefined',
  'A'.repeat(256),
  'unicode-한글-テスト',
  '"',
  "'",
  '{}',
  '[]',
];

export const ABSOLUTE_MAX = 100_000; // hard safety ceiling regardless of configured job max

export function materializeSource(source: PayloadSource, cap: number = ABSOLUTE_MAX): string[] {
  const limit = Math.min(cap, ABSOLUTE_MAX);
  switch (source.kind) {
    case 'list':
      return source.values.slice(0, limit);
    case 'builtin':
      return SAFE_STRUCTURAL.slice(0, limit);
    case 'range': {
      const out: string[] = [];
      const step = source.step === 0 ? 1 : source.step;
      if (step > 0) {
        for (let v = source.from; v <= source.to && out.length < limit; v += step)
          out.push(String(v));
      } else {
        for (let v = source.from; v >= source.to && out.length < limit; v += step)
          out.push(String(v));
      }
      return out;
    }
    default:
      return [];
  }
}

export function materializeAll(
  positions: VariationPosition[],
  cap: number = ABSOLUTE_MAX,
): string[][] {
  return positions.map((p) => materializeSource(p.source, cap));
}

/**
 * Exact number of requests a plan will generate, computed from the TRUE payload
 * sizes (bounded only by the absolute ceiling). The configured per-job maximum
 * is enforced separately by the engine, which refuses over-limit plans rather
 * than silently truncating them.
 */
export function planCount(plan: VariationPlan): number {
  const lists = materializeAll(plan.positions);
  if (lists.length === 0) return 0;
  switch (plan.mode) {
    case 'batteringram':
      return lists[0]?.length ?? 0;
    case 'sniper':
      return lists.reduce((sum, l) => sum + l.length, 0);
    case 'pitchfork':
      return Math.min(...lists.map((l) => l.length));
    case 'clusterbomb':
      return lists.reduce((prod, l) => prod * l.length, 1);
    default:
      return 0;
  }
}

export interface Iteration {
  index: number;
  /** One value per position (aligned to plan.positions). */
  assignment: string[];
}

/** Enumerate the per-request payload assignments for a plan. */
export function* iterate(plan: VariationPlan): Generator<Iteration> {
  const lists = materializeAll(plan.positions);
  const n = plan.positions.length;
  if (n === 0) return;
  let index = 0;

  const baseValues = plan.positions.map((p) => p.baseValue ?? '');

  switch (plan.mode) {
    case 'batteringram': {
      for (const v of lists[0] ?? []) {
        yield { index: index++, assignment: new Array(n).fill(v) };
      }
      return;
    }
    case 'sniper': {
      for (let pos = 0; pos < n; pos++) {
        for (const v of lists[pos] ?? []) {
          const assignment = [...baseValues];
          assignment[pos] = v;
          yield { index: index++, assignment };
        }
      }
      return;
    }
    case 'pitchfork': {
      const count = Math.min(...lists.map((l) => l.length));
      for (let k = 0; k < count; k++) {
        yield { index: index++, assignment: lists.map((l) => l[k] as string) };
      }
      return;
    }
    case 'clusterbomb': {
      const counters = new Array(n).fill(0);
      const total = lists.reduce((p, l) => p * l.length, 1);
      for (let k = 0; k < total; k++) {
        yield { index: index++, assignment: lists.map((l, i) => l[counters[i]] as string) };
        // odometer increment
        for (let i = n - 1; i >= 0; i--) {
          counters[i] += 1;
          if (counters[i] < lists[i]!.length) break;
          counters[i] = 0;
        }
      }
      return;
    }
  }
}

/** Render the base raw request with an assignment substituted at each marker. */
export function renderRequest(
  raw: string,
  positions: VariationPosition[],
  assignment: string[],
): string {
  let out = raw;
  positions.forEach((p, i) => {
    out = out.split(p.marker).join(assignment[i] ?? '');
  });
  return out;
}
