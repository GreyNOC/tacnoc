/**
 * Request/response comparison in three modes: line-based text diff, JSON-aware
 * structural diff, and byte-level diff. Pure functions; used by the UI compare
 * tool and available to extensions.
 */

export type LineDiffType = 'equal' | 'add' | 'remove';

export interface LineDiff {
  type: LineDiffType;
  text: string;
}

/** Guard: very large inputs fall back to a coarse whole-block diff. */
const MAX_LINES_FOR_LCS = 5000;

/** Line-based diff using a longest-common-subsequence table. */
export function diffLines(a: string, b: string): LineDiff[] {
  const left = a.split('\n');
  const right = b.split('\n');

  if (left.length > MAX_LINES_FOR_LCS || right.length > MAX_LINES_FOR_LCS) {
    return a === b
      ? left.map((t) => ({ type: 'equal' as const, text: t }))
      : [
          ...left.map((t) => ({ type: 'remove' as const, text: t })),
          ...right.map((t) => ({ type: 'add' as const, text: t })),
        ];
  }

  const n = left.length;
  const m = right.length;
  // lcs[i][j] = LCS length of left[i:] and right[j:]
  const lcs: number[][] = Array.from({ length: n + 1 }, () => new Array<number>(m + 1).fill(0));
  for (let i = n - 1; i >= 0; i--) {
    for (let j = m - 1; j >= 0; j--) {
      lcs[i]![j] =
        left[i] === right[j] ? lcs[i + 1]![j + 1]! + 1 : Math.max(lcs[i + 1]![j]!, lcs[i]![j + 1]!);
    }
  }

  const out: LineDiff[] = [];
  let i = 0;
  let j = 0;
  while (i < n && j < m) {
    if (left[i] === right[j]) {
      out.push({ type: 'equal', text: left[i] as string });
      i++;
      j++;
    } else if (lcs[i + 1]![j]! >= lcs[i]![j + 1]!) {
      out.push({ type: 'remove', text: left[i] as string });
      i++;
    } else {
      out.push({ type: 'add', text: right[j] as string });
      j++;
    }
  }
  while (i < n) out.push({ type: 'remove', text: left[i++] as string });
  while (j < m) out.push({ type: 'add', text: right[j++] as string });
  return out;
}

export type JsonDiffKind = 'added' | 'removed' | 'changed';

export interface JsonDiffEntry {
  path: string;
  kind: JsonDiffKind;
  left?: unknown;
  right?: unknown;
}

/** Structural diff of two JSON documents. Throws if either side is invalid JSON. */
export function diffJson(a: string, b: string): JsonDiffEntry[] {
  const left = JSON.parse(a) as unknown;
  const right = JSON.parse(b) as unknown;
  const out: JsonDiffEntry[] = [];
  walk('$', left, right, out);
  return out;
}

function walk(path: string, left: unknown, right: unknown, out: JsonDiffEntry[]): void {
  if (deepEqual(left, right)) return;
  const bothObjects = isObject(left) && isObject(right);
  const bothArrays = Array.isArray(left) && Array.isArray(right);

  if (bothObjects) {
    const keys = new Set([...Object.keys(left), ...Object.keys(right)]);
    for (const key of keys) {
      const lHas = key in (left as object);
      const rHas = key in (right as object);
      const childPath = `${path}.${key}`;
      if (lHas && !rHas)
        out.push({
          path: childPath,
          kind: 'removed',
          left: (left as Record<string, unknown>)[key],
        });
      else if (!lHas && rHas)
        out.push({
          path: childPath,
          kind: 'added',
          right: (right as Record<string, unknown>)[key],
        });
      else
        walk(
          childPath,
          (left as Record<string, unknown>)[key],
          (right as Record<string, unknown>)[key],
          out,
        );
    }
    return;
  }

  if (bothArrays) {
    const max = Math.max(left.length, right.length);
    for (let i = 0; i < max; i++) {
      const childPath = `${path}[${i}]`;
      if (i >= left.length) out.push({ path: childPath, kind: 'added', right: right[i] });
      else if (i >= right.length) out.push({ path: childPath, kind: 'removed', left: left[i] });
      else walk(childPath, left[i], right[i], out);
    }
    return;
  }

  out.push({ path, kind: 'changed', left, right });
}

export interface ByteDiff {
  equal: boolean;
  /** Byte offset of the first difference, or -1 if equal up to min length. */
  firstDiffOffset: number;
  leftLength: number;
  rightLength: number;
  /** Count of differing bytes within the overlapping region. */
  differingBytes: number;
}

export function diffBytes(a: Uint8Array, b: Uint8Array): ByteDiff {
  const min = Math.min(a.length, b.length);
  let firstDiff = -1;
  let differing = 0;
  for (let i = 0; i < min; i++) {
    if (a[i] !== b[i]) {
      if (firstDiff === -1) firstDiff = i;
      differing++;
    }
  }
  if (firstDiff === -1 && a.length !== b.length) firstDiff = min;
  return {
    equal: a.length === b.length && firstDiff === -1,
    firstDiffOffset: firstDiff,
    leftLength: a.length,
    rightLength: b.length,
    differingBytes: differing + Math.abs(a.length - b.length),
  };
}

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function deepEqual(a: unknown, b: unknown): boolean {
  if (a === b) return true;
  if (typeof a !== typeof b) return false;
  if (Array.isArray(a) && Array.isArray(b)) {
    if (a.length !== b.length) return false;
    return a.every((x, i) => deepEqual(x, b[i]));
  }
  if (isObject(a) && isObject(b)) {
    const ak = Object.keys(a);
    const bk = Object.keys(b);
    if (ak.length !== bk.length) return false;
    return ak.every((k) => deepEqual(a[k], b[k]));
  }
  return false;
}
