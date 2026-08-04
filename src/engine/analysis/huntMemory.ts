/**
 * Hunt memory — what previous hunts learned, merged and reusable.
 *
 * A hunt that starts from zero every time re-tests what it already refuted last
 * month and forgets what paid off. The expensive part is not the request budget,
 * it is the operator's attention: re-deriving "this endpoint's id is checked
 * properly, stop looking" for the fourth time is pure waste, and forgetting that
 * a class DID pay off on this stack is a missed finding.
 *
 * So outcomes are recorded across engagements, keyed by a **path shape** rather
 * than a literal URL: `/api/orders/10432` and `/api/orders/99887` both reduce to
 * `/api/orders/{id}`, so a lesson learned on one object transfers to the next,
 * and a lesson learned on one target transfers to a target with the same shape.
 * Recall merges the matching records into a short verdict per shape and class.
 *
 * The design follows GreyIQ's outcome learning, and so do its limits:
 *
 *  - **Append-only, local, bounded.** No network. Old records age out; the file
 *    cannot grow without bound.
 *  - **Redacted on write.** Free text passes through the secret redactor before
 *    it is stored, because a note about an auth bug is exactly where a token
 *    ends up pasted.
 *  - **Memory is advisory, never authority.** It reorders attention and nothing
 *    else. It cannot mark a finding confirmed — only `proof.ts` does that, from
 *    a real differential — and it cannot put a host in scope. A wrong record
 *    costs a little misplaced attention, never a false finding or an
 *    out-of-scope request.
 *  - **Best-effort.** Any I/O failure degrades to "no history", which is just
 *    the behaviour without the feature.
 */

import { promises as fs } from 'node:fs';
import * as path from 'node:path';
import { randomUUID } from 'node:crypto';
import { Redactor } from '../redaction/redactor.js';
import type { ProofOutcome } from './proof.js';

const FILE = 'hunt-outcomes.jsonl';
const MAX_RECORDS = 5000;
const MAX_LINE_BYTES = 8 * 1024;
const MAX_FILE_BYTES = 8 * 1024 * 1024;
const MAX_NOTE_CHARS = 600;
const OUTCOMES = new Set<string>(['confirmed', 'refuted', 'inconclusive']);

export interface HuntOutcomeRecord {
  id: string;
  ts: number;
  /** Program or engagement label, so recall can be scoped to one if wanted. */
  program: string;
  host: string;
  /** Generalized path, e.g. `/api/orders/{id}`. The key that makes this reusable. */
  pathShape: string;
  /** Defect class tested, e.g. "access-control". Free text, lowercased. */
  klass: string;
  /** What was tested, in one line. */
  claim: string;
  outcome: ProofOutcome;
  /** Exchange ids backing a confirmed/refuted result, when there was a proof. */
  controlExchangeId?: string;
  testExchangeId?: string;
  /** Short note — why it went this way. Redacted before storage. */
  note?: string;
}

export type HuntOutcomeInput = Omit<HuntOutcomeRecord, 'id' | 'ts'> & {
  id?: string;
  ts?: number;
};

/** One merged verdict for a (pathShape, class) pair across every prior hunt. */
export interface HuntRecall {
  pathShape: string;
  klass: string;
  confirmed: number;
  refuted: number;
  inconclusive: number;
  lastSeen: number;
  hosts: string[];
  /** The most recent note for this pair, if any. */
  latestNote?: string;
  /** What this history suggests doing now. Advisory. */
  suggestion: string;
}

export interface HuntRecallResult {
  /** Merged verdicts, most decisive and most recent first. */
  entries: HuntRecall[];
  recordsConsidered: number;
  notes: string[];
}

/**
 * Reduce a concrete path to a reusable shape: numeric, UUID, hex-blob, and long
 * opaque segments all become `{id}`. This is what lets a lesson about one order
 * apply to every order, and to the next target with the same route shape.
 */
export function pathShape(rawPath: string): string {
  const [withoutQuery] = String(rawPath ?? '/').split('?');
  const segments = (withoutQuery ?? '/').split('/');
  const shaped = segments.map((segment) => {
    if (!segment) return segment;
    if (/^\d+$/.test(segment)) return '{id}';
    if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(segment)) {
      return '{id}';
    }
    if (/^[0-9a-fA-F]{16,}$/.test(segment)) return '{id}';
    // A long mixed-case token with no vowels reads as an opaque id, not a word.
    if (segment.length >= 20 && /^[A-Za-z0-9_-]+$/.test(segment) && !/[aeiou]/i.test(segment)) {
      return '{id}';
    }
    return segment.toLowerCase();
  });
  const joined = shaped.join('/');
  return joined.startsWith('/') ? joined : `/${joined}`;
}

export interface HuntMemoryOptions {
  /** Directory holding the store. Created on first write. */
  directory: string;
  maxRecords?: number;
}

export class HuntMemory {
  private readonly file: string;
  private readonly maxRecords: number;
  /** Notes and claims are redacted on the way in — this is a durable store. */
  private readonly redactor = new Redactor({
    maskCookies: true,
    maskAuthorization: true,
    maskSecretPatterns: true,
  });

  constructor(private readonly options: HuntMemoryOptions) {
    this.file = path.join(options.directory, FILE);
    this.maxRecords = Math.max(100, Math.min(options.maxRecords ?? MAX_RECORDS, 100_000));
  }

  /**
   * Redact FIRST, then truncate. The other order cuts a secret in half and
   * leaves the half that no longer matches its pattern — a JWT sliced before
   * its third segment, a PEM block without its END line — so the redactor sees
   * something it does not recognise and the fragment is stored verbatim.
   */
  private clean(text: string | undefined, max = MAX_NOTE_CHARS): string {
    if (!text) return '';
    const flattened = String(text)
      .slice(0, max * 8)
      .replace(/[\r\n]+/g, ' ');
    return this.redactor.redactText(flattened).slice(0, max).trim();
  }

  /** Append one outcome. Best-effort: a write failure never fails the hunt. */
  async record(input: HuntOutcomeInput): Promise<HuntOutcomeRecord | undefined> {
    const record: HuntOutcomeRecord = {
      id: input.id ?? randomUUID(),
      ts: input.ts ?? Date.now(),
      program: this.clean(input.program, 120),
      host: this.clean(input.host, 253),
      // The path is redacted and capped like every other stored string: a reset
      // link or an API key embedded in a path segment is exactly the sort of
      // thing that ends up in a durable record otherwise.
      pathShape: pathShape(this.clean(input.pathShape, 300)),
      klass: this.clean(input.klass, 60).toLowerCase(),
      claim: this.clean(input.claim, 300),
      outcome: input.outcome,
      ...(input.controlExchangeId ? { controlExchangeId: input.controlExchangeId } : {}),
      ...(input.testExchangeId ? { testExchangeId: input.testExchangeId } : {}),
      ...(input.note ? { note: this.clean(input.note) } : {}),
    };
    const line = JSON.stringify(record);
    if (Buffer.byteLength(line) > MAX_LINE_BYTES) return undefined;
    try {
      await fs.mkdir(this.options.directory, { recursive: true });
      await fs.appendFile(this.file, `${line}\n`, 'utf8');
      await this.compactIfNeeded();
      return record;
    } catch {
      return undefined;
    }
  }

  /**
   * Delete the store outright. The docs tell operators working several programs
   * under NDA to clear it between engagements, which requires the operation to
   * exist rather than meaning "go find a JSONL under your app-data directory".
   */
  async clear(): Promise<void> {
    await fs.rm(this.file, { force: true });
  }

  /** Read every stored record, newest last. Malformed lines are skipped. */
  async all(): Promise<HuntOutcomeRecord[]> {
    let raw: string;
    try {
      const stat = await fs.stat(this.file);
      if (stat.size > MAX_FILE_BYTES) {
        // Read the tail only: the newest records are the ones worth having.
        const handle = await fs.open(this.file, 'r');
        try {
          const buffer = Buffer.alloc(MAX_FILE_BYTES);
          const { bytesRead } = await handle.read(
            buffer,
            0,
            MAX_FILE_BYTES,
            stat.size - MAX_FILE_BYTES,
          );
          raw = buffer.subarray(0, bytesRead).toString('utf8');
          raw = raw.slice(raw.indexOf('\n') + 1); // drop the partial first line
        } finally {
          await handle.close();
        }
      } else {
        raw = await fs.readFile(this.file, 'utf8');
      }
    } catch {
      return [];
    }
    const records: HuntOutcomeRecord[] = [];
    for (const line of raw.split('\n')) {
      if (!line.trim()) continue;
      try {
        const parsed = JSON.parse(line) as HuntOutcomeRecord;
        if (parsed && typeof parsed.pathShape === 'string' && typeof parsed.outcome === 'string') {
          records.push(parsed);
        }
      } catch {
        continue;
      }
    }
    return records;
  }

  /** Trim the store to the newest `maxRecords` entries once it grows past them. */
  private async compactIfNeeded(): Promise<void> {
    const records = await this.all();
    if (records.length <= this.maxRecords) return;
    const kept = records.slice(records.length - this.maxRecords);
    const body = kept.map((r) => JSON.stringify(r)).join('\n');
    await fs.writeFile(this.file, body ? `${body}\n` : '', 'utf8');
  }

  /**
   * Merge prior outcomes into a verdict per (pathShape, class).
   *
   * Filters are optional and additive: no filter recalls everything, which is
   * what the planner wants when it is deciding where to spend a run.
   */
  async recall(
    query: { host?: string; pathShape?: string; klass?: string; program?: string } = {},
  ): Promise<HuntRecallResult> {
    const records = await this.all();
    const wantShape = query.pathShape ? pathShape(query.pathShape) : undefined;
    const wantHost = query.host?.toLowerCase();
    const wantClass = query.klass?.toLowerCase();
    const wantProgram = query.program?.toLowerCase();

    const matched = records.filter((r) => {
      // Defensive: a record can be parsable JSON and still be missing fields
      // (hand-edited file, partial write). Reading them unguarded turned a
      // host-filtered recall — which is the query recon actually makes — into
      // a TypeError that escaped the best-effort contract entirely.
      if (wantHost && String(r.host ?? '').toLowerCase() !== wantHost) return false;
      if (wantShape && r.pathShape !== wantShape) return false;
      if (wantClass && String(r.klass ?? '').toLowerCase() !== wantClass) return false;
      if (wantProgram && String(r.program ?? '').toLowerCase() !== wantProgram) return false;
      return true;
    });

    const merged = new Map<string, HuntRecall & { hostSet: Set<string> }>();
    for (const record of matched) {
      if (!OUTCOMES.has(record.outcome)) continue;
      const klass = String(record.klass ?? '');
      const key = `${record.pathShape}::${klass}`;
      const entry = merged.get(key) ?? {
        pathShape: record.pathShape,
        klass,
        confirmed: 0,
        refuted: 0,
        inconclusive: 0,
        lastSeen: 0,
        hosts: [],
        hostSet: new Set<string>(),
        suggestion: '',
      };
      entry[record.outcome] += 1;
      if (record.ts >= entry.lastSeen) {
        entry.lastSeen = record.ts;
        if (record.note) entry.latestNote = record.note;
      }
      // Hostnames are only returned for the program being recalled. Another
      // client's asset inventory is not context for this engagement, and it
      // would be egressed to the model provider along with everything else.
      if (record.host && wantProgram) entry.hostSet.add(record.host);
      merged.set(key, entry);
    }

    const entries = [...merged.values()]
      .map(({ hostSet, ...entry }) => ({
        ...entry,
        hosts: [...hostSet].slice(0, 10),
        suggestion: suggestionFor(entry),
      }))
      .sort(
        (a, b) =>
          b.confirmed - a.confirmed ||
          b.lastSeen - a.lastSeen ||
          b.refuted + b.inconclusive - (a.refuted + a.inconclusive),
      );

    const notes = [
      'History is advisory. It reorders where to look; it can never confirm a finding or place a host in scope. Re-prove anything you intend to report against this target.',
    ];
    if (!entries.length) {
      notes.push('No prior hunt recorded anything matching this query — treat it as new ground.');
    }
    return { entries, recordsConsidered: matched.length, notes };
  }
}

function suggestionFor(entry: {
  confirmed: number;
  refuted: number;
  inconclusive: number;
}): string {
  if (entry.confirmed > 0 && entry.refuted === 0) {
    return 'This shape and class produced a real differential before. Test it early, and check whether the earlier issue regressed.';
  }
  if (entry.confirmed > 0) {
    return 'Mixed history — it has confirmed somewhere and been refuted elsewhere, so it depends on the implementation. Worth testing, but expect variance.';
  }
  if (entry.refuted >= 3) {
    return 'Refuted repeatedly on this shape. Deprioritise unless something about this target is materially different, and say what that is.';
  }
  if (entry.refuted > 0) {
    return 'Refuted before. Not worthless, but not where to start.';
  }
  return 'Only inconclusive attempts so far. If you test it, design a cleaner control than last time.';
}
