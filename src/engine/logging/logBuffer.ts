/**
 * A bounded in-memory tail of the structured log.
 *
 * Until this existed there was nothing to hand anyone: `Logger`'s only sink was
 * the console, so an operator reporting a problem could offer a screenshot of a
 * terminal they probably never saw — in a packaged Electron app, stdout goes
 * nowhere a user can reach.
 *
 * It is a ring buffer, not a file, and that is deliberate. A log file on disk is
 * a second copy of redacted-but-still-sensitive engagement data with its own
 * lifetime, its own permissions, and nothing that ever deletes it; it would
 * outlive the project it describes. A bounded buffer dies with the process,
 * which is the right default for a tool whose whole posture is local-first and
 * offline. Records are already redacted by `Logger` before they reach any sink
 * (`logger.ts` → `emit`), so this holds redacted records, not raw ones.
 */

import type { LogRecord, LogSink } from './logger.js';

/** Enough to cover a long session; ~2 MB at typical record sizes. */
export const DEFAULT_LOG_CAPACITY = 5000;

export class LogBuffer {
  private readonly records: LogRecord[] = [];
  private dropped = 0;

  constructor(private readonly capacity: number = DEFAULT_LOG_CAPACITY) {
    if (!Number.isInteger(capacity) || capacity < 1) {
      throw new Error(`log buffer capacity must be a positive integer, got ${capacity}`);
    }
  }

  /** Pass to `new Logger(scope, { sink })`. */
  readonly sink: LogSink = (record) => {
    this.records.push(record);
    if (this.records.length > this.capacity) {
      this.records.shift();
      this.dropped++;
    }
  };

  /** Oldest first. A copy — callers must not be able to mutate the tail. */
  all(): LogRecord[] {
    return [...this.records];
  }

  /**
   * How many records were discarded to stay inside the capacity. An export that
   * does not say this reads as a complete log when it is a tail.
   */
  droppedCount(): number {
    return this.dropped;
  }

  size(): number {
    return this.records.length;
  }

  clear(): void {
    this.records.length = 0;
    this.dropped = 0;
  }

  /** JSON Lines, one record per line — the format the console sink already emits. */
  toJsonl(): string {
    return (
      this.records.map((r) => JSON.stringify(r)).join('\n') + (this.records.length ? '\n' : '')
    );
  }
}

/**
 * Tees a sink: records go to the buffer and on to the original sink, so adding
 * an export path does not silently take the console output away from anyone
 * running the app from a terminal.
 */
export function teeSink(buffer: LogBuffer, next: LogSink): LogSink {
  return (record) => {
    buffer.sink(record);
    next(record);
  };
}
