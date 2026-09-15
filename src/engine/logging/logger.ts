/**
 * Structured logging with built-in secret redaction.
 *
 * Every log record is a plain object serialized to JSON. String values in the
 * metadata are passed through a redactor so tokens/cookies/keys never land in
 * logs. Logs are LOCAL ONLY — there is no network sink, by design (no telemetry,
 * no analytics, no external services; see SECURITY.md).
 */

import { Redactor } from '../redaction/redactor.js';

export type LogLevel = 'debug' | 'info' | 'warn' | 'error';

const LEVEL_WEIGHT: Record<LogLevel, number> = { debug: 10, info: 20, warn: 30, error: 40 };

export interface LogRecord {
  ts: string;
  level: LogLevel;
  scope: string;
  msg: string;
  meta?: Record<string, unknown>;
}

export type LogSink = (record: LogRecord) => void;

export interface LoggerOptions {
  level?: LogLevel;
  redactor?: Redactor;
  sink?: LogSink;
  /** Injectable clock for tests. Defaults to Date.now via wall clock. */
  now?: () => number;
}

const defaultRedactor = new Redactor({
  maskCookies: true,
  maskAuthorization: true,
  maskSecretPatterns: true,
});

export class Logger {
  private level: LogLevel;
  private readonly redactor: Redactor;
  private readonly sink: LogSink;
  private readonly now: () => number;

  constructor(
    private readonly scope: string,
    options: LoggerOptions = {},
  ) {
    this.level = options.level ?? 'info';
    this.redactor = options.redactor ?? defaultRedactor;
    this.sink = options.sink ?? consoleSink;
    this.now = options.now ?? (() => Date.now());
  }

  child(subScope: string): Logger {
    return new Logger(`${this.scope}.${subScope}`, {
      level: this.level,
      redactor: this.redactor,
      sink: this.sink,
      now: this.now,
    });
  }

  setLevel(level: LogLevel): void {
    this.level = level;
  }

  debug(msg: string, meta?: Record<string, unknown>): void {
    this.emit('debug', msg, meta);
  }
  info(msg: string, meta?: Record<string, unknown>): void {
    this.emit('info', msg, meta);
  }
  warn(msg: string, meta?: Record<string, unknown>): void {
    this.emit('warn', msg, meta);
  }
  error(msg: string, meta?: Record<string, unknown>): void {
    this.emit('error', msg, meta);
  }

  private emit(level: LogLevel, msg: string, meta?: Record<string, unknown>): void {
    if (LEVEL_WEIGHT[level] < LEVEL_WEIGHT[this.level]) return;
    const record: LogRecord = {
      ts: new Date(this.now()).toISOString(),
      level,
      scope: this.scope,
      msg: this.redactor.redactText(msg),
      ...(meta ? { meta: this.redactMeta(meta) } : {}),
    };
    this.sink(record);
  }

  private redactMeta(meta: Record<string, unknown>): Record<string, unknown> {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(meta)) {
      out[k] = this.redactValue(v);
    }
    return out;
  }

  private redactValue(v: unknown): unknown {
    // `redactUrl`, not `redactText`. Metadata routinely carries URLs and
    // request targets — the proxy logs `url` on every upstream error — and
    // query parameters named `code`, `sig` or `session` are masked only by the
    // URL-aware path; `redactText` catches secret-SHAPED strings and would let
    // those through. It is a strict superset: with no `?` it is exactly
    // `redactText`, and with one it also redacts each half. This matters more
    // now that records reach `LogBuffer` and can be exported to a file the UI
    // describes as redacted.
    if (typeof v === 'string') return this.redactor.redactUrl(v);
    if (Array.isArray(v)) return v.map((x) => this.redactValue(x));
    if (v && typeof v === 'object') {
      const out: Record<string, unknown> = {};
      for (const [k, val] of Object.entries(v as Record<string, unknown>)) {
        out[k] = this.redactValue(val);
      }
      return out;
    }
    return v;
  }
}

/**
 * The default sink. Exported so a caller can tee it — `LogBuffer` keeps a tail
 * for diagnostics export and must not take the terminal output away from
 * anyone running the app from a shell.
 */
export function consoleSink(record: LogRecord): void {
  const line = JSON.stringify(record);
  if (record.level === 'error') console.error(line);
  else if (record.level === 'warn') console.warn(line);
  else console.log(line);
}

/** A sink that collects records in-memory; useful for tests and diagnostics. */
export function createMemorySink(): { sink: LogSink; records: LogRecord[] } {
  const records: LogRecord[] = [];
  return { sink: (r) => records.push(r), records };
}

export const rootLogger = new Logger('tacnoc');
