/**
 * Rate limiting primitives for automated work.
 *
 * TokenBucket enforces a maximum requests-per-second; Semaphore caps
 * concurrency. Both are used by the variation engine to keep automated traffic
 * gentle by default (a safety control, not a performance tuning knob).
 */

export class TokenBucket {
  private tokens: number;
  private lastRefill: number;

  constructor(
    private readonly ratePerSecond: number,
    private readonly burst: number = Math.max(1, Math.ceil(ratePerSecond)),
    private readonly now: () => number = () => Date.now(),
  ) {
    this.tokens = this.burst;
    this.lastRefill = now();
  }

  private refill(): void {
    const t = this.now();
    const elapsed = (t - this.lastRefill) / 1000;
    if (elapsed > 0) {
      this.tokens = Math.min(this.burst, this.tokens + elapsed * this.ratePerSecond);
      this.lastRefill = t;
    }
  }

  /** Resolve when a token is available, respecting an optional abort signal. */
  async take(signal?: AbortSignal): Promise<void> {
    // eslint-disable-next-line no-constant-condition
    while (true) {
      if (signal?.aborted) throw new AbortError();
      this.refill();
      if (this.tokens >= 1) {
        this.tokens -= 1;
        return;
      }
      const needed = 1 - this.tokens;
      const waitMs = Math.max(5, Math.ceil((needed / this.ratePerSecond) * 1000));
      await delay(waitMs, signal);
    }
  }
}

export class Semaphore {
  private available: number;
  private readonly queue: (() => void)[] = [];

  constructor(max: number) {
    this.available = Math.max(1, max);
  }

  async acquire(): Promise<() => void> {
    if (this.available > 0) {
      this.available -= 1;
      return () => this.release();
    }
    return new Promise<() => void>((resolve) => {
      this.queue.push(() => {
        this.available -= 1;
        resolve(() => this.release());
      });
    });
  }

  private release(): void {
    this.available += 1;
    const next = this.queue.shift();
    if (next) next();
  }
}

export class AbortError extends Error {
  constructor() {
    super('aborted');
    this.name = 'AbortError';
  }
}

export function delay(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) return reject(new AbortError());
    const timer = setTimeout(() => {
      cleanup();
      resolve();
    }, ms);
    const onAbort = (): void => {
      cleanup();
      reject(new AbortError());
    };
    const cleanup = (): void => {
      clearTimeout(timer);
      signal?.removeEventListener('abort', onAbort);
    };
    signal?.addEventListener('abort', onAbort, { once: true });
  });
}
