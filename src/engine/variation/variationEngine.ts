/**
 * Controlled request-variation engine (Phase 4).
 *
 * Safety controls (all enforced here, not merely in the UI):
 *  - Refuses to create a job whose base destination is not in scope.
 *  - Reports the EXACT request count before running; refuses to exceed the
 *    configured per-job maximum.
 *  - Default-low concurrency and requests-per-second (token bucket + semaphore).
 *  - Pause / resume / stop, plus a global emergency stop for all jobs.
 *  - Every generated request is recorded (source="variation", automated=true,
 *    jobId) and the job lifecycle is written to the audit log.
 *
 * There are deliberately no built-in credential, injection, destructive, or DoS
 * payload workflows (see payloads.ts).
 */

import { EventEmitter } from 'node:events';
import * as crypto from 'node:crypto';
import type { HttpExchange, Scheme } from '../../shared/model.js';
import type { ScopeConfig } from '../../shared/scope.js';
import type { AuditEntry } from '../../shared/project.js';
import type {
  JobProgress,
  JobStatus,
  VariationPlan,
  VariationResultRow,
} from '../../shared/variation.js';
import { evaluateScope } from '../scope/scope.js';
import { BlobStore } from '../storage/blobStore.js';
import { bytesToBody } from '../storage/bodyCollector.js';
import { parseRawRequest } from '../repeater/rawHttp.js';
import { originForm } from '../proxy/proxyUtil.js';
import { sendRaw } from '../net/httpClient.js';
import { TokenBucket, Semaphore, AbortError } from '../util/rateLimit.js';
import { Logger, rootLogger } from '../logging/logger.js';
import { ABSOLUTE_MAX, iterate, planCount, renderRequest } from './payloads.js';

export interface VariationDeps {
  blobStore: BlobStore;
  getScope: () => ScopeConfig;
  onExchange: (ex: HttpExchange) => void;
  audit: { append: (entry: AuditEntry) => void };
  logger?: Logger;
}

class VariationJob {
  status: JobStatus = 'created';
  completed = 0;
  skipped = 0;
  errors = 0;
  startedAt?: number;
  finishedAt?: number;
  readonly results: VariationResultRow[] = [];
  readonly abort = new AbortController();
  private pauseGate?: { promise: Promise<void>; resolve: () => void };

  constructor(
    readonly id: string,
    readonly plan: VariationPlan,
    readonly total: number,
  ) {}

  progress(): JobProgress {
    return {
      id: this.id,
      name: this.plan.name,
      status: this.status,
      total: this.total,
      completed: this.completed,
      skipped: this.skipped,
      errors: this.errors,
      ...(this.startedAt !== undefined ? { startedAt: this.startedAt } : {}),
      ...(this.finishedAt !== undefined ? { finishedAt: this.finishedAt } : {}),
    };
  }

  pause(): void {
    if (this.status !== 'running') return;
    this.status = 'paused';
    let resolve!: () => void;
    const promise = new Promise<void>((r) => (resolve = r));
    this.pauseGate = { promise, resolve };
  }

  resume(): void {
    if (this.status !== 'paused') return;
    this.status = 'running';
    this.pauseGate?.resolve();
    this.pauseGate = undefined;
  }

  stop(): void {
    if (this.status === 'completed' || this.status === 'stopped') return;
    this.status = 'stopped';
    this.pauseGate?.resolve();
    this.pauseGate = undefined;
    this.abort.abort();
  }

  async waitIfPaused(): Promise<void> {
    if (this.pauseGate) await this.pauseGate.promise;
  }
}

export class VariationEngine extends EventEmitter {
  private readonly jobs = new Map<string, VariationJob>();
  private readonly log: Logger;

  constructor(private readonly deps: VariationDeps) {
    super();
    this.log = (deps.logger ?? rootLogger).child('variation');
  }

  /**
   * Validate and create a job. Throws with a clear message when the base
   * destination is out of scope, the plan is empty, or the request count
   * exceeds the configured maximum.
   */
  createJob(plan: VariationPlan): { id: string; count: number } {
    const path = safePath(plan.base.raw);
    const decision = evaluateScope(this.deps.getScope(), {
      scheme: plan.base.scheme,
      host: plan.base.host,
      port: plan.base.port,
      path,
    });
    if (!decision.inScope) {
      throw new Error(
        `Refusing to create job: destination ${plan.base.host}:${plan.base.port} is not in scope (${decision.reason}). Add it to project scope first.`,
      );
    }
    const count = planCount(plan);
    if (count <= 0) {
      throw new Error('Refusing to create job: the plan generates 0 requests.');
    }
    if (count > ABSOLUTE_MAX) {
      throw new Error(
        `Refusing to create job: plan generates ${count} requests, exceeding the absolute safety ceiling of ${ABSOLUTE_MAX} (regardless of the configured per-job maximum).`,
      );
    }
    if (count > plan.limits.maxRequestsPerJob) {
      throw new Error(
        `Refusing to create job: plan generates ${count} requests, exceeding the maximum of ${plan.limits.maxRequestsPerJob}. Narrow the payloads or raise the limit deliberately.`,
      );
    }
    const id = crypto.randomUUID();
    this.jobs.set(id, new VariationJob(id, plan, count));
    this.deps.audit.append({
      ts: Date.now(),
      actor: 'variation-engine',
      action: 'job.create',
      target: `${plan.base.scheme}://${plan.base.host}:${plan.base.port}${path}`,
      detail: { name: plan.name, mode: plan.mode, count, limits: plan.limits },
      jobId: id,
    });
    return { id, count };
  }

  getProgress(id: string): JobProgress | undefined {
    return this.jobs.get(id)?.progress();
  }
  listProgress(): JobProgress[] {
    return [...this.jobs.values()].map((j) => j.progress());
  }
  getResults(id: string): VariationResultRow[] {
    return this.jobs.get(id)?.results ?? [];
  }

  pause(id: string): void {
    const job = this.jobs.get(id);
    if (!job) return;
    const wasRunning = job.status === 'running';
    job.pause();
    if (wasRunning && job.status === 'paused') {
      this.deps.audit.append({ ts: Date.now(), actor: 'user', action: 'job.pause', jobId: id });
    }
    this.emitProgress(id);
  }
  resume(id: string): void {
    const job = this.jobs.get(id);
    if (!job) return;
    const wasPaused = job.status === 'paused';
    job.resume();
    if (wasPaused && job.status === 'running') {
      this.deps.audit.append({ ts: Date.now(), actor: 'user', action: 'job.resume', jobId: id });
    }
    this.emitProgress(id);
  }
  stop(id: string): void {
    const job = this.jobs.get(id);
    if (!job) return;
    job.stop();
    this.deps.audit.append({ ts: Date.now(), actor: 'user', action: 'job.stop', jobId: id });
    this.emitProgress(id);
  }

  /** Global emergency stop: halt every job immediately. */
  emergencyStopAll(): void {
    this.deps.audit.append({
      ts: Date.now(),
      actor: 'user',
      action: 'emergency-stop',
      detail: { jobs: this.jobs.size },
    });
    for (const job of this.jobs.values()) job.stop();
    for (const id of this.jobs.keys()) this.emitProgress(id);
    this.emit('emergency-stop');
  }

  /** Run a created job to completion (respecting pause/stop). */
  async run(id: string): Promise<JobProgress> {
    const job = this.jobs.get(id);
    if (!job) throw new Error(`unknown job: ${id}`);
    if (job.status !== 'created') throw new Error(`job ${id} already ${job.status}`);

    const { plan } = job;
    const { scheme, host, port } = plan.base;
    job.status = 'running';
    job.startedAt = Date.now();
    this.deps.audit.append({
      ts: job.startedAt,
      actor: 'variation-engine',
      action: 'job.start',
      target: `${scheme}://${host}:${port}`,
      detail: { total: job.total },
      jobId: id,
    });
    this.emitProgress(id);

    const bucket = new TokenBucket(plan.limits.requestsPerSecond);
    const sem = new Semaphore(plan.limits.maxConcurrency);
    const signal = job.abort.signal;
    const inFlight: Promise<void>[] = [];

    try {
      for (const it of iterate(plan)) {
        if (signal.aborted) break;
        await job.waitIfPaused();
        if (signal.aborted) break;
        try {
          await bucket.take(signal);
        } catch {
          break; // aborted while waiting on the rate limiter
        }
        const release = await sem.acquire();
        const task = this.runOne(job, it.index, it.assignment, scheme, host, port, signal)
          .catch((err) => this.log.warn('variation task error', { err: String(err) }))
          .finally(() => {
            release();
            this.emitProgress(id);
          });
        inFlight.push(task);
      }
      await Promise.allSettled(inFlight);
    } finally {
      job.finishedAt = Date.now();
      const wasStopped = job.abort.signal.aborted;
      job.status = wasStopped ? 'stopped' : 'completed';
      this.deps.audit.append({
        ts: job.finishedAt,
        actor: 'variation-engine',
        action: wasStopped ? 'job.stopped' : 'job.complete',
        detail: { completed: job.completed, skipped: job.skipped, errors: job.errors },
        jobId: id,
      });
      this.emitProgress(id);
      this.emit('done', job.progress());
    }
    return job.progress();
  }

  private async runOne(
    job: VariationJob,
    index: number,
    assignment: string[],
    scheme: Scheme,
    host: string,
    port: number,
    signal: AbortSignal,
  ): Promise<void> {
    const rendered = renderRequest(job.plan.base.raw, job.plan.positions, assignment);
    let parsed;
    try {
      parsed = parseRawRequest(rendered);
    } catch (err) {
      job.errors += 1;
      job.results.push({
        index,
        payloads: assignment,
        requestId: '',
        status: 0,
        responseLength: 0,
        durationMs: 0,
        ttfbMs: 0,
        inScope: false,
        error: `malformed rendered request: ${String(err)}`,
      });
      return;
    }

    const path = originForm(parsed.target);
    const decision = evaluateScope(this.deps.getScope(), { scheme, host, port, path });
    if (!decision.inScope) {
      // A payload changed the path into an out-of-scope area — skip and audit.
      job.skipped += 1;
      job.results.push({
        index,
        payloads: assignment,
        requestId: '',
        status: 0,
        responseLength: 0,
        durationMs: 0,
        ttfbMs: 0,
        inScope: false,
        skipped: true,
      });
      this.deps.audit.append({
        ts: Date.now(),
        actor: 'variation-engine',
        action: 'request.skipped-out-of-scope',
        target: `${scheme}://${host}:${port}${path}`,
        jobId: job.id,
      });
      return;
    }

    try {
      const res = await sendRaw(
        scheme,
        host,
        port,
        parsed.method,
        path,
        parsed.headers,
        Buffer.from(parsed.body, 'utf8'),
        job.plan.limits.timeoutMs,
        signal,
      );
      const exId = crypto.randomUUID();
      const startedAt = Date.now() - res.durationMs;
      const exchange: HttpExchange = {
        id: exId,
        createdAt: startedAt,
        source: 'variation',
        scheme,
        host,
        port,
        inScope: true,
        automated: true,
        jobId: job.id,
        request: {
          method: parsed.method,
          target: path,
          url: `${scheme}://${host}:${port}${path}`,
          httpVersion: parsed.httpVersion,
          headers: parsed.headers,
          body: await bytesToBody(
            Buffer.from(parsed.body, 'utf8'),
            bodyLimits(),
            this.deps.blobStore,
          ),
        },
        response: {
          statusCode: res.statusCode,
          statusMessage: res.statusMessage,
          httpVersion: res.httpVersion,
          headers: res.headers,
          body: await bytesToBody(res.body, bodyLimits(), this.deps.blobStore),
        },
        tags: ['variation'],
        timing: { startedAt, ttfbMs: res.ttfbMs, durationMs: res.durationMs },
      };
      this.deps.onExchange(exchange);

      const markerHits = extractMarkers(job.plan.responseMarkers, res.body);
      job.completed += 1;
      job.results.push({
        index,
        payloads: assignment,
        requestId: exId,
        status: res.statusCode,
        responseLength: res.body.length,
        durationMs: res.durationMs,
        ttfbMs: res.ttfbMs,
        inScope: true,
        ...(markerHits.length ? { markerHits } : {}),
      });
    } catch (err) {
      if (err instanceof AbortError || signal.aborted) return; // stopped
      job.errors += 1;
      job.results.push({
        index,
        payloads: assignment,
        requestId: '',
        status: 0,
        responseLength: 0,
        durationMs: 0,
        ttfbMs: 0,
        inScope: true,
        error: String(err),
      });
    }
  }

  private emitProgress(id: string): void {
    const p = this.jobs.get(id)?.progress();
    if (p) this.emit('progress', p);
  }
}

// Variation bodies are typically small; use a fixed modest inline threshold.
function bodyLimits(): { spillToDiskAfterBytes: number; maxCapturedBytes: number } {
  return { spillToDiskAfterBytes: 256 * 1024, maxCapturedBytes: 10 * 1024 * 1024 };
}

function extractMarkers(markers: string[] | undefined, body: Buffer): string[] {
  if (!markers || markers.length === 0) return [];
  const text = body.toString('utf8');
  const hits: string[] = [];
  for (const m of markers) {
    try {
      const match = new RegExp(m).exec(text);
      if (match) hits.push(match[0].slice(0, 120));
    } catch {
      /* invalid regex ignored */
    }
  }
  return hits;
}

function safePath(raw: string): string {
  try {
    return originForm(parseRawRequest(raw).target);
  } catch {
    return '/';
  }
}
