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
  ResponseExtractor,
  VariationPlan,
  VariationResultRow,
} from '../../shared/variation.js';
import type { EngagementProfile } from '../../shared/engagement.js';
import { applyIdentity } from '../engagement/identity.js';
import { evaluateScope } from '../scope/scope.js';
import { BlobStore } from '../storage/blobStore.js';
import { bytesToBody } from '../storage/bodyCollector.js';
import { parseRawRequest } from '../repeater/rawHttp.js';
import { originForm } from '../proxy/proxyUtil.js';
import { sendRaw } from '../net/httpClient.js';
import { TokenBucket, Semaphore, AbortError } from '../util/rateLimit.js';
import { Logger, rootLogger } from '../logging/logger.js';
import { ABSOLUTE_MAX, SAFE_STRUCTURAL, iterate, planCount, renderRequest } from './payloads.js';

const MAX_BASE_REQUEST_BYTES = 2 * 1024 * 1024;
const MAX_PAYLOAD_BYTES = 64 * 1024;
const MAX_POSITIONS = 16;
const MAX_RESPONSE_RULES = 20;
const MAX_REGEX_LENGTH = 512;
const MAX_ANALYSIS_BYTES = 256 * 1024;

interface CompiledExtractor {
  name: string;
  regex: RegExp;
  group: number;
}

export interface VariationDeps {
  blobStore: BlobStore;
  getScope: () => ScopeConfig;
  onExchange: (ex: HttpExchange) => void;
  audit: { append: (entry: AuditEntry) => void };
  logger?: Logger;
  /** Engagement profile; when it mandates identification, every generated
   *  request carries the required User-Agent and identity headers. */
  getEngagement?: () => EngagementProfile | undefined;
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
    readonly markerPatterns: RegExp[],
    readonly extractorPatterns: CompiledExtractor[],
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
    const jobPlan = structuredClone(plan) as VariationPlan;
    validateDestination(jobPlan);
    const path = safePath(jobPlan.base.raw);
    const decision = evaluateScope(this.deps.getScope(), {
      scheme: jobPlan.base.scheme,
      host: jobPlan.base.host,
      port: jobPlan.base.port,
      path,
    });
    if (!decision.inScope) {
      throw new Error(
        `Refusing to create job: destination ${jobPlan.base.host}:${jobPlan.base.port} is not in scope (${decision.reason}). Add it to project scope first.`,
      );
    }
    validatePlan(jobPlan);
    const count = planCount(jobPlan);
    if (count <= 0) {
      throw new Error('Refusing to create job: the plan generates 0 requests.');
    }
    if (count > ABSOLUTE_MAX) {
      throw new Error(
        `Refusing to create job: plan generates ${count} requests, exceeding the absolute safety ceiling of ${ABSOLUTE_MAX} (regardless of the configured per-job maximum).`,
      );
    }
    if (count > jobPlan.limits.maxRequestsPerJob) {
      throw new Error(
        `Refusing to create job: plan generates ${count} requests, exceeding the maximum of ${jobPlan.limits.maxRequestsPerJob}. Narrow the payloads or raise the limit deliberately.`,
      );
    }
    const id = crypto.randomUUID();
    const markerPatterns = (jobPlan.responseMarkers ?? []).map((pattern) => new RegExp(pattern));
    const extractorPatterns = (jobPlan.responseExtractors ?? []).map((extractor) => ({
      name: extractor.name,
      regex: new RegExp(extractor.pattern),
      group: extractor.group ?? 1,
    }));
    this.jobs.set(id, new VariationJob(id, jobPlan, count, markerPatterns, extractorPatterns));
    this.deps.audit.append({
      ts: Date.now(),
      actor: 'variation-engine',
      action: 'job.create',
      target: `${plan.base.scheme}://${plan.base.host}:${plan.base.port}${path}`,
      detail: { name: jobPlan.name, mode: jobPlan.mode, count, limits: jobPlan.limits },
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
    let parsed;
    try {
      // Render inside the try so an expansion that exceeds the request cap (or
      // any other render failure) is recorded as an error, not silently dropped.
      const rendered = renderRequest(
        job.plan.base.raw,
        job.plan.positions,
        assignment,
        MAX_BASE_REQUEST_BYTES,
      );
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

    // Identity is applied per request (not once per job) so a profile edited
    // mid-run takes effect, and the exchange records the headers that were sent.
    const outgoing = applyIdentity(parsed.headers, this.deps.getEngagement?.());

    try {
      const res = await sendRaw(
        scheme,
        host,
        port,
        parsed.method,
        path,
        outgoing,
        Buffer.from(parsed.body, 'utf8'),
        job.plan.limits.timeoutMs,
        signal,
      );
      const exId = crypto.randomUUID();
      const startedAt = Date.now() - res.durationMs;
      const responseBody = await bytesToBody(res.body, bodyLimits(), this.deps.blobStore);
      if (res.bodyTruncated) responseBody.truncated = true;
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
          headers: outgoing,
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
          body: responseBody,
        },
        tags: ['variation'],
        timing: { startedAt, ttfbMs: res.ttfbMs, durationMs: res.durationMs },
      };
      this.deps.onExchange(exchange);

      const analysis = analyzeResponse(job, res.body);
      job.completed += 1;
      job.results.push({
        index,
        payloads: assignment,
        requestId: exId,
        status: res.statusCode,
        responseLength: res.body.length,
        responseWords: analysis.words,
        responseLines: analysis.lines,
        responseHash: crypto.createHash('sha256').update(res.body).digest('hex').slice(0, 16),
        ...(res.bodyTruncated ? { responseTruncated: true } : {}),
        durationMs: res.durationMs,
        ttfbMs: res.ttfbMs,
        inScope: true,
        ...(analysis.markerHits.length ? { markerHits: analysis.markerHits } : {}),
        ...(Object.keys(analysis.extracted).length ? { extracted: analysis.extracted } : {}),
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

function analyzeResponse(
  job: VariationJob,
  body: Buffer,
): { markerHits: string[]; extracted: Record<string, string>; words: number; lines: number } {
  const text = body.subarray(0, MAX_ANALYSIS_BYTES).toString('utf8');
  const hits: string[] = [];
  for (const regex of job.markerPatterns) {
    const match = regex.exec(text);
    if (match) hits.push(match[0].slice(0, 120));
  }
  const extracted: Record<string, string> = {};
  for (const extractor of job.extractorPatterns) {
    const match = extractor.regex.exec(text);
    if (match) extracted[extractor.name] = (match[extractor.group] ?? match[0]).slice(0, 240);
  }
  const trimmed = text.trim();
  return {
    markerHits: hits,
    extracted,
    words: trimmed ? trimmed.split(/\s+/).length : 0,
    lines: text.length ? text.split(/\r?\n/).length : 0,
  };
}

function safePath(raw: string): string {
  try {
    return originForm(parseRawRequest(raw).target);
  } catch {
    return '/';
  }
}

function validatePlan(plan: VariationPlan): void {
  validateDestination(plan);
  if (!Array.isArray(plan.positions)) throw new Error('Invalid variation plan.');
  if (typeof plan.name !== 'string' || plan.name.length > 200) {
    throw new Error('Variation job names must be at most 200 characters.');
  }
  if (!['sniper', 'batteringram', 'pitchfork', 'clusterbomb'].includes(plan.mode)) {
    throw new Error('Variation mode is invalid.');
  }
  if (plan.positions.length === 0 || plan.positions.length > MAX_POSITIONS) {
    throw new Error(`Variation plans require 1–${MAX_POSITIONS} payload positions.`);
  }
  const markers = new Set<string>();
  for (const [index, position] of plan.positions.entries()) {
    if (!position || typeof position !== 'object' || !position.source) {
      throw new Error(`Position ${index + 1} is invalid.`);
    }
    if (
      typeof position.marker !== 'string' ||
      position.marker.length === 0 ||
      position.marker.length > 128 ||
      !plan.base.raw.includes(position.marker)
    ) {
      throw new Error(
        `Position ${index + 1} must use a non-empty marker present in the base request.`,
      );
    }
    if (markers.has(position.marker))
      throw new Error(`Duplicate position marker: ${position.marker}`);
    if (
      [...markers].some(
        (marker) => marker.includes(position.marker) || position.marker.includes(marker),
      )
    ) {
      throw new Error('Variation position markers must not overlap one another.');
    }
    markers.add(position.marker);
    if (position.source.kind === 'list') {
      if (!Array.isArray(position.source.values) || position.source.values.length > ABSOLUTE_MAX) {
        throw new Error(`Position ${index + 1} payload list is invalid or too large.`);
      }
      for (const value of position.source.values) {
        if (typeof value !== 'string' || Buffer.byteLength(value) > MAX_PAYLOAD_BYTES) {
          throw new Error(
            `Position ${index + 1} contains a payload over ${MAX_PAYLOAD_BYTES / 1024} KiB.`,
          );
        }
      }
    } else if (position.source.kind === 'range') {
      if (
        !Number.isFinite(position.source.from) ||
        !Number.isFinite(position.source.to) ||
        !Number.isFinite(position.source.step) ||
        position.source.step === 0
      ) {
        throw new Error(`Position ${index + 1} number range is invalid.`);
      }
    } else if (position.source.kind === 'builtin') {
      if (position.source.set !== 'safe-structural') {
        throw new Error(`Position ${index + 1} has an unsupported built-in payload set.`);
      }
    } else {
      throw new Error(`Position ${index + 1} has an unsupported payload source.`);
    }
  }
  validateWorstCaseRequestSize(plan);
  validateLimits(plan);
  if (plan.responseMarkers !== undefined && !Array.isArray(plan.responseMarkers)) {
    throw new Error('Response markers must be an array.');
  }
  if (plan.responseExtractors !== undefined && !Array.isArray(plan.responseExtractors)) {
    throw new Error('Response extractors must be an array.');
  }
  validateResponseRules(plan.responseMarkers ?? [], plan.responseExtractors ?? []);
}

function validateDestination(plan: VariationPlan): void {
  if (!plan || typeof plan !== 'object' || !plan.base) throw new Error('Invalid variation plan.');
  if (plan.base.scheme !== 'http' && plan.base.scheme !== 'https') {
    throw new Error('Variation scheme must be http or https.');
  }
  if (
    !plan.base.host ||
    !Number.isInteger(plan.base.port) ||
    plan.base.port < 1 ||
    plan.base.port > 65535
  ) {
    throw new Error('Variation destination host/port is invalid.');
  }
  if (
    typeof plan.base.raw !== 'string' ||
    Buffer.byteLength(plan.base.raw) > MAX_BASE_REQUEST_BYTES
  ) {
    throw new Error(`Base request must be at most ${MAX_BASE_REQUEST_BYTES / 1024 / 1024} MiB.`);
  }
}

function validateLimits(plan: VariationPlan): void {
  const limits = plan.limits;
  if (
    !limits ||
    !Number.isInteger(limits.maxConcurrency) ||
    limits.maxConcurrency < 1 ||
    limits.maxConcurrency > 64
  ) {
    throw new Error('Variation concurrency must be an integer from 1 to 64.');
  }
  if (
    !Number.isFinite(limits.requestsPerSecond) ||
    limits.requestsPerSecond <= 0 ||
    limits.requestsPerSecond > 1000
  ) {
    throw new Error('Variation rate must be greater than 0 and no more than 1000 requests/second.');
  }
  if (!Number.isFinite(limits.timeoutMs) || limits.timeoutMs < 100 || limits.timeoutMs > 120_000) {
    throw new Error('Variation timeout must be from 100 to 120000 milliseconds.');
  }
  if (!Number.isSafeInteger(limits.maxRequestsPerJob) || limits.maxRequestsPerJob < 1) {
    throw new Error('Variation max requests must be a positive safe integer.');
  }
}

function validateWorstCaseRequestSize(plan: VariationPlan): void {
  let worstCaseBytes = Buffer.byteLength(plan.base.raw);
  for (const position of plan.positions) {
    const occurrences = countOccurrences(plan.base.raw, position.marker);
    const markerBytes = Buffer.byteLength(position.marker);
    let maxValueBytes = 0;
    switch (position.source.kind) {
      case 'list':
        maxValueBytes = position.source.values.reduce(
          (max, value) => Math.max(max, Buffer.byteLength(value)),
          0,
        );
        break;
      case 'range':
        maxValueBytes = Math.max(
          Buffer.byteLength(String(position.source.from)),
          Buffer.byteLength(String(position.source.to)),
          32,
        );
        break;
      case 'builtin':
        maxValueBytes = SAFE_STRUCTURAL.reduce(
          (max, value) => Math.max(max, Buffer.byteLength(value)),
          0,
        );
        break;
    }
    worstCaseBytes += occurrences * Math.max(0, maxValueBytes - markerBytes);
    if (worstCaseBytes > MAX_BASE_REQUEST_BYTES) {
      throw new Error(
        `Worst-case rendered request exceeds the ${MAX_BASE_REQUEST_BYTES / 1024 / 1024} MiB limit.`,
      );
    }
  }
}

function countOccurrences(value: string, marker: string): number {
  let count = 0;
  let offset = 0;
  while ((offset = value.indexOf(marker, offset)) !== -1) {
    count += 1;
    offset += marker.length;
  }
  return count;
}

function validateResponseRules(
  markers: readonly string[],
  extractors: readonly ResponseExtractor[],
): void {
  if (markers.length > MAX_RESPONSE_RULES || extractors.length > MAX_RESPONSE_RULES) {
    throw new Error(`Use at most ${MAX_RESPONSE_RULES} response markers and extractors per job.`);
  }
  for (const pattern of markers) validatePattern(pattern);
  const names = new Set<string>();
  for (const extractor of extractors) {
    if (!extractor || typeof extractor !== 'object') {
      throw new Error('Response extractors must be objects.');
    }
    if (!extractor.name || extractor.name.length > 64)
      throw new Error('Response extractor names must be 1–64 characters.');
    if (names.has(extractor.name))
      throw new Error(`Duplicate response extractor name: ${extractor.name}`);
    names.add(extractor.name);
    if (
      extractor.group !== undefined &&
      (!Number.isInteger(extractor.group) || extractor.group < 0 || extractor.group > 20)
    ) {
      throw new Error(
        `Extractor "${extractor.name}" capture group must be an integer from 0 to 20.`,
      );
    }
    validatePattern(extractor.pattern);
  }
}

function validatePattern(pattern: string): void {
  if (typeof pattern !== 'string' || pattern.length === 0 || pattern.length > MAX_REGEX_LENGTH) {
    throw new Error(`Response regexes must be 1–${MAX_REGEX_LENGTH} characters.`);
  }
  // Reject nested-quantifier shapes that cause catastrophic backtracking — e.g.
  // (a+)+, (a*)*, ((a)*)*, ([a-z]+)+ — including through nested groups, which the
  // previous flat regex-on-a-regex check missed. Response analysis runs on the
  // engine's event loop, so a catastrophic pattern would otherwise freeze the
  // job and defeat pause/stop. This structural scan is a safety net, not a proof
  // of linear-time matching: operator patterns can still be pathological in ways
  // it does not model (e.g. overlapping alternations like (a|a)+), so keep
  // response regexes simple.
  if (hasNestedQuantifier(pattern)) {
    throw new Error(`Potentially unsafe nested-quantifier response regex: ${pattern}`);
  }
  try {
    void new RegExp(pattern);
  } catch (error) {
    throw new Error(`Invalid response regex "${pattern}": ${String(error)}`);
  }
}

/**
 * Detects an unbounded quantifier applied to a group that itself contains an
 * unbounded quantifier — the classic catastrophic-backtracking shape ((a+)+,
 * (a*)*, ((a)*)*, ([a-z]+)+, …), including through nested groups. Pure linear
 * scan, no regex execution, so it is safe to run on an untrusted-length pattern.
 */
function hasNestedQuantifier(pattern: string): boolean {
  const groupHasQuantifier: boolean[] = [];
  for (let i = 0; i < pattern.length; i++) {
    const ch = pattern[i];
    if (ch === '\\') {
      i++; // skip the escaped character
      continue;
    }
    if (ch === '[') {
      i = skipCharClass(pattern, i);
      continue;
    }
    if (ch === '(') {
      groupHasQuantifier.push(false);
      continue;
    }
    if (ch === ')') {
      const inner = groupHasQuantifier.pop() ?? false;
      const quant = quantifierAt(pattern, i + 1);
      // The group contributes an unbounded quantifier to any enclosing group if
      // it *contains* one (inner) or is itself unbounded-quantified. Propagating
      // `inner` even when this group has NO trailing quantifier is what closes
      // the ((a*))* bypass: an extra wrapping group must not hide the inner
      // quantifier from an outer one.
      let contributesUnbounded = inner;
      if (quant) {
        i = quant.end;
        if (inner && quant.unbounded) return true;
        if (quant.unbounded) contributesUnbounded = true;
      }
      if (contributesUnbounded && groupHasQuantifier.length) {
        groupHasQuantifier[groupHasQuantifier.length - 1] = true;
      }
      continue;
    }
    const quant = quantifierAt(pattern, i);
    if (quant) {
      i = quant.end;
      if (quant.unbounded && groupHasQuantifier.length) {
        groupHasQuantifier[groupHasQuantifier.length - 1] = true;
      }
    }
  }
  return false;
}

/** Classify the quantifier token at `i` (`*`, `+`, `?`, `{n,m}`), or null. */
function quantifierAt(pattern: string, i: number): { unbounded: boolean; end: number } | null {
  const ch = pattern[i];
  if (ch === '*' || ch === '+') return { unbounded: true, end: i };
  if (ch === '?') return { unbounded: false, end: i };
  if (ch === '{') {
    const m = /^\{\d*(?:,\d*)?\}/.exec(pattern.slice(i));
    if (!m) return null; // a literal '{', not a repetition quantifier
    return { unbounded: /^\{\d*,\}$/.test(m[0]), end: i + m[0].length - 1 };
  }
  return null;
}

/** Return the index of a character class's closing ']' (or the string end). */
function skipCharClass(pattern: string, start: number): number {
  let i = start + 1;
  if (pattern[i] === '^') i++;
  if (pattern[i] === ']') i++; // a leading ']' is a literal member
  while (i < pattern.length && pattern[i] !== ']') {
    if (pattern[i] === '\\') i++;
    i++;
  }
  return i;
}
