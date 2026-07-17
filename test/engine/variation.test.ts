import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import * as os from 'node:os';
import * as path from 'node:path';
import { promises as fs } from 'node:fs';
import * as crypto from 'node:crypto';
import { VariationEngine } from '../../src/engine/variation/variationEngine.js';
import { planCount } from '../../src/engine/variation/payloads.js';
import { BlobStore } from '../../src/engine/storage/blobStore.js';
import { startTestServer, type TestServerHandle } from '../server/testServer.js';
import type { ScopeConfig } from '../../src/shared/scope.js';
import type { AuditEntry } from '../../src/shared/project.js';
import type { HttpExchange } from '../../src/shared/model.js';
import type { VariationPlan } from '../../src/shared/variation.js';
import type { AutomationLimits } from '../../src/shared/config.js';

let server: TestServerHandle;
let blobs: BlobStore;
let dir: string;
let scope: ScopeConfig;
let audit: AuditEntry[];
let captured: HttpExchange[];
let engine: VariationEngine;

const LIMITS: AutomationLimits = {
  maxConcurrency: 4,
  requestsPerSecond: 50,
  timeoutMs: 10000,
  maxRequestsPerJob: 5000,
};

function raw(pathTemplate: string): string {
  return `GET ${pathTemplate} HTTP/1.1\r\nHost: 127.0.0.1:${server.httpPort}\r\n\r\n`;
}

function makeEngine(): VariationEngine {
  return new VariationEngine({
    blobStore: blobs,
    getScope: () => scope,
    onExchange: (ex) => captured.push(ex),
    audit: { append: (e) => audit.push(e) },
  });
}

beforeAll(async () => {
  server = await startTestServer();
  dir = path.join(os.tmpdir(), `belcher-var-${crypto.randomBytes(6).toString('hex')}`);
  blobs = new BlobStore(path.join(dir, 'blobs'));
});

afterAll(async () => {
  await server.close();
  await fs.rm(dir, { recursive: true, force: true });
});

function reset(): void {
  scope = { include: [], exclude: [] };
  audit = [];
  captured = [];
  engine = makeEngine();
}

const inScopeHost = (): ScopeConfig => ({
  include: [
    { id: 'r', enabled: true, hostMatch: 'exact', host: '127.0.0.1', schemes: [], ports: [] },
  ],
  exclude: [],
});

describe('variation engine — safety gates', () => {
  it('refuses to create a job when the destination is out of scope', () => {
    reset();
    const plan: VariationPlan = {
      name: 'oos',
      base: { scheme: 'http', host: '127.0.0.1', port: server.httpPort, raw: raw('/json?x={{0}}') },
      positions: [{ marker: '{{0}}', source: { kind: 'list', values: ['a', 'b'] } }],
      mode: 'batteringram',
      limits: LIMITS,
    };
    expect(() => engine.createJob(plan)).toThrow(/not in scope/i);
  });

  it('refuses to exceed the configured maximum request count', () => {
    reset();
    scope = inScopeHost();
    const plan: VariationPlan = {
      name: 'toobig',
      base: { scheme: 'http', host: '127.0.0.1', port: server.httpPort, raw: raw('/json?x={{0}}') },
      positions: [{ marker: '{{0}}', source: { kind: 'range', from: 1, to: 100, step: 1 } }],
      mode: 'batteringram',
      limits: { ...LIMITS, maxRequestsPerJob: 10 },
    };
    expect(() => engine.createJob(plan)).toThrow(/exceeding the maximum/i);
  });

  it('refuses to exceed the absolute safety ceiling regardless of the per-job max', () => {
    reset();
    scope = inScopeHost();
    const big = Array.from({ length: 400 }, (_, i) => String(i)); // 400 × 400 = 160k > 100k
    const plan: VariationPlan = {
      name: 'ceiling',
      base: {
        scheme: 'http',
        host: '127.0.0.1',
        port: server.httpPort,
        raw: raw('/json?a={{0}}&b={{1}}'),
      },
      positions: [
        { marker: '{{0}}', source: { kind: 'list', values: big } },
        { marker: '{{1}}', source: { kind: 'list', values: big } },
      ],
      mode: 'clusterbomb',
      limits: { ...LIMITS, maxRequestsPerJob: 1_000_000 },
    };
    expect(() => engine.createJob(plan)).toThrow(/absolute safety ceiling/i);
  });

  it('computes exact counts per mode', () => {
    const base = {
      scheme: 'http' as const,
      host: '127.0.0.1',
      port: server.httpPort,
      raw: raw('/json?a={{0}}&b={{1}}'),
    };
    const positions = [
      { marker: '{{0}}', source: { kind: 'list' as const, values: ['1', '2', '3'] } },
      { marker: '{{1}}', source: { kind: 'list' as const, values: ['x', 'y'] } },
    ];
    expect(planCount({ name: '', base, positions, mode: 'clusterbomb', limits: LIMITS })).toBe(6);
    expect(planCount({ name: '', base, positions, mode: 'pitchfork', limits: LIMITS })).toBe(2);
    expect(planCount({ name: '', base, positions, mode: 'sniper', limits: LIMITS })).toBe(5);
    expect(planCount({ name: '', base, positions, mode: 'batteringram', limits: LIMITS })).toBe(3);
  });
});

describe('variation engine — execution', () => {
  it('runs an in-scope job and records automated exchanges + audit', async () => {
    reset();
    scope = inScopeHost();
    const plan: VariationPlan = {
      name: 'run',
      base: { scheme: 'http', host: '127.0.0.1', port: server.httpPort, raw: raw('/json?x={{0}}') },
      positions: [{ marker: '{{0}}', source: { kind: 'list', values: ['a', 'b', 'c'] } }],
      mode: 'batteringram',
      limits: LIMITS,
      responseMarkers: ['"ok":true'],
    };
    const { id, count } = engine.createJob(plan);
    expect(count).toBe(3);
    const progress = await engine.run(id);
    expect(progress.status).toBe('completed');
    expect(progress.completed).toBe(3);
    expect(captured).toHaveLength(3);
    expect(captured.every((e) => e.automated && e.source === 'variation' && e.jobId === id)).toBe(
      true,
    );
    // response markers extracted
    expect(engine.getResults(id).every((r) => r.markerHits?.includes('"ok":true'))).toBe(true);
    // audit lifecycle present
    const actions = audit.map((a) => a.action);
    expect(actions).toContain('job.create');
    expect(actions).toContain('job.start');
    expect(actions).toContain('job.complete');
  });

  it('skips rendered requests that fall out of scope', async () => {
    reset();
    scope = {
      include: [
        { id: 'i', enabled: true, hostMatch: 'exact', host: '127.0.0.1', schemes: [], ports: [] },
      ],
      exclude: [
        {
          id: 'e',
          enabled: true,
          hostMatch: 'exact',
          host: '127.0.0.1',
          schemes: [],
          ports: [],
          path: { kind: 'regex', value: '^/admin' },
        },
      ],
    };
    const plan: VariationPlan = {
      name: 'skip',
      base: { scheme: 'http', host: '127.0.0.1', port: server.httpPort, raw: raw('/{{0}}') },
      positions: [{ marker: '{{0}}', source: { kind: 'list', values: ['json', 'admin'] } }],
      mode: 'batteringram',
      limits: LIMITS,
    };
    const { id } = engine.createJob(plan);
    const progress = await engine.run(id);
    expect(progress.skipped).toBe(1);
    expect(progress.completed).toBe(1);
    expect(audit.some((a) => a.action === 'request.skipped-out-of-scope')).toBe(true);
  });

  it('enforces the request rate (token bucket)', async () => {
    reset();
    scope = inScopeHost();
    const plan: VariationPlan = {
      name: 'rate',
      base: { scheme: 'http', host: '127.0.0.1', port: server.httpPort, raw: raw('/json?x={{0}}') },
      positions: [{ marker: '{{0}}', source: { kind: 'range', from: 1, to: 8, step: 1 } }],
      mode: 'batteringram',
      limits: { ...LIMITS, requestsPerSecond: 4, maxConcurrency: 2 },
    };
    const { id, count } = engine.createJob(plan);
    expect(count).toBe(8);
    const t0 = Date.now();
    await engine.run(id);
    const elapsed = Date.now() - t0;
    // burst≈4, then 4 more at 4/s ⇒ ≥ ~0.75s. Allow generous lower bound.
    expect(elapsed).toBeGreaterThan(600);
    expect(engine.getProgress(id)?.completed).toBe(8);
  });

  it('records pause and resume in the audit log', async () => {
    reset();
    scope = inScopeHost();
    const plan: VariationPlan = {
      name: 'pauseresume',
      base: { scheme: 'http', host: '127.0.0.1', port: server.httpPort, raw: raw('/json?x={{0}}') },
      positions: [{ marker: '{{0}}', source: { kind: 'range', from: 1, to: 20, step: 1 } }],
      mode: 'batteringram',
      limits: { ...LIMITS, requestsPerSecond: 8, maxConcurrency: 1 },
    };
    const { id } = engine.createJob(plan);
    const running = engine.run(id);
    await new Promise((r) => setTimeout(r, 150));
    engine.pause(id);
    await new Promise((r) => setTimeout(r, 100));
    engine.resume(id);
    await running;
    const actions = audit.map((a) => a.action);
    expect(actions).toContain('job.pause');
    expect(actions).toContain('job.resume');
  });

  it('honors emergency stop mid-run', async () => {
    reset();
    scope = inScopeHost();
    const plan: VariationPlan = {
      name: 'estop',
      base: { scheme: 'http', host: '127.0.0.1', port: server.httpPort, raw: raw('/json?x={{0}}') },
      positions: [{ marker: '{{0}}', source: { kind: 'range', from: 1, to: 40, step: 1 } }],
      mode: 'batteringram',
      limits: { ...LIMITS, requestsPerSecond: 5, maxConcurrency: 1 },
    };
    const { id } = engine.createJob(plan);
    const running = engine.run(id);
    await new Promise((r) => setTimeout(r, 300));
    engine.emergencyStopAll();
    const progress = await running;
    expect(progress.status).toBe('stopped');
    expect(progress.completed).toBeLessThan(40);
    expect(audit.some((a) => a.action === 'emergency-stop')).toBe(true);
  });
});
