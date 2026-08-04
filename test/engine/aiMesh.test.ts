/**
 * AI mesh orchestrator — safety-bound tests with a fake provider (no network,
 * no API key). These prove the bounds that make "autonomous within scope" safe:
 * egress must be acknowledged, empty scope fails closed, the per-run active
 * request cap is enforced regardless of the model, emergency stop aborts a run,
 * and the closed loop runs planner → attacker/analyst → reporter.
 */

import { describe, it, expect } from 'vitest';
import { MeshOrchestrator } from '../../src/engine/ai/orchestrator.js';
import { buildTools, meshRepeaterScopeDecision, type ToolSpec } from '../../src/engine/ai/tools.js';
import type { TacnocSession } from '../../src/engine/session.js';
import { Redactor, redactAiValue } from '../../src/engine/redaction/redactor.js';
import * as zlib from 'node:zlib';
import type {
  AgentTurnOptions,
  AgentTurnResult,
  LlmProvider,
} from '../../src/engine/ai/provider.js';
import { delay } from '../../src/engine/util/rateLimit.js';
import type { AiConfig, MeshRunStatus, MeshStep } from '../../src/shared/ai.js';
import type { ScopeConfig } from '../../src/shared/scope.js';
import type { AuditEntry } from '../../src/shared/project.js';

const IN_SCOPE: ScopeConfig = {
  include: [
    { id: 'r', enabled: true, hostMatch: 'subdomain', host: 'x.test', schemes: [], ports: [] },
  ],
  exclude: [],
};

// Host x.test is in scope, but the /admin path is excluded.
const PATH_SCOPE: ScopeConfig = {
  include: [
    { id: 'i', enabled: true, hostMatch: 'subdomain', host: 'x.test', schemes: [], ports: [] },
  ],
  exclude: [
    {
      id: 'e',
      enabled: true,
      hostMatch: 'subdomain',
      host: 'x.test',
      schemes: [],
      ports: [],
      path: { kind: 'prefix', value: '/admin' },
    },
  ],
};

function baseConfig(overrides: Partial<AiConfig> = {}): AiConfig {
  return {
    enabled: true,
    egressAcknowledged: true,
    redactBeforeSend: false,
    autonomy: 'auto',
    roles: {
      recon: { provider: 'anthropic', model: 'recon-model' },
      planner: { provider: 'anthropic', model: 'planner-model' },
      attacker: { provider: 'anthropic', model: 'attacker-model' },
      analyst: { provider: 'anthropic', model: 'analyst-model' },
      reporter: { provider: 'anthropic', model: 'reporter-model' },
    },
    runTokenBudget: 0,
    maxActiveRequestsPerRun: 3,
    workspaceAccess: false,
    allowCertOps: false,
    ...overrides,
  };
}

function makeTools(onProbe: () => void, cost?: number): ToolSpec[] {
  return [
    {
      name: 'get_target_map',
      description: 'read',
      inputSchema: { type: 'object' },
      effect: 'read',
      mutates: false,
      handler: async () => ({ sites: [] }),
    },
    {
      name: 'send_probe',
      description: 'active',
      inputSchema: { type: 'object' },
      effect: 'target-traffic',
      mutates: true,
      ...(cost !== undefined ? { requestCost: () => cost } : {}),
      handler: async () => {
        onProbe();
        return { ok: true };
      },
    },
  ];
}

/** Fake provider: the attacker hammers the (only) mutating tool `attempts` times. */
class FakeProvider implements LlmProvider {
  readonly id = 'fake';
  readonly roleLog: string[] = [];
  lastMaxIterations: number | undefined = undefined;
  constructor(private readonly attempts = 1) {}

  async runAgent(o: AgentTurnOptions): Promise<AgentTurnResult> {
    const role = /Your role: (\w+)/.exec(o.system)?.[1]?.toLowerCase() ?? 'unknown';
    this.roleLog.push(role);
    this.lastMaxIterations = o.maxIterations;
    const mutating = o.tools.find((t) => t.mutates);
    if (mutating) {
      for (let i = 0; i < this.attempts; i += 1) {
        if (o.signal?.aborted) break;
        const call = { id: `c${i}`, name: mutating.name, input: {} };
        o.onToolCall?.(call);
        const result = await mutating.handler(call.input);
        o.onToolResult?.(call, result);
      }
    }
    // Analyst ends the loop after one round.
    const text = role === 'analyst' ? 'triaged\nDONE' : `${role} finished`;
    return { text, tokens: { input: 10, output: 5 }, stopReason: 'end_turn' };
  }
}

async function waitForTerminal(
  orch: MeshOrchestrator,
  runId: string,
  timeoutMs = 4000,
): Promise<MeshRunStatus> {
  const started = Date.now();
  const terminal: MeshRunStatus[] = ['done', 'error', 'stopped'];
  while (Date.now() - started < timeoutMs) {
    const status = orch.get(runId)?.progress.status;
    if (status && terminal.includes(status)) return status;
    await new Promise((r) => setTimeout(r, 5));
  }
  throw new Error(`run did not finish; last status = ${orch.get(runId)?.progress.status}`);
}

describe('MeshOrchestrator safety bounds', () => {
  it('refuses to start when egress is not acknowledged', () => {
    const orch = new MeshOrchestrator({
      getScope: () => IN_SCOPE,
      audit: () => {},
      onStep: () => {},
      onProgress: () => {},
    });
    expect(() =>
      orch.start(
        { objective: 'probe' },
        {
          provider: new FakeProvider(),
          config: baseConfig({ egressAcknowledged: false }),
          tools: makeTools(() => {}),
        },
      ),
    ).toThrow(/egress/i);
  });

  it('fails closed when scope is empty', () => {
    const orch = new MeshOrchestrator({
      getScope: () => ({ include: [], exclude: [] }),
      audit: () => {},
      onStep: () => {},
      onProgress: () => {},
    });
    expect(() =>
      orch.start(
        { objective: 'probe' },
        { provider: new FakeProvider(), config: baseConfig(), tools: makeTools(() => {}) },
      ),
    ).toThrow(/scope is empty/i);
  });

  it('enforces the per-run active-request cap regardless of the model', async () => {
    let probes = 0;
    const audit: AuditEntry[] = [];
    const orch = new MeshOrchestrator({
      getScope: () => IN_SCOPE,
      audit: (e) => audit.push(e),
      onStep: () => {},
      onProgress: () => {},
    });
    // Attacker attempts 100 probes; cap is 3.
    const progress = orch.start(
      { objective: 'probe' },
      {
        provider: new FakeProvider(100),
        config: baseConfig({ maxActiveRequestsPerRun: 3 }),
        tools: makeTools(() => (probes += 1)),
      },
    );
    const status = await waitForTerminal(orch, progress.runId);

    expect(status).toBe('done');
    expect(probes).toBe(3); // the underlying tool ran at most `cap` times
    expect(orch.get(progress.runId)?.progress.activeRequests).toBe(3);
    // Exactly `cap` active requests were audited.
    expect(audit.filter((e) => e.action === 'mesh.request')).toHaveLength(3);
    expect(audit.some((e) => e.action === 'mesh.start')).toBe(true);
    expect(audit.some((e) => e.action === 'mesh.done')).toBe(true);
  });

  it('runs the closed loop recon → planner → attacker → analyst → reporter', async () => {
    const provider = new FakeProvider(1);
    const orch = new MeshOrchestrator({
      getScope: () => IN_SCOPE,
      audit: () => {},
      onStep: () => {},
      onProgress: () => {},
    });
    const progress = orch.start(
      { objective: 'probe' },
      { provider, config: baseConfig(), tools: makeTools(() => {}) },
    );
    await waitForTerminal(orch, progress.runId);

    // Recon runs before the planner, always: the engagement is reviewed before
    // anything is planned against it.
    expect(provider.roleLog[0]).toBe('recon');
    expect(provider.roleLog[1]).toBe('planner');
    expect(provider.roleLog).toContain('attacker');
    expect(provider.roleLog).toContain('analyst');
    expect(provider.roleLog[provider.roleLog.length - 1]).toBe('reporter');
    // Analyst said DONE after round 1, so only one attacker turn ran.
    expect(provider.roleLog.filter((r) => r === 'attacker')).toHaveLength(1);
  });

  it('readonly autonomy gives the attacker no active tools', async () => {
    let probes = 0;
    const orch = new MeshOrchestrator({
      getScope: () => IN_SCOPE,
      audit: () => {},
      onStep: () => {},
      onProgress: () => {},
    });
    const progress = orch.start(
      { objective: 'probe' },
      {
        provider: new FakeProvider(50),
        config: baseConfig({ autonomy: 'readonly' }),
        tools: makeTools(() => (probes += 1)),
      },
    );
    await waitForTerminal(orch, progress.runId);
    expect(probes).toBe(0); // no mutating tool was ever exposed
  });

  it('emergency stop aborts an in-flight run', async () => {
    const slow: LlmProvider = {
      id: 'slow',
      runAgent: async (o) => {
        await delay(5000, o.signal); // rejects on abort
        return { text: '', tokens: { input: 0, output: 0 }, stopReason: 'end_turn' };
      },
    };
    const orch = new MeshOrchestrator({
      getScope: () => IN_SCOPE,
      audit: () => {},
      onStep: () => {},
      onProgress: () => {},
    });
    const progress = orch.start(
      { objective: 'probe' },
      { provider: slow, config: baseConfig(), tools: makeTools(() => {}) },
    );
    orch.stopAll();
    const status = await waitForTerminal(orch, progress.runId);
    expect(status).toBe('stopped');
  });

  it('charges the active-request budget by request count, not tool-call count', async () => {
    let probes = 0;
    const orch = new MeshOrchestrator({
      getScope: () => IN_SCOPE,
      audit: () => {},
      onStep: () => {},
      onProgress: () => {},
    });
    // Each probe costs 40 requests; cap is 50 → only the first fits.
    const progress = orch.start(
      { objective: 'probe' },
      {
        provider: new FakeProvider(3),
        config: baseConfig({ maxActiveRequestsPerRun: 50 }),
        tools: makeTools(() => (probes += 1), 40),
      },
    );
    await waitForTerminal(orch, progress.runId);
    expect(probes).toBe(1);
    expect(orch.get(progress.runId)?.progress.activeRequests).toBe(40);
  });

  it('passes a hard per-role tool-loop cap to the provider', async () => {
    const provider = new FakeProvider(0);
    const orch = new MeshOrchestrator({
      getScope: () => IN_SCOPE,
      audit: () => {},
      onStep: () => {},
      onProgress: () => {},
    });
    const progress = orch.start(
      { objective: 'probe' },
      { provider, config: baseConfig(), tools: makeTools(() => {}) },
    );
    await waitForTerminal(orch, progress.runId);
    expect(provider.lastMaxIterations).toBeGreaterThan(0);
    expect(Number.isFinite(provider.lastMaxIterations)).toBe(true);
  });

  it('prunes old terminal runs so run history cannot grow unbounded', async () => {
    const orch = new MeshOrchestrator({
      getScope: () => IN_SCOPE,
      audit: () => {},
      onStep: () => {},
      onProgress: () => {},
    });
    const ids: string[] = [];
    for (let i = 0; i < 25; i += 1) {
      const progress = orch.start(
        { objective: `probe-${i}` },
        { provider: new FakeProvider(0), config: baseConfig(), tools: makeTools(() => {}) },
      );
      ids.push(progress.runId);
      await waitForTerminal(orch, progress.runId);
    }
    expect(orch.get(ids[0] as string)).toBeUndefined();
    expect(orch.get(ids[24] as string)).toBeDefined();
  });
});

describe('send_repeater scope gate', () => {
  it('meshRepeaterScopeDecision refuses out-of-scope hosts', () => {
    const session = { getScope: () => IN_SCOPE };
    expect(
      meshRepeaterScopeDecision(session, {
        scheme: 'https',
        host: 'sub.x.test',
        port: 443,
        raw: 'GET / HTTP/1.1\r\n\r\n',
      }).inScope,
    ).toBe(true);
    expect(
      meshRepeaterScopeDecision(session, {
        scheme: 'https',
        host: 'attacker.evil',
        port: 443,
        raw: 'GET / HTTP/1.1\r\n\r\n',
      }).inScope,
    ).toBe(false);
  });

  it('gates the path the repeater actually sends (absolute-form request line)', () => {
    const session = { getScope: () => PATH_SCOPE };
    // Absolute-form line to an excluded path must be refused — the gate must see
    // the same '/admin' the Repeater would send, not '/'.
    expect(
      meshRepeaterScopeDecision(session, {
        scheme: 'http',
        host: 'in.x.test',
        port: 80,
        raw: 'GET http://in.x.test/admin HTTP/1.1\r\nHost: in.x.test\r\n\r\n',
      }).inScope,
    ).toBe(false);
    // An in-scope path is still allowed.
    expect(
      meshRepeaterScopeDecision(session, {
        scheme: 'http',
        host: 'in.x.test',
        port: 80,
        raw: 'GET http://in.x.test/public HTTP/1.1\r\nHost: in.x.test\r\n\r\n',
      }).inScope,
    ).toBe(true);
  });

  it('the send_repeater tool refuses out-of-scope and never follows redirects', async () => {
    const calls: { options: { followRedirects: boolean; maxRedirects: number } }[] = [];
    const fakeSession = {
      getScope: () => IN_SCOPE,
      sendRepeater: async (
        _target: unknown,
        options: { followRedirects: boolean; maxRedirects: number },
      ) => {
        calls.push({ options });
        return { exchange: { id: 'ex1' }, redirects: [], totalMs: 1 };
      },
      getExchangeDetail: async (id: string) => ({ id, request: { headers: [], bodyBase64: '' } }),
    } as unknown as TacnocSession;
    const repeater = buildTools(fakeSession, { workspaceAccess: false, allowCertOps: false }).find(
      (t) => t.name === 'send_repeater',
    );
    if (!repeater) throw new Error('send_repeater tool missing');

    const refused = await repeater.handler({
      target: { scheme: 'https', host: 'attacker.evil', port: 443, raw: 'GET / HTTP/1.1\r\n\r\n' },
    });
    expect(refused).toHaveProperty('error');
    expect(calls).toHaveLength(0); // never reached the network

    await repeater.handler({
      target: { scheme: 'https', host: 'in.x.test', port: 443, raw: 'GET / HTTP/1.1\r\n\r\n' },
    });
    expect(calls).toHaveLength(1);
    expect(calls[0]?.options.followRedirects).toBe(false); // redirects forced off
    expect(calls[0]?.options.maxRedirects).toBe(0);
  });

  it('sends the destination it scope-checked, not the raw model input', async () => {
    // The gate normalizes scheme/port before evaluating scope; the Repeater then
    // reads target.scheme/target.port verbatim and sendRaw picks TLS on an exact
    // 'https' match. If the raw model object were forwarded, the gate would
    // approve destination A while the engine contacted destination B:
    //   scheme 'HTTPS' -> checked as https, sent as CLEARTEXT
    //   port omitted   -> checked as 443,   sent to Node's default 80
    // Tool input is NOT schema-validated at runtime (the Anthropic SDK's tool
    // parser is the identity function), so non-canonical values do reach here.
    const sent: { scheme: unknown; host: unknown; port: unknown }[] = [];
    const httpsOnly: ScopeConfig = {
      include: [
        {
          id: 'r',
          enabled: true,
          hostMatch: 'subdomain',
          host: 'x.test',
          schemes: ['https'],
          ports: [443],
        },
      ],
      exclude: [],
    };
    const fakeSession = {
      getScope: () => httpsOnly,
      sendRepeater: async (target: { scheme: unknown; host: unknown; port: unknown }) => {
        sent.push({ scheme: target.scheme, host: target.host, port: target.port });
        return { exchange: { id: 'ex1' }, redirects: [], totalMs: 1 };
      },
      getExchangeDetail: async (id: string) => ({ id, request: { headers: [], bodyBase64: '' } }),
    } as unknown as TacnocSession;
    const repeater = buildTools(fakeSession, { workspaceAccess: false, allowCertOps: false }).find(
      (t) => t.name === 'send_repeater',
    );
    if (!repeater) throw new Error('send_repeater tool missing');

    await repeater.handler({
      target: { scheme: 'HTTPS', host: 'in.x.test', port: 443, raw: 'GET / HTTP/1.1\r\n\r\n' },
    });
    expect(sent[0]?.scheme).toBe('https'); // canonical, so TLS is actually selected

    await repeater.handler({
      target: { scheme: 'https', host: 'in.x.test', raw: 'GET / HTTP/1.1\r\n\r\n' },
    });
    expect(sent[1]?.port).toBe(443); // the port the gate authorized, not Node's default 80
  });
});

describe('AI egress redaction', () => {
  it('masks structured headers and secrets in decoded base64 bodies', () => {
    const redactor = new Redactor({
      maskCookies: true,
      maskAuthorization: true,
      maskSecretPatterns: true,
    });
    const body = Buffer.from('user=admin&password=hunter2', 'utf8').toString('base64');
    const out = redactAiValue(
      {
        request: {
          headers: [
            { name: 'Cookie', value: 'JSESSIONID=topsecret' },
            { name: 'Authorization', value: 'Bearer abcdef.ghijkl.mnopqrst' },
          ],
          bodyBase64: body,
        },
      },
      redactor,
    ) as { request: { headers: { value: string }[]; bodyBase64: string } };

    expect(out.request.headers[0]?.value).not.toContain('topsecret'); // cookie value masked
    expect(out.request.headers[1]?.value).toContain('[REDACTED]'); // authorization masked
    const decoded = Buffer.from(out.request.bodyBase64, 'base64').toString('utf8');
    expect(decoded).not.toContain('hunter2'); // secret in body masked, not left as base64
    expect(decoded).toContain('[REDACTED]');
  });

  it('decompresses gzip bodies before masking and clears the encoding', () => {
    const redactor = new Redactor({
      maskCookies: true,
      maskAuthorization: true,
      maskSecretPatterns: true,
    });
    const gz = zlib
      .gzipSync(Buffer.from('api_key=SECRETKEY123456&ok=1', 'utf8'))
      .toString('base64');
    const out = redactAiValue(
      { response: { bodyBase64: gz, contentEncoding: 'gzip' } },
      redactor,
    ) as { response: { bodyBase64: string; contentEncoding?: string } };

    expect(out.response.contentEncoding).toBeUndefined(); // decompressed → now plaintext
    const decoded = Buffer.from(out.response.bodyBase64, 'base64').toString('utf8');
    expect(decoded).toContain('[REDACTED]'); // secret in the gzip body masked
    expect(decoded).not.toContain('SECRETKEY123456');
  });

  it('masks sensitive query params in url fields', () => {
    const redactor = new Redactor({
      maskCookies: true,
      maskAuthorization: true,
      maskSecretPatterns: true,
    });
    const out = redactAiValue(
      { url: 'https://in.x.test/cb?code=SUPERSECRETCODE&ok=1' },
      redactor,
    ) as { url: string };
    expect(out.url).not.toContain('SUPERSECRETCODE');
    expect(out.url).toContain('ok=1');
  });
});

describe('a declined turn does not throw the run away', () => {
  /** Declines the named roles the way the provider reports a refusal. */
  class DecliningProvider implements LlmProvider {
    readonly id = 'declining';
    readonly roleLog: string[] = [];
    readonly seenPrompts: string[] = [];
    constructor(private readonly refuse: Set<string>) {}
    async runAgent(o: AgentTurnOptions): Promise<AgentTurnResult> {
      const role = /Your role: (\w+)/.exec(o.system)?.[1]?.toLowerCase() ?? 'unknown';
      this.roleLog.push(role);
      const last = o.messages[o.messages.length - 1];
      this.seenPrompts.push(typeof last?.content === 'string' ? last.content : '');
      if (this.refuse.has(role)) {
        return { text: '', tokens: { input: 1, output: 0 }, stopReason: 'refusal' };
      }
      const text = role === 'analyst' ? 'triaged\nDONE' : `${role} finished`;
      return { text, tokens: { input: 10, output: 5 }, stopReason: 'end_turn' };
    }
  }

  const orchWith = (
    refuse: string[],
    briefing?: () => Promise<string>,
  ): { orch: MeshOrchestrator; provider: DecliningProvider; steps: MeshStep[] } => {
    const provider = new DecliningProvider(new Set(refuse));
    const steps: MeshStep[] = [];
    const orch = new MeshOrchestrator({
      getScope: () => IN_SCOPE,
      audit: () => {},
      onStep: (s) => steps.push(s),
      onProgress: () => {},
      ...(briefing ? { briefing } : {}),
    });
    return { orch, provider, steps };
  };

  it('carries on past a declined recon turn using the engine briefing', async () => {
    const { orch, provider, steps } = orchWith(
      ['recon'],
      async () => 'ENGINE BRIEFING: host x.test',
    );
    const progress = orch.start(
      { objective: 'probe' },
      { provider, config: baseConfig(), tools: makeTools(() => {}) },
    );
    const status = await waitForTerminal(orch, progress.runId);

    // The run completes rather than erroring out on the first turn.
    expect(status).toBe('done');
    expect(provider.roleLog).toEqual(['recon', 'planner', 'attacker', 'analyst', 'reporter']);
    // The planner was handed the engine's briefing in place of recon's summary.
    expect(provider.seenPrompts[1]).toContain('ENGINE BRIEFING: host x.test');
    // And the decline is stated, not buried.
    expect(steps.some((s) => s.summary.includes('declined the recon turn'))).toBe(true);
  });

  it('reports the decline to the reporter so coverage is not overstated', async () => {
    const { orch, provider } = orchWith(['recon'], async () => 'ENGINE BRIEFING');
    const progress = orch.start(
      { objective: 'probe' },
      { provider, config: baseConfig(), tools: makeTools(() => {}) },
    );
    await waitForTerminal(orch, progress.runId);
    const reporterPrompt = provider.seenPrompts[provider.seenPrompts.length - 1] ?? '';
    expect(reporterPrompt).toMatch(/declined by the model/i);
    expect(reporterPrompt).toContain('recon');
  });

  it('carries on past a declined planner turn too', async () => {
    const { orch, provider, steps } = orchWith(['planner'], async () => 'ENGINE BRIEFING');
    const progress = orch.start(
      { objective: 'probe' },
      { provider, config: baseConfig(), tools: makeTools(() => {}) },
    );
    expect(await waitForTerminal(orch, progress.runId)).toBe('done');
    expect(provider.roleLog).toContain('attacker');
    expect(steps.some((s) => s.summary.includes('declined the planning turn'))).toBe(true);
  });

  it('still runs when no briefing source is wired, falling back to the scope', async () => {
    const { orch, provider } = orchWith(['recon']);
    const progress = orch.start(
      { objective: 'probe' },
      { provider, config: baseConfig(), tools: makeTools(() => {}) },
    );
    expect(await waitForTerminal(orch, progress.runId)).toBe('done');
    expect(provider.seenPrompts[1]).toContain('x.test');
  });

  it('does not let a failing briefing become the thing that kills the run', async () => {
    const { orch, provider } = orchWith(['recon'], async () => {
      throw new Error('project closed');
    });
    const progress = orch.start(
      { objective: 'probe' },
      { provider, config: baseConfig(), tools: makeTools(() => {}) },
    );
    expect(await waitForTerminal(orch, progress.runId)).toBe('done');
    expect(provider.seenPrompts[1]).toContain('x.test');
  });
});
