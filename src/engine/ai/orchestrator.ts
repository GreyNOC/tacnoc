/**
 * MeshOrchestrator — the closed-loop tester.
 *
 *   recon (read-only) → planner (read-only)
 *        →  [ attacker (active) → analyst (read-only) ]×N  →  reporter
 *
 * Recon runs before anything is planned, and it is not optional. It reads the
 * engagement folder, the program's rules, the scope, the certificate state, and
 * the traffic already captured, then reports readiness. If preflight finds a
 * blocker — no authorization on file, an empty scope, an expired CA — the run
 * stops there rather than producing a confident plan for an engagement that
 * cannot legitimately proceed.
 *
 * The loop is bounded independently of anything the model does:
 *  - the run's AbortController (emergency stop / explicit stop aborts every turn),
 *  - a hard per-role tool-loop cap (max_iterations) so one role cannot spin forever,
 *  - MAX_ROUNDS on the attack → analyse cycle,
 *  - a per-run active-request BUDGET charged by the real number of HTTP requests
 *    each action launches (a fuzz job counts as its full size), enforced at the
 *    tool wrapper so the model cannot fan out past it, and
 *  - an optional token budget that ends the loop early.
 *
 * Scope is the hard boundary: create/run_variation_job re-check scope in the
 * engine, send_repeater is scope-checked at the tool boundary (tools.ts) and
 * never follows cross-host redirects, plus a fail-closed guard here that refuses
 * to start when the project has no in-scope hosts. Egress requires explicit
 * acknowledgement; when redactBeforeSend is on, tool results are best-effort
 * redacted before they reach the provider.
 *
 * The orchestrator is deliberately decoupled from TacnocSession (it takes tools
 * + provider + callbacks) so there is no engine/ai import cycle.
 */

import { randomUUID } from 'node:crypto';
import type { AuditEntry } from '../../shared/project.js';
import type { ScopeConfig } from '../../shared/scope.js';
import type {
  AgentRole,
  AiAutonomy,
  AiConfig,
  MeshRun,
  MeshRunPlan,
  MeshRunProgress,
  MeshRunStatus,
  MeshStep,
} from '../../shared/ai.js';
import type { AgentMessage, LlmProvider } from './provider.js';
import type { ToolEffect, ToolSpec } from './tools.js';
import { systemPromptFor } from './prompts.js';
import type { Logger } from '../logging/logger.js';

const MAX_STEPS = 1000;
const MAX_ROUNDS = 3;
/**
 * Output ceiling per role turn. Higher reasoning effort means the model spends
 * more of the budget thinking, and `max_tokens` caps thinking plus response
 * together — an 8K ceiling at xhigh truncates the answer mid-sentence, which
 * reads as "the role had little to say" rather than as the truncation it is.
 */
const ROLE_MAX_TOKENS_DEFAULT = 16_000;
const ROLE_MAX_TOKENS_DEEP = 64_000;
const MIN_TASK_BUDGET = 20_000; // SDK minimum for output_config.task_budget
const MAX_ITERATIONS_PER_ROLE = 24; // hard cap on a single role's tool-call loop
const MAX_RETAINED_RUNS = 20; // cap on finished-run history kept in memory

/**
 * Which tool effects each role may call.
 *
 * The roles documented as read-only are read-only in code, not just in the
 * prompt. Only the attacker touches the target or the operator's interception
 * environment; the analyst may write local evidence records because triage is
 * exactly when a hypothesis is settled and should be recorded. A reporter that
 * could revoke the CA after the last evidence was gathered is not a reporter.
 */
const ROLE_EFFECTS: Record<AgentRole, readonly ToolEffect[]> = {
  recon: ['read'],
  planner: ['read'],
  attacker: ['read', 'local-write', 'environment', 'target-traffic'],
  analyst: ['read', 'local-write'],
  reporter: ['read'],
};

/**
 * Effects withheld in read-only autonomy. "No traffic" has to include the
 * environment change that silently stops traffic being captured at all.
 */
const READONLY_WITHHELD: readonly ToolEffect[] = ['target-traffic', 'environment'];

export interface MeshOrchestratorDeps {
  getScope: () => ScopeConfig;
  audit: (entry: AuditEntry) => void;
  onStep: (step: MeshStep) => void;
  onProgress: (progress: MeshRunProgress) => void;
  /** Structural redaction applied to tool results when config.redactBeforeSend is on. */
  redactResult?: (value: unknown) => unknown;
  logger?: Logger;
  /**
   * A briefing the ENGINE can produce with no model involved: preflight,
   * scope, the engagement folder, and the ranked attack surface.
   *
   * Used when the model declines a turn. A declined recon turn used to abort
   * the whole run, which meant one refusal threw away work the engine had
   * already done deterministically and could hand to the next role unchanged.
   */
  briefing?: () => Promise<string>;
}

export interface MeshRunContext {
  provider: LlmProvider;
  config: AiConfig;
  tools: ToolSpec[];
}

interface RunState {
  progress: MeshRunProgress;
  steps: MeshStep[];
  report?: string;
  controller: AbortController;
}

export class MeshOrchestrator {
  private readonly runs = new Map<string, RunState>();

  constructor(private readonly deps: MeshOrchestratorDeps) {}

  /** Start a run. Returns the initial progress synchronously; work streams via callbacks. */
  start(plan: MeshRunPlan, ctx: MeshRunContext): MeshRunProgress {
    const { config } = ctx;
    if (!config.enabled) throw new Error('AI mesh is disabled. Enable it in AI settings first.');
    if (!config.egressAcknowledged) {
      throw new Error(
        'AI egress is not acknowledged for this project. Running the mesh sends captured ' +
          'traffic (including any secrets, cookies, and PII) to the model provider. Acknowledge ' +
          'egress in AI settings to proceed.',
      );
    }
    if (!plan.objective || !plan.objective.trim()) {
      throw new Error('Provide a testing objective for the mesh run.');
    }
    // Count only ENABLED rules, the same way the evaluator does. Counting all
    // of them let a project whose include rules were switched off start a run
    // that then had every single request refused — provider tokens spent to
    // rediscover a fact the guard already had.
    if (this.deps.getScope().include.filter((r) => r.enabled !== false).length === 0) {
      throw new Error(
        'Scope is empty (fail-closed): add at least one ENABLED in-scope host before running the ' +
          'mesh — every request would otherwise be refused. If your program policy is in the ' +
          'engagement folder, Engagement → Proposed scope reads the hosts out of it.',
      );
    }

    const runId = randomUUID();
    const now = Date.now();
    const state: RunState = {
      progress: {
        runId,
        status: 'planning',
        stepCount: 0,
        activeRequests: 0,
        tokens: { input: 0, output: 0 },
        startedAt: now,
        updatedAt: now,
      },
      steps: [],
      controller: new AbortController(),
    };
    this.runs.set(runId, state);
    this.prune();
    this.deps.audit({
      ts: now,
      actor: 'ai-mesh',
      action: 'mesh.start',
      detail: { objective: plan.objective, autonomy: config.autonomy },
    });
    this.emitProgress(state);

    void this.execute(runId, plan, ctx).catch((err: unknown) => {
      if (state.controller.signal.aborted) this.finish(runId, 'stopped');
      else this.fail(runId, err);
    });
    return { ...state.progress, tokens: { ...state.progress.tokens } };
  }

  stop(runId: string): void {
    const state = this.runs.get(runId);
    if (!state) return;
    state.controller.abort();
    if (state.progress.status !== 'done' && state.progress.status !== 'error') {
      this.finish(runId, 'stopped');
    }
  }

  stopAll(): void {
    for (const id of this.runs.keys()) this.stop(id);
  }

  get(runId: string): MeshRun | undefined {
    const state = this.runs.get(runId);
    if (!state) return undefined;
    return {
      progress: { ...state.progress, tokens: { ...state.progress.tokens } },
      steps: [...state.steps],
      ...(state.report !== undefined ? { report: state.report } : {}),
    };
  }

  // ---- internals ----

  private async execute(runId: string, plan: MeshRunPlan, ctx: MeshRunContext): Promise<void> {
    const state = this.mustRun(runId);
    const active = this.wrapActive(runId, ctx.tools, ctx.config);
    const redact = ctx.config.redactBeforeSend ? this.deps.redactResult : undefined;
    const finalTools = redact ? active.map((spec) => redactTool(spec, redact)) : active;
    const toolsFor = (role: AgentRole): ToolSpec[] =>
      finalTools.filter((tool) => this.mayCall(role, tool.effect, ctx.config.autonomy));
    const declined: string[] = [];

    // Recon first, always: review the engagement folder, the rules, the scope,
    // and the interception state before anything is planned.
    const reconResult = await this.runRole(runId, ctx, 'recon', toolsFor('recon'), [
      { role: 'user', content: reconPrompt(plan) },
    ]);
    if (this.aborted(state)) return;
    let reconText = reconResult.text;
    if (this.noteRefusal(runId, 'recon', reconResult, declined)) {
      // The model declined to write the recon summary. The engine already knows
      // the readiness state, the scope, the engagement folder, and the ranked
      // surface — none of that needed a model — so hand that over and carry on
      // rather than discarding the run.
      reconText = await this.engineBriefing();
      this.pushStep(
        runId,
        'recon',
        'error',
        'The model declined the recon turn. Continuing on the engine-built briefing ' +
          '(preflight, scope, engagement folder, ranked surface) instead. Recon commentary is ' +
          'missing from this run.',
      );
    }
    if (isBlocked(reconText)) {
      state.report = reconText;
      this.pushStep(
        runId,
        'recon',
        'error',
        'Recon reported a blocker; the run stopped before planning. See the recon message.',
      );
      this.finish(runId, 'done');
      return;
    }

    const planResult = await this.runRole(runId, ctx, 'planner', toolsFor('planner'), [
      { role: 'user', content: plannerPrompt(plan, reconText) },
    ]);
    if (this.aborted(state)) return;
    let planText = planResult.text;
    if (this.noteRefusal(runId, 'planner', planResult, declined)) {
      // Same reasoning as recon: the ranked attack surface is a real, ordered
      // list of where to look, computed by the engine. Better to work it than to
      // discard the run.
      planText = await this.engineBriefing();
      this.pushStep(
        runId,
        'planner',
        'error',
        'The model declined the planning turn. Falling back to the engine-ranked attack surface. ' +
          'There is no model-written test plan in this run.',
      );
    }

    let analysis = '';
    for (let round = 1; round <= MAX_ROUNDS; round += 1) {
      if (
        this.aborted(state) ||
        this.budgetExceeded(state, ctx) ||
        this.activeExhausted(state, ctx)
      ) {
        break;
      }
      const attackResult = await this.runRole(runId, ctx, 'attacker', toolsFor('attacker'), [
        {
          role: 'user',
          content: attackerPrompt(plan, planText, analysis, ctx.config.autonomy),
        },
      ]);
      if (this.aborted(state)) return;
      this.noteRefusal(runId, 'attacker', attackResult, declined);

      const analystResult = await this.runRole(runId, ctx, 'analyst', toolsFor('analyst'), [
        { role: 'user', content: analystPrompt(attackResult.text) },
      ]);
      this.noteRefusal(runId, 'analyst', analystResult, declined);
      analysis += `\n\n[Round ${round}]\n${analystResult.text}`;
      if (this.aborted(state)) return;
      if (/^\s*DONE\s*$/im.test(analystResult.text)) break;
    }
    if (this.aborted(state)) return;

    const reportResult = await this.runRole(runId, ctx, 'reporter', toolsFor('reporter'), [
      { role: 'user', content: reporterPrompt(plan, reconText, analysis, declined) },
    ]);
    state.report = reportResult.text;
    this.pushStep(runId, 'reporter', 'finding', 'Engagement report ready.');
    this.finish(runId, 'done');
  }

  private async runRole(
    runId: string,
    ctx: MeshRunContext,
    role: AgentRole,
    tools: ToolSpec[],
    messages: AgentMessage[],
  ): Promise<{ text: string; stopReason: string }> {
    const state = this.mustRun(runId);
    state.progress.role = role;
    state.progress.status = role === 'planner' || role === 'recon' ? 'planning' : 'running';
    this.emitProgress(state);
    this.pushStep(runId, role, 'message', `${role} starting…`);

    const roleConfig = ctx.config.roles[role];
    const effort = roleConfig.effort;
    const deep = effort === 'xhigh' || effort === 'max';
    const perRole = ctx.config.runTokenBudget > 0 ? Math.floor(ctx.config.runTokenBudget / 5) : 0;
    const result = await ctx.provider.runAgent({
      system: systemPromptFor(role),
      messages,
      tools,
      model: roleConfig.model,
      ...(effort ? { effort } : {}),
      maxTokens: deep ? ROLE_MAX_TOKENS_DEEP : ROLE_MAX_TOKENS_DEFAULT,
      maxIterations: MAX_ITERATIONS_PER_ROLE,
      ...(perRole >= MIN_TASK_BUDGET ? { taskTokenBudget: perRole } : {}),
      signal: state.controller.signal,
      onToolCall: (call) => {
        // Every attempt is shown in the activity stream (including ones the cap
        // later refuses); the AUDIT of a real request happens in wrapMutating,
        // only once the request is actually about to be sent.
        const spec = tools.find((t) => t.name === call.name);
        this.pushStep(runId, role, 'tool-call', `${call.name} ${briefInput(call.input)}`, {
          tool: call.name,
          mutating: spec?.mutates ?? false,
        });
      },
      onToolResult: (call, res) => {
        this.pushStep(runId, role, 'tool-result', summarizeResult(res), { tool: call.name });
      },
    });
    this.addTokens(state, result.tokens);
    if (result.text.trim()) this.pushStep(runId, role, 'message', result.text);
    // A turn cut off at the output ceiling is not a turn that finished. Saying so
    // is the difference between "the analyst found little" and "the analyst was
    // truncated mid-sentence and you are reading half a thought".
    if (result.stopReason === 'max_tokens') {
      this.pushStep(
        runId,
        role,
        'error',
        `The ${role} turn hit the output ceiling and was cut off mid-answer. Treat its output as incomplete.`,
      );
    }
    return { text: result.text, stopReason: result.stopReason };
  }

  /**
   * The engine's own briefing, for when a model turn is declined.
   *
   * Deliberately never throws: it exists to keep a run alive on deterministic
   * data, so a failure to build it must not become the thing that kills the run.
   */
  private async engineBriefing(): Promise<string> {
    const scope = this.deps.getScope();
    const hosts = scope.include
      .filter((r) => r.enabled !== false)
      .map((r) => r.host)
      .join(', ');
    const fallback =
      `ENGINE BRIEFING (no model recon was produced for this run).

` +
      `In-scope hosts: ${hosts || '(none)'}
` +
      `Every request is checked against this scope by the engine and refused if it falls outside.`;
    if (!this.deps.briefing) return fallback;
    try {
      const text = (await this.deps.briefing()).trim();
      return text || fallback;
    } catch (err) {
      this.deps.logger?.warn?.('mesh: engine briefing failed', {
        error: err instanceof Error ? err.message : String(err),
      });
      return fallback;
    }
  }

  /**
   * Record a declined turn. A refusal arrives as a successful response with an
   * empty body, so without this the run would treat "the model would not do
   * this" as "there was nothing to say" and report a clean result. Returns true
   * when the turn was declined.
   */
  private noteRefusal(
    runId: string,
    role: AgentRole,
    result: { text: string; stopReason: string },
    declined: string[],
  ): boolean {
    if (result.stopReason !== 'refusal') return false;
    declined.push(role);
    this.pushStep(
      runId,
      role,
      'error',
      `The model declined this ${role} turn. Its work was NOT done — do not read the rest of this run as coverage of it.`,
    );
    this.deps.audit({
      ts: Date.now(),
      actor: `ai-mesh:${role}`,
      action: 'mesh.refused',
      detail: { role },
    });
    return true;
  }

  /** Refuse any tool call once the run has been stopped. */
  private wrapAbort(runId: string, spec: ToolSpec): ToolSpec {
    return {
      ...spec,
      handler: async (input: Record<string, unknown>) => {
        const state = this.runs.get(runId);
        if (!state || state.controller.signal.aborted) return { error: 'run stopped' };
        return spec.handler(input);
      },
    };
  }

  /** Whether a role may call a tool with this effect under this autonomy. */
  private mayCall(role: AgentRole, effect: ToolEffect, autonomy: AiAutonomy): boolean {
    if (autonomy === 'readonly' && READONLY_WITHHELD.includes(effect)) return false;
    return ROLE_EFFECTS[role].includes(effect);
  }

  /**
   * Wrap active (mutating) tools so the per-run active-request BUDGET is enforced
   * by the number of HTTP requests each action launches — not one-per-tool-call.
   * A fuzz job that would launch N requests is charged N and refused if it would
   * exceed the remaining budget, so the model cannot fan out past the cap.
   */
  private wrapActive(runId: string, tools: ToolSpec[], config: AiConfig): ToolSpec[] {
    return tools.map((spec) => {
      // EVERY tool honours the stop, not just the ones that cost budget.
      // Emergency stop has to also stop a CA revocation or a memory write that
      // was dispatched a moment before the operator hit it.
      if (!spec.mutates) return this.wrapAbort(runId, spec);
      return {
        ...spec,
        handler: async (input: Record<string, unknown>) => {
          const state = this.runs.get(runId);
          if (!state || state.controller.signal.aborted) return { error: 'run stopped' };
          const cost = Math.max(0, Math.trunc(await (spec.requestCost?.(input) ?? 1)));
          if (cost > 0 && state.progress.activeRequests + cost > config.maxActiveRequestsPerRun) {
            return {
              error: `active-request budget (${config.maxActiveRequestsPerRun}) for this run would be exceeded: this action launches ${cost} request(s) and ${state.progress.activeRequests} are already used. Narrow the job or send fewer requests.`,
            };
          }
          if (cost > 0) {
            state.progress.activeRequests += cost;
            this.emitProgress(state);
            // Audit real requests only (cost 0 = no traffic, e.g. creating a job).
            const target = targetOf(input);
            this.deps.audit({
              ts: Date.now(),
              actor: `ai-mesh:${state.progress.role ?? 'attacker'}`,
              action: 'mesh.request',
              ...(target ? { target } : {}),
              detail: { tool: spec.name, requests: cost },
            });
          }
          return spec.handler(input);
        },
      };
    });
  }

  /** Evict oldest terminal runs so the in-memory history cannot grow without bound. */
  private prune(): void {
    if (this.runs.size <= MAX_RETAINED_RUNS) return;
    const terminal = new Set<MeshRunStatus>(['done', 'error', 'stopped']);
    for (const [id, st] of this.runs) {
      if (this.runs.size <= MAX_RETAINED_RUNS) break;
      if (terminal.has(st.progress.status)) this.runs.delete(id);
    }
  }

  private pushStep(
    runId: string,
    role: AgentRole,
    kind: MeshStep['kind'],
    summary: string,
    opts?: { tool?: string; mutating?: boolean },
  ): void {
    const state = this.runs.get(runId);
    if (!state) return;
    const createdAt = Date.now();
    const step: MeshStep = {
      id: randomUUID(),
      runId,
      role,
      kind,
      summary: summary.length > 4000 ? `${summary.slice(0, 4000)}…` : summary,
      createdAt,
      ...(opts?.tool ? { tool: opts.tool } : {}),
      ...(opts?.mutating !== undefined ? { mutating: opts.mutating } : {}),
    };
    state.steps.push(step);
    if (state.steps.length > MAX_STEPS) state.steps.splice(0, state.steps.length - MAX_STEPS);
    state.progress.stepCount += 1;
    state.progress.updatedAt = createdAt;
    this.deps.onStep(step);
    this.emitProgress(state);
  }

  private addTokens(state: RunState, tokens: { input: number; output: number }): void {
    state.progress.tokens.input += tokens.input;
    state.progress.tokens.output += tokens.output;
    state.progress.updatedAt = Date.now();
    this.emitProgress(state);
  }

  private finish(runId: string, status: MeshRunStatus): void {
    const state = this.runs.get(runId);
    if (!state) return;
    if (state.progress.status === 'done' || state.progress.status === 'error') return;
    state.progress.status = status;
    state.progress.updatedAt = Date.now();
    this.deps.audit({
      ts: state.progress.updatedAt,
      actor: 'ai-mesh',
      action: `mesh.${status}`,
      detail: {
        steps: state.progress.stepCount,
        activeRequests: state.progress.activeRequests,
        tokens: state.progress.tokens,
      },
    });
    this.emitProgress(state);
  }

  private fail(runId: string, err: unknown): void {
    const state = this.runs.get(runId);
    if (!state) return;
    const message = err instanceof Error ? err.message : String(err);
    this.deps.logger?.error('mesh run failed', { runId, err: message });
    this.pushStep(runId, state.progress.role ?? 'planner', 'error', message);
    state.progress.status = 'error';
    state.progress.error = message;
    state.progress.updatedAt = Date.now();
    this.deps.audit({
      ts: state.progress.updatedAt,
      actor: 'ai-mesh',
      action: 'mesh.error',
      detail: { error: message },
    });
    this.emitProgress(state);
  }

  private emitProgress(state: RunState): void {
    this.deps.onProgress({ ...state.progress, tokens: { ...state.progress.tokens } });
  }

  private mustRun(runId: string): RunState {
    const state = this.runs.get(runId);
    if (!state) throw new Error(`unknown mesh run: ${runId}`);
    return state;
  }

  private aborted(state: RunState): boolean {
    return state.controller.signal.aborted;
  }

  private budgetExceeded(state: RunState, ctx: MeshRunContext): boolean {
    const total = state.progress.tokens.input + state.progress.tokens.output;
    return ctx.config.runTokenBudget > 0 && total >= ctx.config.runTokenBudget;
  }

  private activeExhausted(state: RunState, ctx: MeshRunContext): boolean {
    return state.progress.activeRequests >= ctx.config.maxActiveRequestsPerRun;
  }
}

// ---- prompt builders + step formatting ----

function hostLine(plan: MeshRunPlan): string {
  return plan.hosts?.length ? `\nRestrict to these in-scope hosts: ${plan.hosts.join(', ')}.` : '';
}

function reconPrompt(plan: MeshRunPlan): string {
  return `Objective: ${plan.objective}${hostLine(plan)}

Run recon now. Check readiness with get_preflight, read the engagement folder for the program's binding rules, confirm the interception path actually works, and map the attack surface from captured traffic. Send no requests to the target.

If preflight reports a blocker, say so in your FIRST line, beginning with "BLOCKED:", and explain what must be fixed. Otherwise report readiness, the rules that bind this engagement, the attack surface, and where a real issue is most likely to be.`;
}

/** Recon opens with "BLOCKED:" when the engagement cannot legitimately proceed. */
function isBlocked(reconText: string): boolean {
  return /^\s*BLOCKED\s*:/i.test(reconText);
}

function plannerPrompt(plan: MeshRunPlan, reconText: string): string {
  return `Objective: ${plan.objective}${hostLine(plan)}

Recon reported:
${reconText}

Produce the prioritised, hypothesis-driven test plan now, honouring the program rules recon surfaced. Do not send any requests.`;
}

function attackerPrompt(
  plan: MeshRunPlan,
  planText: string,
  analysis: string,
  autonomy: AiAutonomy,
): string {
  const mode =
    autonomy === 'readonly'
      ? 'You have NO active tools this run (read-only mode) — do not attempt to send requests; just note what you would test.'
      : 'Execute the highest-value, least-impact checks. Call evaluate_scope before every destination.';
  const prior = analysis.trim() ? `\n\nPrior analysis:${analysis}` : '';
  return `Objective: ${plan.objective}\n\nPlan:\n${planText}\n\n${mode}${prior}`;
}

function analystPrompt(attackText: string): string {
  return `The attacker just reported:\n${attackText}\n\nReview the resulting exchanges and findings, triage real vs. noise (cite exchange ids), and either say what to probe next or output DONE on its own line if the objective is met.`;
}

function reporterPrompt(
  plan: MeshRunPlan,
  reconText: string,
  analysis: string,
  declined: string[],
): string {
  // A declined turn is coverage the run did not get. The report has to say so,
  // or the operator reads silence as a clean result.
  const gaps = declined.length
    ? `\n\nIMPORTANT — these roles were declined by the model and their work was NOT done: ${declined.join(', ')}. State this plainly in the report's coverage section; do not present the engagement as complete.`
    : '';
  return `Objective: ${plan.objective}

Recon (engagement context and rules):
${reconText}

Round-by-round analysis:${analysis || '\n(none)'}${gaps}

Write the final engagement report now, using only evidence you can cite.`;
}

/** Wrap a tool so its result is structurally redacted before egress. */
function redactTool(spec: ToolSpec, redactResult: (value: unknown) => unknown): ToolSpec {
  return {
    ...spec,
    handler: async (input: Record<string, unknown>) => redactResult(await spec.handler(input)),
  };
}

function briefInput(input: Record<string, unknown>): string {
  try {
    const s = JSON.stringify(input);
    return s.length > 200 ? `${s.slice(0, 200)}…` : s;
  } catch {
    return '';
  }
}

function summarizeResult(res: unknown): string {
  if (res && typeof res === 'object' && 'error' in res) {
    return `error: ${String((res as { error: unknown }).error)}`;
  }
  try {
    const s = typeof res === 'string' ? res : JSON.stringify(res);
    return s.length > 500 ? `${s.slice(0, 500)}…` : s;
  } catch {
    return '[unserializable result]';
  }
}

function targetOf(input: Record<string, unknown>): string | undefined {
  if (typeof input.url === 'string') return input.url;
  const t = (input.target ?? input.base) as
    { scheme?: string; host?: string; port?: number } | undefined;
  if (t && typeof t.host === 'string') {
    return `${t.scheme ?? 'https'}://${t.host}${t.port ? `:${t.port}` : ''}`;
  }
  return undefined;
}
