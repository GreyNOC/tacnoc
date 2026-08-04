/**
 * Shared types for the AI mesh — the multi-agent layer that drives TACNOC's
 * engine primitives to plan, execute, and report authorized web-app tests.
 *
 * The mesh runs entirely in the main process; the renderer only ever sees these
 * DTOs over the existing IPC event channel — never a vendor SDK and never an API
 * key. Provider backends sit behind engine/ai/provider.ts so the orchestrator is
 * provider-agnostic (Anthropic today; OpenAI slots in when billing is enabled).
 *
 * SAFETY INVARIANT: every model-initiated action still routes through the
 * project scope gate, rate limiter, per-run active-request cap, audit log, and
 * emergency stop. "Autonomous within scope" means the mesh may act WITHOUT
 * per-request approval — it does NOT mean without bounds. The scope gate is the
 * hard boundary and cannot be bypassed from this layer.
 */

/** Which vendor backend answers a role. */
export type AiProviderId = 'anthropic' | 'openai';

/**
 * A mesh role. Each maps to a focused system prompt + a subset of tools.
 *
 * `recon` runs FIRST and is read-only. It reviews the engagement folder, the
 * program's rules, the scope, the certificate state, and the traffic already
 * captured — before anything is planned. Planning without that step is how you
 * get a confident test plan for the wrong hosts, under the wrong rules, against
 * a proxy that was never intercepting.
 */
export type AgentRole = 'recon' | 'planner' | 'attacker' | 'analyst' | 'reporter';

export const AGENT_ROLES: readonly AgentRole[] = [
  'recon',
  'planner',
  'attacker',
  'analyst',
  'reporter',
];

/** How much the mesh may do without a human in the loop. */
export type AiAutonomy =
  | 'readonly' // never sends traffic — analyses captured data only
  | 'approve' // active requests queue for one-click approval (future)
  | 'auto'; // acts within scope without per-request approval

/** Reasoning effort. Higher means more thinking per turn, not more requests. */
export type AiEffort = 'low' | 'medium' | 'high' | 'xhigh' | 'max';

export const AI_EFFORTS: readonly AiEffort[] = ['low', 'medium', 'high', 'xhigh', 'max'];

export interface AiModelConfig {
  provider: AiProviderId;
  /** Exact provider model ID (e.g. "claude-opus-5"). Not validated here. */
  model: string;
  /**
   * Reasoning effort for this role. Ignored by models that do not support it.
   * Raising effort buys depth of reasoning per turn — it does NOT raise the
   * number of requests sent to the target, which stays bounded by the scope
   * gate, the rate limiter, and the per-run active-request budget.
   */
  effort?: AiEffort;
}

/**
 * Non-secret AI settings, persisted per project. The API key is NOT here — it
 * lives app-level in OS secure storage and never reaches the renderer.
 */
export interface AiConfig {
  enabled: boolean;
  /**
   * Egress acknowledgement. The mesh sends captured request/response content to
   * the model provider. OFF by default; must be enabled per project; every
   * toggle is written to the audit log. Never silently assumed.
   */
  egressAcknowledged: boolean;
  /**
   * Redact captured content before it reaches the provider: cookie / Authorization
   * / credential headers are masked (thorough), and secret patterns (tokens, keys,
   * JWTs, Bearer/Basic, password/secret assignments) are masked in the DECODED
   * request/response bodies. Body masking is pattern-based (best-effort) — an
   * opaque, non-pattern token sitting in a body may still pass.
   */
  redactBeforeSend: boolean;
  autonomy: AiAutonomy;
  /** Per-role model assignment. */
  roles: Record<AgentRole, AiModelConfig>;
  /** Soft token budget for one closed-loop run (0 = provider default). */
  runTokenBudget: number;
  /** Hard ceiling on active (target-touching) requests the mesh may launch per run. */
  maxActiveRequestsPerRun: number;
  /**
   * Let the mesh read the engagement workspace folder (program policy, scope
   * documents, operator notes) during recon. Read-only and sandboxed to the
   * folder, but its contents are egressed to the provider like any other
   * context — so it is a separate, explicit choice. ON by default because the
   * whole point of recon is reviewing that folder before planning; turn it off
   * for a folder holding material you do not want sent.
   */
  workspaceAccess: boolean;
  /**
   * Let the mesh issue and revoke the project's TLS interception CA. Useful for
   * testing how a client behaves when the certificate changes or interception
   * stops. OFF by default: rotating the CA breaks every browser that trusted
   * the old one until the operator installs the new one, so it should be a
   * deliberate grant rather than a surprise mid-run.
   */
  allowCertOps: boolean;
  /** Optional base-URL override for special-access endpoints. */
  baseUrl?: string;
}

/** Whether an API key is present + how securely it is held. Never carries the key. */
export interface AiKeyStatus {
  configured: boolean;
  secure: boolean;
  backendName: string;
}

// ---- run lifecycle (main → renderer over IPC events) ----

export type MeshRunStatus = 'planning' | 'running' | 'paused' | 'done' | 'error' | 'stopped';

/** One observable event in a mesh run — streamed to the UI as it happens. */
export interface MeshStep {
  id: string;
  runId: string;
  role: AgentRole;
  kind: 'thought' | 'tool-call' | 'tool-result' | 'message' | 'finding' | 'error';
  summary: string;
  createdAt: number;
  /** Present for tool-call / tool-result steps. */
  tool?: string;
  /** True when the step generated (or would generate) traffic to the target. */
  mutating?: boolean;
}

export interface MeshRunProgress {
  runId: string;
  status: MeshRunStatus;
  role?: AgentRole;
  stepCount: number;
  activeRequests: number;
  tokens: { input: number; output: number };
  startedAt: number;
  updatedAt: number;
  error?: string;
}

export interface MeshRun {
  progress: MeshRunProgress;
  steps: MeshStep[];
  report?: string;
}

export interface MeshRunPlan {
  /** Free-text objective from the operator, e.g. "test the auth and search endpoints". */
  objective: string;
  /** Optional restriction to specific already-in-scope hosts. */
  hosts?: string[];
}

/**
 * Off-by-default, autonomous-within-scope defaults. Pure so main + renderer
 * share it.
 *
 * Every role runs the most capable model rather than a cheap one for triage.
 * The expensive part of an engagement is a missed vulnerability or a fabricated
 * finding, not tokens — and the roles that look "cheap" (triage, reporting) are
 * exactly where a weaker model produces false positives that cost real hours to
 * disprove. Effort is `xhigh` on the two agentic roles, where extra reasoning
 * per turn buys fewer, better-targeted requests at the target.
 */
export function defaultAiConfig(): AiConfig {
  const opus = (effort: AiEffort): AiModelConfig => ({
    provider: 'anthropic',
    model: 'claude-opus-5',
    effort,
  });
  return {
    enabled: false,
    egressAcknowledged: false,
    redactBeforeSend: false,
    autonomy: 'auto',
    roles: {
      recon: opus('high'),
      planner: opus('xhigh'),
      attacker: opus('xhigh'),
      analyst: opus('high'),
      reporter: opus('high'),
    },
    runTokenBudget: 0,
    maxActiveRequestsPerRun: 50,
    workspaceAccess: true,
    allowCertOps: false,
  };
}

/**
 * Load a stored config, filling gaps and validating every value.
 *
 * A project file is data, not trusted configuration. It can be hand-edited,
 * shared, or imported from someone else, and the values here govern real safety
 * controls — so nothing is taken on faith. Two of these matter more than the
 * rest: a non-numeric `maxActiveRequestsPerRun` would make every budget
 * comparison `NaN` and silently disable the per-run request cap, and `baseUrl`
 * decides which host receives the operator's API key.
 */
export function normalizeAiConfig(stored: Partial<AiConfig> | undefined): AiConfig {
  const base = defaultAiConfig();
  if (!stored || typeof stored !== 'object') return base;

  const roles = { ...base.roles };
  for (const role of AGENT_ROLES) {
    const provided = stored.roles?.[role];
    if (!provided?.model || typeof provided.model !== 'string') continue;
    const effort =
      typeof provided.effort === 'string' &&
      (AI_EFFORTS as readonly string[]).includes(provided.effort)
        ? (provided.effort as AiEffort)
        : base.roles[role].effort;
    roles[role] = {
      provider: provided.provider === 'openai' ? 'openai' : 'anthropic',
      model: provided.model,
      ...(effort ? { effort } : {}),
    };
  }

  const bool = (value: unknown, fallback: boolean): boolean =>
    typeof value === 'boolean' ? value : fallback;
  const count = (value: unknown, fallback: number, max: number): number =>
    typeof value === 'number' && Number.isFinite(value) && value >= 0
      ? Math.min(Math.trunc(value), max)
      : fallback;

  return {
    enabled: bool(stored.enabled, base.enabled),
    egressAcknowledged: bool(stored.egressAcknowledged, base.egressAcknowledged),
    redactBeforeSend: bool(stored.redactBeforeSend, base.redactBeforeSend),
    autonomy:
      stored.autonomy === 'readonly' || stored.autonomy === 'approve' || stored.autonomy === 'auto'
        ? stored.autonomy
        : base.autonomy,
    roles,
    runTokenBudget: count(stored.runTokenBudget, base.runTokenBudget, 100_000_000),
    maxActiveRequestsPerRun: count(
      stored.maxActiveRequestsPerRun,
      base.maxActiveRequestsPerRun,
      100_000,
    ),
    workspaceAccess: bool(stored.workspaceAccess, base.workspaceAccess),
    allowCertOps: bool(stored.allowCertOps, base.allowCertOps),
    ...(normalizeBaseUrl(stored.baseUrl) ? { baseUrl: normalizeBaseUrl(stored.baseUrl) } : {}),
  };
}

/**
 * A base URL is only honoured when it is a well-formed **https** origin.
 *
 * This value decides where the API key is sent. A project file carrying
 * `http://attacker.test` would hand the operator's key — held in OS secure
 * storage precisely so it is hard to reach — to that host in cleartext on the
 * first turn. Anything not plainly https is dropped and the provider default is
 * used instead.
 */
function normalizeBaseUrl(value: unknown): string | undefined {
  if (typeof value !== 'string' || !value.trim()) return undefined;
  try {
    const url = new URL(value.trim());
    return url.protocol === 'https:' ? url.toString() : undefined;
  } catch {
    return undefined;
  }
}
