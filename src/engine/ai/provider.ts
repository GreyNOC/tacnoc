/**
 * LlmProvider — the single seam the AI mesh talks to.
 *
 * Concrete backends implement this so the orchestrator never imports a vendor
 * SDK directly:
 *   - AnthropicProvider  → @anthropic-ai/sdk Tool Runner (drives its own loop)
 *   - OpenAiProvider     → openai SDK tool loop (model id + endpoint from config)
 *
 * This is what makes the mesh multi-provider: the same ToolSpec set and the same
 * agent turn drive either backend.
 */

import type { ToolSpec } from './tools.js';

export interface AgentMessage {
  role: 'user' | 'assistant';
  content: string;
}

export interface ToolCall {
  id: string;
  name: string;
  input: Record<string, unknown>;
}

export interface AgentTurnOptions {
  /** System prompt defining the role and its guardrails. */
  system: string;
  /** Conversation so far, provider-neutral. */
  messages: AgentMessage[];
  /** Tools this role may call. A subset of the full registry. */
  tools: ToolSpec[];
  /** Exact provider model id. */
  model: string;
  /** Hard per-response output cap. Defaults to the provider's configured default. */
  maxTokens?: number;
  /** Hard cap on tool-loop iterations for this turn — bounds a runaway role. */
  maxIterations?: number;
  /**
   * Reasoning effort. Ignored by backends/models that do not support it. `xhigh`
   * is the right setting for the agentic roles: the model reads more captured
   * evidence before choosing what to probe, which is exactly the tradeoff a
   * least-impact engagement wants (more thinking, fewer requests at the target).
   */
  effort?: 'low' | 'medium' | 'high' | 'xhigh' | 'max';
  /** Soft, self-paced token budget for this turn (0/undefined = provider default). */
  taskTokenBudget?: number;
  signal?: AbortSignal;
  /** Fired for every tool the model invokes, BEFORE the handler runs — for audit + gating. */
  onToolCall?: (call: ToolCall) => void;
  /** Fired with the tool's result after the handler runs. */
  onToolResult?: (call: ToolCall, result: unknown) => void;
  /** Streamed assistant text deltas, for live UI. */
  onText?: (delta: string) => void;
}

export interface AgentTurnResult {
  /** Final assistant text after the tool loop settles. */
  text: string;
  tokens: { input: number; output: number };
  /** Provider stop reason, normalized loosely ("end_turn", "stop", "max_tokens", ...). */
  stopReason: string;
}

export interface LlmProvider {
  readonly id: string;
  /**
   * Run one agent to completion: the backend drives its own tool-call loop
   * (Anthropic Tool Runner / OpenAI tool loop), executing ToolSpec handlers as
   * the model requests them, until the model stops calling tools or the run is
   * aborted via `signal`.
   */
  runAgent(options: AgentTurnOptions): Promise<AgentTurnResult>;
}
