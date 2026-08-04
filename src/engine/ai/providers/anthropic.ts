/**
 * Anthropic backend for the AI mesh, built on the SDK's beta Tool Runner.
 *
 * The Tool Runner drives its own request → execute → loop cycle over the tools
 * we hand it, so the orchestrator never writes a manual agent loop. Each engine
 * ToolSpec is wrapped as a `betaTool` whose `run` fires our audit/observe hooks
 * before and after the real handler, and turns a thrown handler error (e.g. the
 * scope gate refusing an out-of-scope job) into a tool-result the model can read
 * and adapt to — a single tool failure never crashes the run.
 *
 * Model-capability aware: adaptive thinking, reasoning effort, and task budgets
 * are only sent to models that accept them, so a Haiku triage role does not 400.
 *
 * A declined request is reported, never swallowed. The API returns HTTP 200 with
 * `stop_reason: "refusal"` and usually empty content, which is indistinguishable
 * from "the model had nothing to say" unless you check for it — and for a
 * bug-hunting tool, silently turning a decline into an empty finding set is the
 * worst available failure. `runAgent` returns the stop reason so the orchestrator
 * can record it as an error the operator sees.
 */

import Anthropic from '@anthropic-ai/sdk';
import { betaTool } from '@anthropic-ai/sdk/helpers/beta/json-schema';
import { randomUUID } from 'node:crypto';
import type { AgentTurnOptions, AgentTurnResult, LlmProvider, ToolCall } from '../provider.js';
import type { ToolSpec } from '../tools.js';

const ADAPTIVE_THINKING = [
  'claude-opus-5',
  'claude-opus-4-8',
  'claude-opus-4-7',
  'claude-opus-4-6',
  'claude-sonnet-5',
  'claude-fable-5',
];
const TASK_BUDGET = [
  'claude-opus-5',
  'claude-opus-4-8',
  'claude-opus-4-7',
  'claude-sonnet-5',
  'claude-fable-5',
];
/**
 * Models accepting `output_config.effort`. Effort is the single largest quality
 * lever for this workload: agentic tool-use benefits materially from `xhigh`,
 * where the model reads more evidence before deciding what to probe.
 */
const EFFORT = [
  'claude-opus-5',
  'claude-opus-4-8',
  'claude-opus-4-7',
  'claude-opus-4-6',
  'claude-sonnet-5',
  'claude-sonnet-4-6',
  'claude-fable-5',
];

const TASK_BUDGET_BETA = 'task-budgets-2026-03-13';

const startsWithAny = (prefixes: string[], model: string): boolean =>
  prefixes.some((p) => model.startsWith(p));

/**
 * One turn of a streaming tool-runner: the SSE events, then the assembled
 * message. Only the two members this provider actually reads are declared.
 */
interface StreamedTurn<M> extends AsyncIterable<StreamEvent> {
  finalMessage(): Promise<M>;
}

/**
 * The one event shape we act on. Declared as a single open type rather than a
 * union: a union whose fallback arm is `{type: string}` is not discriminated —
 * the fallback absorbs every literal and `delta` becomes unreachable.
 */
interface StreamEvent {
  type: string;
  delta?: { type: string; text?: string };
}

export interface AnthropicProviderOptions {
  apiKey: string;
  baseUrl?: string;
  defaultMaxTokens?: number;
}

export class AnthropicProvider implements LlmProvider {
  readonly id = 'anthropic';
  private readonly client: Anthropic;
  private readonly defaultMaxTokens: number;

  constructor(opts: AnthropicProviderOptions) {
    this.client = new Anthropic({
      apiKey: opts.apiKey,
      ...(opts.baseUrl ? { baseURL: opts.baseUrl } : {}),
    });
    // Streaming removes the timeout ceiling that forced a small cap, so the
    // budget can be sized for the work instead. The agentic roles run at xhigh
    // effort, where adaptive thinking takes a large share of the output budget —
    // at 8192 a planner could spend the whole allowance thinking and return a
    // truncated plan with `stop_reason: max_tokens`, burning the turn.
    this.defaultMaxTokens = opts.defaultMaxTokens ?? 64000;
  }

  async runAgent(options: AgentTurnOptions): Promise<AgentTurnResult> {
    const runnable = options.tools.map((spec) =>
      toBetaTool(spec, options.onToolCall, options.onToolResult),
    );
    const useAdaptive = startsWithAny(ADAPTIVE_THINKING, options.model);
    const useBudget = !!options.taskTokenBudget && startsWithAny(TASK_BUDGET, options.model);
    const effort =
      options.effort && startsWithAny(EFFORT, options.model) ? options.effort : undefined;
    // Both knobs live under output_config; sending two of them separately would
    // drop the first.
    const outputConfig = {
      ...(effort ? { effort } : {}),
      ...(useBudget
        ? { task_budget: { type: 'tokens' as const, total: options.taskTokenBudget } }
        : {}),
    };

    const body = {
      model: options.model,
      max_tokens: options.maxTokens ?? this.defaultMaxTokens,
      // Hard cap on the tool-call loop so a single role can never run unbounded,
      // regardless of what the model does (the SDK loops until this or end_turn).
      max_iterations: options.maxIterations ?? 32,
      // Frozen role prompt cached across the run's many turns.
      system: [
        {
          type: 'text' as const,
          text: options.system,
          cache_control: { type: 'ephemeral' as const },
        },
      ],
      messages: options.messages.map((m) => ({ role: m.role, content: m.content })),
      tools: runnable,
      // Stream, always.
      //
      // The SDK refuses a NON-streaming request whose max_tokens implies it could
      // run past the 10-minute HTTP ceiling — "Streaming is required for
      // operations that may take longer than 10 minutes" — and it refuses it
      // before sending anything, so the turn dies with no output at all. Agentic
      // roles at xhigh effort are exactly the shape that trips it.
      //
      // It also earns its keep: text now reaches the operator as it is generated
      // rather than in one lump when the turn ends.
      stream: true as const,
      ...(useAdaptive ? { thinking: { type: 'adaptive' as const } } : {}),
      ...(Object.keys(outputConfig).length ? { output_config: outputConfig } : {}),
    };

    const reqOptions: { signal?: AbortSignal; headers?: Record<string, string> } = {};
    if (options.signal) reqOptions.signal = options.signal;
    if (useBudget) reqOptions.headers = { 'anthropic-beta': TASK_BUDGET_BETA };

    // `as never`: the body carries beta-only fields (thinking/output_config) that
    // are valid on the wire but not all typed in the SDK's params yet.
    const rawRunner = this.client.beta.messages.toolRunner(body as never, reqOptions);
    type FinalMessage = Awaited<ReturnType<typeof rawRunner.done>>;
    // The `as never` above also erases `stream: true` from the runner's inferred
    // type, so it still claims to yield messages. Restore the streaming shape
    // explicitly rather than iterating against a type that does not match what
    // arrives at runtime.
    const runner = rawRunner as unknown as AsyncIterable<StreamedTurn<FinalMessage>> & {
      done(): Promise<FinalMessage>;
      pushMessages(...messages: { role: 'assistant'; content: FinalMessage['content'] }[]): void;
    };

    let input = 0;
    let output = 0;
    let finalText = '';
    // With `stream: true` each iteration yields a STREAM, not a message — a
    // `message.stop_reason` check against it silently never matches.
    for await (const stream of runner) {
      // Reset per message. Carrying text forward from an earlier turn would let a
      // declined or empty final message be reported as this role's answer — the
      // exact "silence looks like a result" failure the refusal handling exists
      // to prevent.
      let messageText = '';
      for await (const event of stream) {
        if (
          event.type === 'content_block_delta' &&
          event.delta?.type === 'text_delta' &&
          event.delta.text
        ) {
          messageText += event.delta.text;
          options.onText?.(event.delta.text);
        }
      }
      const message = await stream.finalMessage();
      const u = message.usage;
      input +=
        (u.input_tokens ?? 0) +
        (u.cache_read_input_tokens ?? 0) +
        (u.cache_creation_input_tokens ?? 0);
      output += u.output_tokens ?? 0;
      finalText = messageText;

      // The runner does NOT resume a paused turn on its own — it only continues
      // after a tool produces a result. A `pause_turn` would otherwise end the
      // loop with no error and no warning, and the truncated answer would be
      // reported as this role's complete work.
      if (message.stop_reason === 'pause_turn') {
        runner.pushMessages({ role: 'assistant', content: message.content });
      }
    }
    const final = await runner.done();
    return {
      text: finalText,
      tokens: { input, output },
      stopReason: final.stop_reason ?? 'end_turn',
    };
  }
}

function toBetaTool(
  spec: ToolSpec,
  onToolCall?: (call: ToolCall) => void,
  onToolResult?: (call: ToolCall, result: unknown) => void,
): ReturnType<typeof betaTool> {
  return betaTool({
    name: spec.name,
    description: spec.description,
    inputSchema: spec.inputSchema as { type: 'object' },
    run: async (args: unknown) => {
      const call: ToolCall = {
        id: randomUUID(),
        name: spec.name,
        input: (args ?? {}) as Record<string, unknown>,
      };
      onToolCall?.(call);
      try {
        const result = await spec.handler(call.input);
        onToolResult?.(call, result);
        return typeof result === 'string' ? result : JSON.stringify(result ?? null);
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        onToolResult?.(call, { error: message });
        return JSON.stringify({ error: message });
      }
    },
  });
}
