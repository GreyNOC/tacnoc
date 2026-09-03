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
import type {
  AgentTurnOptions,
  AgentTurnResult,
  LlmProvider,
  ProviderCheck,
  ToolCall,
} from '../provider.js';
import type { ToolSpec } from '../tools.js';

/**
 * Models that accept `thinking: {type: 'adaptive'}`.
 *
 * Getting this list WRONG in the omitting direction is silent and expensive: on
 * the 4.6 generation, leaving `thinking` off means the model does not reason at
 * all. `claude-sonnet-4-6` was in the effort list but missing here, so choosing
 * it for a role sent `output_config.effort: xhigh` to a model running with
 * thinking disabled — the operator set the single largest quality lever this app
 * has and got a non-reasoning turn, with nothing anywhere saying so.
 *
 * Fable and Mythos are listed explicitly rather than relying on
 * `claude-fable-5-1` happening to prefix-match `claude-fable-5`. Their thinking
 * is always on and an explicit `disabled` is rejected, so sending adaptive is
 * both correct and a no-op — but coverage should be stated, not incidental.
 */
const ADAPTIVE_THINKING = [
  'claude-fable-5',
  'claude-mythos-5',
  'claude-opus-5',
  'claude-opus-4-8',
  'claude-opus-4-7',
  'claude-opus-4-6',
  'claude-sonnet-5',
  'claude-sonnet-4-6',
];

/** Models accepting `output_config.task_budget` (with the beta header below). */
const TASK_BUDGET = [
  'claude-fable-5',
  'claude-opus-5',
  'claude-opus-4-8',
  'claude-opus-4-7',
  'claude-sonnet-5',
];

/**
 * Models accepting `output_config.effort`. Effort is the single largest quality
 * lever for this workload: agentic tool-use benefits materially from `xhigh`,
 * where the model reads more evidence before deciding what to probe.
 */
const EFFORT = [
  'claude-fable-5',
  'claude-mythos-5',
  'claude-opus-5',
  'claude-opus-4-8',
  'claude-opus-4-7',
  'claude-opus-4-6',
  'claude-sonnet-5',
  'claude-sonnet-4-6',
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

  /**
   * Check the credentials and the model id WITHOUT starting a run.
   *
   * Uses `count_tokens`, which authenticates and resolves the model but
   * generates nothing — so it costs no output tokens and cannot touch the
   * target. The failure it prevents is expensive and badly-timed: without it a
   * wrong key or a mistyped model id surfaces partway through a live run, after
   * the mesh has spent tokens and possibly already sent traffic, as an SDK
   * string in an error box that does not say which of the two is wrong.
   */
  async verify(model: string): Promise<ProviderCheck> {
    try {
      const counted = await this.client.messages.countTokens({
        model,
        messages: [{ role: 'user', content: 'ping' }],
      });
      return {
        ok: true,
        model,
        detail: `Reached the Anthropic API and resolved "${model}" (token counting returned ${counted.input_tokens}). The key and the model id are both good.`,
      };
    } catch (err) {
      const described = describeApiError(err, model);
      return {
        ok: false,
        model,
        detail: described.detail,
        ...(described.remedy ? { remedy: described.remedy } : {}),
      };
    }
  }

  async runAgent(options: AgentTurnOptions): Promise<AgentTurnResult> {
    try {
      return await this.runAgentInner(options);
    } catch (err) {
      // An aborted turn is the operator's own stop, not a fault — let it through
      // untouched so the orchestrator reports "stopped" rather than an error.
      if (err instanceof Anthropic.APIUserAbortError) throw err;
      // Everything else becomes a sentence that says what to fix. The raw SDK
      // message reaches the operator inside a mesh error box with no context,
      // and "401 {"type":"error"...}" does not tell them the key is wrong.
      const { detail, remedy } = describeApiError(err, options.model);
      throw new Error(remedy ? `${detail} ${remedy}` : detail);
    }
  }

  private async runAgentInner(options: AgentTurnOptions): Promise<AgentTurnResult> {
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

/**
 * Turn an SDK failure into something an operator can act on.
 *
 * Ordered most-specific first. Every branch names the ONE thing to change,
 * because the four common failures here (wrong key, no credit, wrong model id,
 * no network) are indistinguishable from each other in the raw message and lead
 * to completely different fixes.
 */
function describeApiError(err: unknown, model: string): { detail: string; remedy?: string } {
  if (err instanceof Anthropic.AuthenticationError) {
    return {
      detail: 'The Anthropic API rejected the API key (401).',
      remedy: 'Check the key in AI Mesh → Anthropic API key, then save it again.',
    };
  }
  if (err instanceof Anthropic.PermissionDeniedError) {
    return {
      detail: `The API key is valid but is not permitted to use "${model}" (403).`,
      remedy: 'Check the model access and billing on the account this key belongs to.',
    };
  }
  if (err instanceof Anthropic.NotFoundError) {
    return {
      detail: `The Anthropic API does not recognise the model id "${model}" (404).`,
      remedy: 'Correct the model id for this role in AI Mesh → Mesh settings.',
    };
  }
  if (err instanceof Anthropic.RateLimitError) {
    return {
      detail:
        'The Anthropic API rate limit was exceeded and the built-in retries did not clear it (429).',
      remedy: 'Wait for the limit to reset, or lower the role effort, and run again.',
    };
  }
  if (err instanceof Anthropic.BadRequestError) {
    // The likeliest cause here is a capability mismatch — a parameter this model
    // does not accept — so say that rather than only echoing the API.
    return {
      detail: `The Anthropic API refused the request for "${model}" as invalid (400): ${err.message}`,
      remedy:
        'This usually means the model id does not accept a parameter this role sends. Check the model id, or pick a current model.',
    };
  }
  if (err instanceof Anthropic.APIConnectionError) {
    return {
      detail: 'Could not reach the Anthropic API (network error).',
      remedy: 'Check connectivity and any proxy or base-URL override in the AI settings.',
    };
  }
  if (err instanceof Anthropic.InternalServerError) {
    return {
      detail: `The Anthropic API returned a server error (${err.status ?? '5xx'}).`,
      remedy: 'This is upstream and usually transient — try again shortly.',
    };
  }
  if (err instanceof Anthropic.APIError) {
    return {
      detail: `The Anthropic API call failed (${err.status ?? 'no status'}): ${err.message}`,
    };
  }
  return { detail: err instanceof Error ? err.message : String(err) };
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
