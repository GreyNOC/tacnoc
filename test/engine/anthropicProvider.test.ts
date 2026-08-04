/**
 * The real AnthropicProvider, driven against a local server that speaks the
 * Anthropic SSE wire format.
 *
 * This exists because the mesh tests all use a fake provider, so nothing
 * exercised the actual SDK call — and the defect this covers was invisible to
 * them: with a large `max_tokens`, a NON-streaming request is refused by the SDK
 * before it sends anything ("Streaming is required for operations that may take
 * longer than 10 minutes"), killing the turn with no output. A green suite said
 * the mesh worked while every real planner turn died.
 *
 * No API key and no network: the provider is pointed at 127.0.0.1.
 */

import { describe, expect, it, beforeEach, afterEach } from 'vitest';
import * as http from 'node:http';
import type { AddressInfo } from 'node:net';
import { AnthropicProvider } from '../../src/engine/ai/providers/anthropic.js';

let server: http.Server;
let baseUrl = '';
let lastBody: Record<string, unknown> = {};
let lastAccept = '';

/** One assistant turn, as the API would stream it. */
const SSE = [
  'event: message_start',
  'data: {"type":"message_start","message":{"id":"msg_1","type":"message","role":"assistant","model":"claude-opus-5","content":[],"stop_reason":null,"stop_sequence":null,"usage":{"input_tokens":11,"output_tokens":0,"cache_read_input_tokens":3,"cache_creation_input_tokens":2}}}',
  '',
  'event: content_block_start',
  'data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}',
  '',
  'event: content_block_delta',
  'data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"in "}}',
  '',
  'event: content_block_delta',
  'data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"pieces"}}',
  '',
  'event: content_block_stop',
  'data: {"type":"content_block_stop","index":0}',
  '',
  'event: message_delta',
  'data: {"type":"message_delta","delta":{"stop_reason":"end_turn","stop_sequence":null},"usage":{"output_tokens":7}}',
  '',
  'event: message_stop',
  'data: {"type":"message_stop"}',
  '',
  '',
].join('\n');

beforeEach(async () => {
  server = http.createServer((req, res) => {
    let raw = '';
    req.on('data', (c) => (raw += c));
    req.on('end', () => {
      lastBody = raw ? (JSON.parse(raw) as Record<string, unknown>) : {};
      lastAccept = String(req.headers.accept ?? '');
      res.writeHead(200, {
        'content-type': 'text/event-stream',
        'cache-control': 'no-cache',
      });
      res.end(SSE);
    });
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  baseUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

afterEach(async () => {
  await new Promise<void>((r) => server.close(() => r()));
});

const run = (maxTokens?: number) => {
  const provider = new AnthropicProvider({
    apiKey: 'sk-ant-not-a-real-key',
    baseUrl,
    ...(maxTokens !== undefined ? { defaultMaxTokens: maxTokens } : {}),
  });
  const chunks: string[] = [];
  return provider
    .runAgent({
      model: 'claude-opus-5',
      system: 'You are a test.',
      messages: [{ role: 'user', content: 'go' }],
      tools: [],
      effort: 'xhigh',
      onText: (t) => chunks.push(t),
    })
    .then((result) => ({ result, chunks }));
};

describe('the real provider talks to the API', () => {
  it('streams — the request the SDK would otherwise refuse outright', async () => {
    await run();
    // The bug was the absence of this flag. Assert it on the wire, not on our
    // own local variable. (The SDK sends `Accept: application/json` either way —
    // the body flag is what selects streaming, so that is what to check.)
    expect(lastBody.stream).toBe(true);
    expect(lastAccept).toBe('application/json');
  });

  it('gives the output budget room instead of capping it to dodge a timeout', async () => {
    await run();
    // At xhigh effort adaptive thinking takes a large share of the budget; a
    // small cap returns a truncated answer and burns the turn.
    expect(Number(lastBody.max_tokens)).toBeGreaterThanOrEqual(64000);
  });

  it('assembles the streamed text and reports it as the turn result', async () => {
    const { result } = await run();
    expect(result.text).toBe('in pieces');
    expect(result.stopReason).toBe('end_turn');
  });

  it('delivers text as it arrives rather than in one lump at the end', async () => {
    const { chunks } = await run();
    expect(chunks).toEqual(['in ', 'pieces']);
  });

  it('counts tokens across every usage field, including cache reads', async () => {
    const { result } = await run();
    expect(result.tokens.input).toBe(16); // 11 + 3 cache-read + 2 cache-write
    expect(result.tokens.output).toBe(7);
  });

  it('sends the effort hint the agentic roles depend on', async () => {
    await run();
    expect(lastBody.output_config).toMatchObject({ effort: 'xhigh' });
    expect(lastBody.thinking).toMatchObject({ type: 'adaptive' });
  });
});
