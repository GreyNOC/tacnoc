/**
 * Tests for the MCP server: JSON-RPC framing, the read-only tool contract, and
 * the scope evaluator's fail-closed behaviour as exposed to an agent.
 *
 * The most load-bearing test here is `exposes only offline, read-only tools`.
 * It is not a formality: the tool handlers do NOT carry the per-run request
 * budget, audit record, or abort check (those live in the AI orchestrator's
 * `wrapActive`). If someone adds a traffic-generating tool to this registry,
 * that test fails and forces the gap to be dealt with deliberately rather than
 * discovered on a live engagement.
 */

import { describe, it, expect } from 'vitest';
import { PassThrough } from 'node:stream';
import { McpServer, renderResult, type McpTool } from '../../src/mcp/protocol.js';
import { buildReadOnlyTools } from '../../src/mcp/tools.js';

const EXPECTED_TOOLS = [
  'inspect_jwt',
  'analyze_tokens',
  'list_transforms',
  'apply_transform',
  'diff_text',
  'diff_json',
  'diff_bytes',
  'evaluate_scope',
].sort();

type JsonValue = string | number | boolean | null | JsonValue[] | { [key: string]: JsonValue };

interface RpcResponse {
  jsonrpc: string;
  id: string | number | null;
  result?: Record<string, JsonValue>;
  error?: { code: number; message: string };
}

interface ToolOutcome {
  isError: boolean;
  text: string;
  json: JsonValue;
}

function server(tools: readonly McpTool[] = buildReadOnlyTools()): McpServer {
  return new McpServer('tacnoc', '0.0.0-test', tools);
}

async function request(
  msg: Record<string, unknown>,
  tools?: readonly McpTool[],
): Promise<RpcResponse> {
  const res = await server(tools ?? buildReadOnlyTools()).handle(msg);
  if (res === null) throw new Error('expected a response, but the server stayed silent');
  return res as unknown as RpcResponse;
}

/**
 * Read a dotted path out of a decoded JSON value; numeric segments index arrays.
 * Keeps assertions readable without reaching for `any` (the repo lints at zero
 * warnings, and `no-explicit-any` is on).
 */
function at(value: unknown, path: string): JsonValue {
  let cursor: unknown = value;
  for (const key of path.split('.')) {
    if (Array.isArray(cursor)) {
      cursor = cursor[Number(key)];
    } else if (cursor !== null && typeof cursor === 'object') {
      cursor = (cursor as Record<string, unknown>)[key];
    } else {
      throw new Error(`path "${path}" is unreachable: "${key}" has no container`);
    }
  }
  return cursor as JsonValue;
}

function arr(value: unknown): JsonValue[] {
  if (!Array.isArray(value)) throw new Error(`expected an array, got ${typeof value}`);
  return value as JsonValue[];
}

function safeParse(text: string): JsonValue {
  try {
    return JSON.parse(text) as JsonValue;
  } catch {
    return null;
  }
}

/** Call a tool and decode its rendered result. */
async function call(name: string, args: Record<string, unknown>): Promise<ToolOutcome> {
  const res = await request({
    jsonrpc: '2.0',
    id: 1,
    method: 'tools/call',
    params: { name, arguments: args },
  });
  const text = String(at(res, 'result.content.0.text') ?? '');
  return { isError: res.result?.['isError'] === true, text, json: safeParse(text) };
}

describe('MCP protocol', () => {
  it('echoes the client protocol version and identifies itself', async () => {
    const res = await request({
      jsonrpc: '2.0',
      id: 1,
      method: 'initialize',
      params: { protocolVersion: '2024-11-05' },
    });
    expect(res.result?.['protocolVersion']).toBe('2024-11-05');
    expect(at(res, 'result.serverInfo.name')).toBe('tacnoc');
    expect(at(res, 'result.capabilities.tools')).toBeDefined();
  });

  it('falls back to a default protocol version when the client omits one', async () => {
    const res = await request({ jsonrpc: '2.0', id: 1, method: 'initialize' });
    const version = res.result?.['protocolVersion'];
    expect(typeof version).toBe('string');
    expect(String(version).length).toBeGreaterThan(0);
  });

  it('never answers a notification (a message with no id)', async () => {
    expect(
      await server().handle({ jsonrpc: '2.0', method: 'notifications/initialized' }),
    ).toBeNull();
    // An unknown notification is ignored too — it must not produce an error frame.
    expect(await server().handle({ jsonrpc: '2.0', method: 'notifications/whatever' })).toBeNull();
  });

  it('returns method-not-found for an unknown request', async () => {
    const res = await request({ jsonrpc: '2.0', id: 9, method: 'nope' });
    expect(res.error?.code).toBe(-32601);
  });

  it('returns method-not-found for an unknown tool', async () => {
    const res = await request({
      jsonrpc: '2.0',
      id: 3,
      method: 'tools/call',
      params: { name: 'rm_rf', arguments: {} },
    });
    expect(res.error?.code).toBe(-32601);
  });

  it('reports a failing tool as an error RESULT, not a transport error', async () => {
    const boom: McpTool = {
      name: 'boom',
      description: 'always throws',
      inputSchema: { type: 'object' },
      handler: () => {
        throw new Error('kaboom');
      },
    };
    const res = await request(
      { jsonrpc: '2.0', id: 4, method: 'tools/call', params: { name: 'boom', arguments: {} } },
      [boom],
    );
    // The model must be able to READ the failure and adapt.
    expect(res.error).toBeUndefined();
    expect(res.result?.['isError']).toBe(true);
    expect(String(at(res, 'result.content.0.text'))).toContain('kaboom');
  });

  it('rejects duplicate tool names at construction', () => {
    const dup: McpTool = {
      name: 'same',
      description: 'x',
      inputSchema: { type: 'object' },
      handler: () => null,
    };
    expect(() => server([dup, { ...dup }])).toThrow(/duplicate/i);
  });

  it('truncates an oversized result instead of flooding the caller', () => {
    const rendered = renderResult('x'.repeat(250_000));
    expect(rendered.length).toBeLessThan(150_000);
    expect(rendered).toContain('truncated');
  });

  it('serves newline-delimited JSON-RPC over a stream and survives bad input', async () => {
    const input = new PassThrough();
    const output = new PassThrough();
    const chunks: string[] = [];
    output.on('data', (c: Buffer) => chunks.push(c.toString('utf8')));

    const done = server().serve(input, output);
    input.write('{"jsonrpc":"2.0","id":1,"method":"tools/list"}\n');
    input.write('this is not json\n');
    input.write('{"jsonrpc":"2.0","method":"notifications/initialized"}\n');
    input.write('{"jsonrpc":"2.0","id":2,"method":"ping"}\n');
    input.end();
    await done;

    const frames = chunks
      .join('')
      .trim()
      .split('\n')
      .map((line) => JSON.parse(line) as RpcResponse);

    // Three frames: tools/list, the parse error, ping. The notification gets none.
    expect(frames).toHaveLength(3);
    expect(arr(at(frames[0] ?? null, 'result.tools'))).toHaveLength(EXPECTED_TOOLS.length);
    expect(frames[1]?.error?.code).toBe(-32700);
    expect(frames[1]?.id).toBeNull();
    expect(frames[2]?.id).toBe(2);
  });
});

describe('tool registry contract', () => {
  it('exposes only offline, read-only tools', () => {
    // See the file header: adding a traffic-generating tool here bypasses the
    // request budget, audit trail, and abort check that live in the AI
    // orchestrator. Update those FIRST, then this list.
    expect(
      buildReadOnlyTools()
        .map((t) => t.name)
        .sort(),
    ).toEqual(EXPECTED_TOOLS);
  });

  it('gives every tool a description and an object input schema', () => {
    for (const tool of buildReadOnlyTools()) {
      expect(tool.description.length).toBeGreaterThan(30);
      expect(tool.inputSchema['type']).toBe('object');
    }
  });
});

describe('evaluate_scope', () => {
  it('fails closed when no include rule is defined', async () => {
    const r = await call('evaluate_scope', {
      url: 'https://api.example.com/',
      scope: { include: [] },
    });
    expect(at(r.json, 'inScope')).toBe(false);
  });

  it('admits a host matched by a wildcard include rule', async () => {
    const r = await call('evaluate_scope', {
      url: 'https://api.example.com/v1/users',
      scope: { include: [{ host: '*.example.com' }] },
    });
    expect(at(r.json, 'inScope')).toBe(true);
  });

  it('defaults an unstarred host to an EXACT match, not a subdomain match', async () => {
    // The narrow default is deliberate: an ambiguous scope must under-claim.
    const r = await call('evaluate_scope', {
      url: 'https://api.example.com/',
      scope: { include: [{ host: 'example.com' }] },
    });
    expect(at(r.json, 'normalizedScope.include.0.hostMatch')).toBe('exact');
    expect(at(r.json, 'inScope')).toBe(false);
  });

  it('lets an exclude rule veto an included host by path', async () => {
    const scope = {
      include: [{ host: '*.example.com' }],
      exclude: [{ host: 'api.example.com', path: { kind: 'prefix', value: '/admin' } }],
    };
    const allowed = await call('evaluate_scope', {
      url: 'https://api.example.com/v1/users',
      scope,
    });
    const vetoed = await call('evaluate_scope', { url: 'https://api.example.com/admin/x', scope });
    expect(at(allowed.json, 'inScope')).toBe(true);
    expect(at(vetoed.json, 'inScope')).toBe(false);
  });

  it('refuses a non-http scheme rather than guessing', async () => {
    const r = await call('evaluate_scope', {
      url: 'file:///etc/passwd',
      scope: { include: [{ host: '*' }] },
    });
    expect(at(r.json, 'inScope')).toBe(false);
  });

  it('rejects a scope whose rule has no host', async () => {
    const r = await call('evaluate_scope', {
      url: 'https://a.example.com/',
      scope: { include: [{ hostMatch: 'subdomain' }] },
    });
    expect(r.isError).toBe(true);
    expect(r.text).toMatch(/host is required/);
  });
});

describe('analysis tools', () => {
  it('decodes a JWT without asserting the signature is valid', async () => {
    const jwt =
      'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
    const r = await call('inspect_jwt', { token: jwt });
    expect(at(r.json, 'header.alg')).toBe('HS256');
    expect(at(r.json, 'payload.sub')).toBe('1234567890');
    // Decode-only: nothing in the output may claim verification happened.
    expect(r.text.toLowerCase()).not.toMatch(/signature (is )?valid|verified: ?true/);
  });

  it('handles a malformed JWT without throwing', async () => {
    const r = await call('inspect_jwt', { token: 'not-a-jwt' });
    expect(r.isError).toBe(false);
  });

  it('rates predictable tokens as poor', async () => {
    const weak: string[] = [];
    for (let i = 1; i <= 160; i++) {
      weak.push(Buffer.from(`SESSIONID-acct-${String(i).padStart(6, '0')}`).toString('hex'));
    }
    const r = await call('analyze_tokens', { samples: weak, encoding: 'hex' });
    expect(at(r.json, 'assessment')).toBe('poor');
    expect(arr(at(r.json, 'observations')).length).toBeGreaterThan(1);
  });

  it('does not rate high-entropy tokens as poor', async () => {
    // Distinguishes a real signal from the analyzer simply always saying "poor".
    const strong: string[] = [];
    for (let i = 0; i < 160; i++) {
      const bytes = Buffer.alloc(24);
      for (let k = 0; k < bytes.length; k++) {
        // Deterministic but well-mixed, so the test cannot flake on entropy.
        bytes[k] = (Math.imul(i + 1, 2654435761) >>> ((k % 4) * 8)) ^ (k * 167 + 89);
      }
      strong.push(bytes.toString('hex'));
    }
    const r = await call('analyze_tokens', { samples: strong, encoding: 'hex' });
    expect(at(r.json, 'sampleCount')).toBe(160);
    expect(at(r.json, 'assessment')).not.toBe('poor');
  });

  it('rejects an unknown transform id', async () => {
    const r = await call('apply_transform', { id: 'base64-decode', input: 'x' });
    expect(r.isError).toBe(true);
    expect(r.text).toMatch(/unknown transform/);
  });

  it('round-trips a value through the real transform ids', async () => {
    const encoded = await call('apply_transform', { id: 'base64.encode', input: 'GNBB-CANARY' });
    const decoded = await call('apply_transform', {
      id: 'base64.decode',
      input: at(encoded.json, 'output'),
    });
    expect(at(decoded.json, 'output')).toBe('GNBB-CANARY');
  });

  it('diffs JSON structurally rather than by line', async () => {
    const r = await call('diff_json', {
      a: '{"role":"user","id":7}',
      b: '{"id":7,"role":"admin"}',
    });
    const changed = arr(r.json).filter((entry) => at(entry, 'kind') === 'changed');
    expect(changed).toHaveLength(1);
    expect(String(at(changed[0] ?? null, 'path'))).toContain('role');
  });

  it('reports byte-level equality', async () => {
    const a = Buffer.from('GNBB-CANARY-A').toString('base64');
    const b = Buffer.from('GNBB-CANARY-B').toString('base64');
    const same = await call('diff_bytes', { a_base64: a, b_base64: a });
    const diff = await call('diff_bytes', { a_base64: a, b_base64: b });
    expect(at(same.json, 'equal')).toBe(true);
    expect(at(diff.json, 'equal')).toBe(false);
  });

  it('enforces the input size cap', async () => {
    const r = await call('inspect_jwt', { token: 'x'.repeat(2_000_001) });
    expect(r.isError).toBe(true);
    expect(r.text).toMatch(/limit is/);
  });
});
