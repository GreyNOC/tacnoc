/**
 * The read-only TACNOC tool registry exposed over MCP.
 *
 * Scope of this file, deliberately: **every tool here is offline and pure.** No
 * tool opens a project, touches the SQLite store, reads a secret, or emits a
 * single packet. That is not a limitation to be lifted casually — it is what
 * makes the server safe to expose to an agent:
 *
 *   - Nothing here can breach an engagement's rules of engagement, because
 *     nothing here can reach a target.
 *   - Nothing here needs the CA key or the per-project data key, so the server
 *     runs as plain Node with no Electron `safeStorage` dependency.
 *   - Nothing here writes, so it cannot race the desktop app for the project
 *     database.
 *
 * If a traffic-generating tool (Repeater, Variation) is ever added, it inherits
 * NONE of the above and must additionally re-implement the per-run request
 * budget, the audit record, and the abort check that live in
 * `engine/ai/orchestrator.ts` (`wrapActive`) — the tool handlers themselves do
 * not carry them. See `docs/mcp-server.md`.
 */

import { inspectJwt, applyTransform, BUILTIN_TRANSFORMS } from '../engine/transforms/codec.js';
import { diffLines, diffJson, diffBytes } from '../engine/compare/compare.js';
import { analyzeTokenSamples } from '../engine/analysis/sequencer.js';
import { evaluateScope, targetFromUrl } from '../engine/scope/scope.js';
import type { TokenEncoding } from '../shared/sequencer.js';
import type { ScopeConfig, ScopeRule, HostMatchKind } from '../shared/scope.js';
import type { Scheme } from '../shared/model.js';
import type { McpTool } from './protocol.js';

/** Cap on any single text input. Guards against a pathological payload turning
 *  a pure function into a memory problem; well above any real hunting input. */
const MAX_INPUT_CHARS = 2_000_000;

const TOKEN_ENCODINGS: readonly TokenEncoding[] = ['text', 'hex', 'base64', 'base64url'];
const HOST_MATCH_KINDS: readonly HostMatchKind[] = ['exact', 'subdomain', 'wildcard'];

function str(input: Record<string, unknown>, key: string, required = true): string {
  const value = input[key];
  if (value === undefined || value === null) {
    if (required) throw new Error(`"${key}" is required`);
    return '';
  }
  if (typeof value !== 'string') throw new Error(`"${key}" must be a string`);
  if (value.length > MAX_INPUT_CHARS) {
    throw new Error(
      `"${key}" is ${value.length.toLocaleString()} characters; the limit is ${MAX_INPUT_CHARS.toLocaleString()}.`,
    );
  }
  return value;
}

function strArray(input: Record<string, unknown>, key: string): string[] {
  const value = input[key];
  if (!Array.isArray(value)) throw new Error(`"${key}" must be an array of strings`);
  return value.map((item, i) => {
    if (typeof item !== 'string') throw new Error(`"${key}"[${i}] must be a string`);
    return item;
  });
}

/**
 * Fill in a partial scope rule.
 *
 * Defaults are chosen to be NARROWER than the caller might expect: an
 * unspecified `hostMatch` becomes `exact` (or `wildcard` when the host contains
 * a `*`), never `subdomain`. Scope decides what may be touched, so when the
 * input is ambiguous the answer should under-claim, not over-claim.
 */
function normalizeRule(raw: unknown, index: number, kind: 'include' | 'exclude'): ScopeRule {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new Error(`scope.${kind}[${index}] must be an object`);
  }
  const r = raw as Record<string, unknown>;
  const host = typeof r['host'] === 'string' ? r['host'] : '';
  if (!host) throw new Error(`scope.${kind}[${index}].host is required`);

  const declared = r['hostMatch'];
  const hostMatch: HostMatchKind =
    typeof declared === 'string' && (HOST_MATCH_KINDS as readonly string[]).includes(declared)
      ? (declared as HostMatchKind)
      : host.includes('*')
        ? 'wildcard'
        : 'exact';

  const schemes = Array.isArray(r['schemes'])
    ? (r['schemes'].filter((s) => s === 'http' || s === 'https') as Scheme[])
    : [];
  const ports = Array.isArray(r['ports'])
    ? r['ports'].filter((p): p is number => typeof p === 'number' && Number.isFinite(p))
    : [];

  const rule: ScopeRule = {
    id: typeof r['id'] === 'string' && r['id'] ? r['id'] : `${kind}-${index + 1}`,
    enabled: r['enabled'] !== false,
    hostMatch,
    host,
    schemes,
    ports,
  };
  if (typeof r['label'] === 'string') rule.label = r['label'];

  const path = r['path'];
  if (path && typeof path === 'object' && !Array.isArray(path)) {
    const p = path as Record<string, unknown>;
    if (typeof p['value'] === 'string') {
      rule.path = { kind: p['kind'] === 'regex' ? 'regex' : 'prefix', value: p['value'] };
    }
  }
  return rule;
}

function normalizeScope(raw: unknown): ScopeConfig {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new Error('"scope" must be an object with "include" and optional "exclude" arrays');
  }
  const s = raw as Record<string, unknown>;
  const include = Array.isArray(s['include']) ? s['include'] : [];
  const exclude = Array.isArray(s['exclude']) ? s['exclude'] : [];
  return {
    include: include.map((r, i) => normalizeRule(r, i, 'include')),
    exclude: exclude.map((r, i) => normalizeRule(r, i, 'exclude')),
  };
}

const OBJECT = (
  properties: Record<string, unknown>,
  required: string[] = [],
): Record<string, unknown> => ({
  type: 'object',
  properties,
  ...(required.length ? { required } : {}),
  additionalProperties: false,
});

const SCOPE_RULE_SCHEMA = {
  type: 'object',
  properties: {
    host: { type: 'string', description: 'Host pattern, e.g. "example.com" or "*.example.com".' },
    hostMatch: {
      enum: ['exact', 'subdomain', 'wildcard'],
      description:
        'How the host matches. Defaults to "wildcard" when host contains "*", otherwise "exact" — deliberately narrow.',
    },
    schemes: {
      type: 'array',
      items: { enum: ['http', 'https'] },
      description: 'Allowed schemes; omit or leave empty for any.',
    },
    ports: {
      type: 'array',
      items: { type: 'number' },
      description: 'Allowed ports; omit or leave empty for any.',
    },
    path: {
      type: 'object',
      description: 'Optional path matcher: {kind:"prefix"|"regex", value:string}.',
    },
    enabled: { type: 'boolean', description: 'Defaults to true.' },
    label: { type: 'string' },
    id: { type: 'string' },
  },
  required: ['host'],
  additionalProperties: false,
};

/**
 * Build the registry. Pure and dependency-free, so tests can call this directly
 * without a transport.
 */
export function buildReadOnlyTools(): McpTool[] {
  return [
    {
      name: 'inspect_jwt',
      description:
        'Decode a JWT and report its header, payload claims, signature presence, and expiry state. DECODE ONLY — it never verifies a signature and never claims a token is valid. Offline; sends no traffic. Use when triaging session or reset tokens (ATO class C-ATO-3).',
      inputSchema: OBJECT(
        { token: { type: 'string', description: 'The raw JWT, dot-separated.' } },
        ['token'],
      ),
      handler: (input) => inspectJwt(str(input, 'token')),
    },

    {
      name: 'analyze_tokens',
      description:
        'Statistically screen a set of captured tokens (session ids, reset tokens, nonces) for predictability: duplicate collisions, byte and per-position entropy, monobit bias, adjacent-byte correlation, and compressibility. Offline; sends no traffic. The assessment is intentionally cautious — it can show a generator is WEAK, but never proves one is cryptographically secure.',
      inputSchema: OBJECT(
        {
          samples: {
            type: 'array',
            items: { type: 'string' },
            description: 'Token samples, one per entry. More samples give a sharper result.',
          },
          encoding: {
            enum: ['text', 'hex', 'base64', 'base64url'],
            description: 'How to decode each sample to bytes. Defaults to "text".',
          },
        },
        ['samples'],
      ),
      handler: (input) => {
        const samples = strArray(input, 'samples');
        const raw = input['encoding'];
        const encoding: TokenEncoding =
          typeof raw === 'string' && (TOKEN_ENCODINGS as readonly string[]).includes(raw)
            ? (raw as TokenEncoding)
            : 'text';
        return analyzeTokenSamples(samples, encoding);
      },
    },

    {
      name: 'list_transforms',
      description:
        'List the available encode/decode/hash/timestamp transforms and their ids, for use with apply_transform. Offline.',
      inputSchema: OBJECT({}),
      handler: () =>
        BUILTIN_TRANSFORMS.map((t) => ({ id: t.id, label: t.label, category: t.category })),
    },

    {
      name: 'apply_transform',
      description:
        'Apply one named transform to a string — URL/Base64/Base64url/hex/HTML encode and decode, gzip and gunzip, MD5/SHA-1/SHA-256/SHA-512 hashing, and epoch/ISO timestamp conversion. Call list_transforms for the ids. Offline; sends no traffic.',
      inputSchema: OBJECT(
        {
          id: { type: 'string', description: 'Transform id from list_transforms.' },
          input: { type: 'string', description: 'The text to transform.' },
        },
        ['id', 'input'],
      ),
      handler: (input) => {
        const id = str(input, 'id');
        const text = str(input, 'input', false);
        return { id, output: applyTransform(id, text) };
      },
    },

    {
      name: 'diff_text',
      description:
        'Line-level diff of two texts, returning the changed lines with their kind. Offline. Built for state-differential work: compare two responses that should differ only by the one variable you changed.',
      inputSchema: OBJECT({ a: { type: 'string' }, b: { type: 'string' } }, ['a', 'b']),
      handler: (input) => diffLines(str(input, 'a', false), str(input, 'b', false)),
    },

    {
      name: 'diff_json',
      description:
        'Structure-aware diff of two JSON documents, reporting added, removed, and changed paths rather than line noise. Offline. Use on API responses where key order or formatting differs but structure is what matters.',
      inputSchema: OBJECT(
        {
          a: { type: 'string', description: 'JSON text.' },
          b: { type: 'string', description: 'JSON text.' },
        },
        ['a', 'b'],
      ),
      handler: (input) => diffJson(str(input, 'a', false), str(input, 'b', false)),
    },

    {
      name: 'diff_bytes',
      description:
        'Byte-level diff of two base64-encoded blobs: first difference offset, common prefix and suffix length, and equality. Offline. Use when a text diff would hide whitespace, encoding, or padding differences.',
      inputSchema: OBJECT(
        {
          a_base64: { type: 'string', description: 'First blob, base64-encoded.' },
          b_base64: { type: 'string', description: 'Second blob, base64-encoded.' },
        },
        ['a_base64', 'b_base64'],
      ),
      handler: (input) =>
        diffBytes(
          Buffer.from(str(input, 'a_base64', false), 'base64'),
          Buffer.from(str(input, 'b_base64', false), 'base64'),
        ),
    },

    {
      name: 'evaluate_scope',
      description:
        "Decide whether a URL falls inside an engagement's authorized scope, using TACNOC's own fail-closed scope evaluator — the same logic the engine gates automated traffic on. Offline; sends no traffic and does not resolve the host. Returns the matching include rule or the exclude rule that vetoed. With no include rules, NOTHING is in scope, by design.",
      inputSchema: OBJECT(
        {
          url: { type: 'string', description: 'Absolute http(s) URL to test.' },
          scope: {
            type: 'object',
            description:
              'Scope definition. A destination is in scope iff it matches an enabled include rule AND no enabled exclude rule.',
            properties: {
              include: { type: 'array', items: SCOPE_RULE_SCHEMA },
              exclude: { type: 'array', items: SCOPE_RULE_SCHEMA },
            },
            additionalProperties: false,
          },
        },
        ['url', 'scope'],
      ),
      handler: (input) => {
        const url = str(input, 'url');
        const scope = normalizeScope(input['scope']);
        const target = targetFromUrl(url);
        if (!target) {
          return {
            inScope: false,
            reason: 'unparseable URL, or a scheme other than http/https',
            url,
          };
        }
        return { url, target, ...evaluateScope(scope, target), normalizedScope: scope };
      },
    },
  ];
}
