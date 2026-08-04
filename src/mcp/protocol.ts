/**
 * Minimal MCP (Model Context Protocol) server core — JSON-RPC 2.0 over stdio.
 *
 * Hand-rolled rather than depending on `@modelcontextprotocol/sdk` on purpose:
 * TACNOC ships three runtime dependencies and a published SBOM, and for a
 * security research tool the dependency surface is part of the threat model.
 * The stdio transport is newline-delimited JSON-RPC and the surface we need is
 * four methods, so the SDK would add more supply-chain surface than it saves.
 *
 * Transport invariant: **stdout carries JSON-RPC frames and nothing else.** A
 * stray write (a banner, a console.log, a dependency's deprecation notice)
 * corrupts the stream and the client drops the connection. All diagnostics go
 * to stderr; `log()` below is the only sanctioned way to emit one.
 */

/** Protocol revision we implement. Clients that ask for another are echoed back
 *  their own version — every revision so far is wire-compatible for the tool
 *  subset used here, and echoing avoids a spurious version negotiation failure. */
const DEFAULT_PROTOCOL_VERSION = '2025-06-18';

const JSONRPC_VERSION = '2.0';

/** JSON-RPC reserved error codes (see the JSON-RPC 2.0 spec, §5.1). */
const ERR_PARSE = -32700;
const ERR_INVALID_REQUEST = -32600;
const ERR_METHOD_NOT_FOUND = -32601;
const ERR_INTERNAL = -32603;

/**
 * Hard ceiling on a single tool result, in characters. An unbounded result (a
 * byte diff of two large bodies, a target map) would flood the caller's context
 * window and is never what the operator wanted. We truncate with a visible
 * marker rather than silently sending a partial document.
 */
const MAX_RESULT_CHARS = 100_000;

export interface McpTool {
  name: string;
  description: string;
  /** JSON Schema (object) describing the tool input. */
  inputSchema: Record<string, unknown>;
  handler: (input: Record<string, unknown>) => Promise<unknown> | unknown;
}

type RpcId = string | number | null;

interface RpcMessage {
  jsonrpc?: unknown;
  id?: RpcId;
  method?: unknown;
  params?: unknown;
}

/** Write a diagnostic line. stderr only — see the transport invariant above. */
export function log(message: string): void {
  process.stderr.write(`[tacnoc-mcp] ${message}\n`);
}

/** Serialize a tool result, truncating rather than flooding the caller. */
export function renderResult(value: unknown): string {
  let text: string;
  if (typeof value === 'string') {
    text = value;
  } else {
    try {
      text = JSON.stringify(value, null, 2) ?? String(value);
    } catch {
      // Circular or otherwise unserializable — report it instead of throwing,
      // so one bad result can't take the server down.
      text = String(value);
    }
  }
  if (text.length <= MAX_RESULT_CHARS) return text;
  const omitted = text.length - MAX_RESULT_CHARS;
  return (
    text.slice(0, MAX_RESULT_CHARS) +
    `\n\n… [truncated: ${omitted.toLocaleString()} more characters omitted. ` +
    `Narrow the input — e.g. fewer samples, a smaller slice — for a complete result.]`
  );
}

export class McpServer {
  private readonly tools = new Map<string, McpTool>();

  constructor(
    private readonly name: string,
    private readonly version: string,
    tools: readonly McpTool[],
  ) {
    for (const tool of tools) {
      if (this.tools.has(tool.name)) throw new Error(`duplicate tool name: ${tool.name}`);
      this.tools.set(tool.name, tool);
    }
  }

  /** Tool names, for diagnostics and tests. */
  toolNames(): string[] {
    return [...this.tools.keys()];
  }

  /**
   * Handle one decoded JSON-RPC message. Returns the response object, or `null`
   * for a notification (a message with no `id`), which the spec forbids us from
   * answering.
   */
  async handle(msg: RpcMessage): Promise<Record<string, unknown> | null> {
    const isNotification = msg.id === undefined;
    const id: RpcId = msg.id ?? null;
    const method = typeof msg.method === 'string' ? msg.method : null;

    if (!method) {
      return isNotification ? null : this.error(id, ERR_INVALID_REQUEST, 'missing method');
    }

    switch (method) {
      case 'initialize': {
        const params = (msg.params ?? {}) as { protocolVersion?: unknown };
        const requested =
          typeof params.protocolVersion === 'string' && params.protocolVersion.length > 0
            ? params.protocolVersion
            : DEFAULT_PROTOCOL_VERSION;
        return this.ok(id, {
          protocolVersion: requested,
          capabilities: { tools: {} },
          serverInfo: { name: this.name, version: this.version },
        });
      }

      // Post-initialize handshake notification: acknowledged by staying silent.
      case 'notifications/initialized':
      case 'initialized':
        return null;

      case 'ping':
        return isNotification ? null : this.ok(id, {});

      case 'tools/list':
        return this.ok(id, {
          tools: [...this.tools.values()].map((t) => ({
            name: t.name,
            description: t.description,
            inputSchema: t.inputSchema,
          })),
        });

      case 'tools/call':
        return this.callTool(id, msg.params);

      default:
        // Unknown notifications are ignored; unknown requests get a clean error.
        return isNotification
          ? null
          : this.error(id, ERR_METHOD_NOT_FOUND, `unknown method: ${method}`);
    }
  }

  private async callTool(id: RpcId, rawParams: unknown): Promise<Record<string, unknown>> {
    const params = (rawParams ?? {}) as { name?: unknown; arguments?: unknown };
    const name = typeof params.name === 'string' ? params.name : '';
    const tool = this.tools.get(name);
    if (!tool) {
      return this.error(id, ERR_METHOD_NOT_FOUND, `unknown tool: ${name || '(unnamed)'}`);
    }

    const args =
      params.arguments && typeof params.arguments === 'object' && !Array.isArray(params.arguments)
        ? (params.arguments as Record<string, unknown>)
        : {};

    try {
      const result = await tool.handler(args);
      return this.ok(id, {
        content: [{ type: 'text', text: renderResult(result) }],
      });
    } catch (err) {
      // A tool that rejects bad input is normal operation, not a protocol
      // failure: hand the message back as an error-flagged RESULT so the caller
      // can read it and adapt, instead of a transport error it cannot see.
      const message = err instanceof Error ? err.message : String(err);
      return this.ok(id, {
        content: [{ type: 'text', text: `error: ${message}` }],
        isError: true,
      });
    }
  }

  private ok(id: RpcId, result: unknown): Record<string, unknown> {
    return { jsonrpc: JSONRPC_VERSION, id, result };
  }

  private error(id: RpcId, code: number, message: string): Record<string, unknown> {
    return { jsonrpc: JSONRPC_VERSION, id, error: { code, message } };
  }

  /**
   * Bind to a newline-delimited JSON stream pair and serve until stdin ends.
   *
   * Messages are processed strictly in arrival order (each awaited before the
   * next is read). MCP clients tolerate out-of-order responses, but serial
   * handling keeps behaviour reproducible, which is what the evidence rules in
   * this project care about.
   */
  serve(input: NodeJS.ReadableStream, output: NodeJS.WritableStream): Promise<void> {
    return new Promise((resolve) => {
      let buffer = '';
      let chain: Promise<void> = Promise.resolve();

      input.setEncoding('utf8');

      input.on('data', (chunk: string) => {
        buffer += chunk;
        let newline = buffer.indexOf('\n');
        while (newline !== -1) {
          const line = buffer.slice(0, newline).trim();
          buffer = buffer.slice(newline + 1);
          if (line.length > 0) {
            chain = chain.then(() => this.dispatchLine(line, output));
          }
          newline = buffer.indexOf('\n');
        }
      });

      input.on('end', () => {
        // Drain anything already queued before reporting shutdown.
        chain.then(() => resolve()).catch(() => resolve());
      });
    });
  }

  private async dispatchLine(line: string, output: NodeJS.WritableStream): Promise<void> {
    let parsed: RpcMessage;
    try {
      parsed = JSON.parse(line) as RpcMessage;
    } catch {
      this.write(output, this.error(null, ERR_PARSE, 'invalid JSON'));
      return;
    }

    try {
      const response = await this.handle(parsed);
      if (response) this.write(output, response);
    } catch (err) {
      // The dispatcher itself failed — report it rather than dying, so a single
      // malformed message can't end the session.
      const message = err instanceof Error ? err.message : String(err);
      const id: RpcId = parsed.id ?? null;
      if (parsed.id !== undefined) this.write(output, this.error(id, ERR_INTERNAL, message));
      log(`internal error: ${message}`);
    }
  }

  private write(output: NodeJS.WritableStream, payload: Record<string, unknown>): void {
    output.write(`${JSON.stringify(payload)}\n`);
  }
}
