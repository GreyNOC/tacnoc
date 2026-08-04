/**
 * Intercepting HTTP/HTTPS proxy.
 *
 * Architecture:
 *   - A main `http.Server` accepts plain-HTTP proxy requests (absolute-form),
 *     CONNECT tunnels, and Upgrade (WebSocket) requests.
 *   - CONNECT terminates TLS locally with a per-host leaf cert (from the project
 *     CA) and feeds the decrypted stream into an inner `http.Server`, so the
 *     same request path handles both HTTP and decrypted HTTPS.
 *   - ALPN on the MITM side offers `h2` and `http/1.1` by default: HTTP/2 is
 *     terminated and translated to HTTP/1.1 upstream (set `enableHttp2: false`
 *     to offer only `http/1.1`). HTTP/3/QUIC is not intercepted — see
 *     docs/certificate-management.md and PLAN.md.
 *
 * All captured bytes are treated as untrusted: bodies flow through bounded
 * BodyCollectors, header fidelity is preserved, and response content is never
 * executed or rendered.
 */

import * as http from 'node:http';
import * as https from 'node:https';
import * as http2 from 'node:http2';
import * as net from 'node:net';
import * as tls from 'node:tls';
import { once } from 'node:events';
import * as crypto from 'node:crypto';
import type { Readable, Writable } from 'node:stream';
import {
  fromRawHeaders,
  getHeader,
  serializeHeaders,
  type CapturedRequest,
  type CapturedResponse,
  type HttpExchange,
  type HttpHeader,
  type MessageBody,
  type Scheme,
} from '../../shared/model.js';
import type { EngineLimits } from '../../shared/config.js';
import type { ScopeConfig } from '../../shared/scope.js';
import type { InterceptedRequestView, InterceptedResponseView } from '../../shared/intercept.js';
import { evaluateScope } from '../scope/scope.js';
import { CertificateAuthority } from '../ca/certificateAuthority.js';
import { BlobStore } from '../storage/blobStore.js';
import { BodyCollector, bytesToBody, readBodyBytes } from '../storage/bodyCollector.js';
import { Interceptor } from './interceptor.js';
import { buildOutboundHeaders, originForm, parseAuthority, buildUrl } from './proxyUtil.js';
import { WsFrameParser } from './wsFrame.js';
import { Logger, rootLogger } from '../logging/logger.js';

export interface CapturedWsMessage {
  exchangeId: string;
  seq: number;
  direction: 'c2s' | 's2c';
  kind: string;
  size: number;
  truncated: boolean;
  payload: Buffer;
  createdAt: number;
}

const WS_MAX_MESSAGES = 5000;
const WS_MAX_MESSAGE_BYTES = 64 * 1024;
/** Cap on the WebSocket handshake response headers we buffer before tunneling. */
const MAX_HANDSHAKE_BYTES = 64 * 1024;

export interface ProxyServerDeps {
  ca: CertificateAuthority;
  limits: EngineLimits;
  blobStore: BlobStore;
  interceptor: Interceptor;
  getScope: () => ScopeConfig;
  onExchange: (ex: HttpExchange) => void;
  onWebSocket?: (ex: HttpExchange) => void;
  onWebSocketMessage?: (msg: CapturedWsMessage) => void;
  logger?: Logger;
  captureWebSockets?: boolean;
  /** Offer ALPN "h2" and intercept HTTP/2 (translated to HTTP/1.1 upstream). */
  enableHttp2?: boolean;
}

interface RequestContext {
  id: string;
  scheme: Scheme;
  host: string;
  port: number;
  method: string;
  target: string;
  path: string;
  url: string;
  httpVersion: string;
  headers: HttpHeader[];
  inScope: boolean;
}

const AUTHORITY = Symbol('tacnocAuthority');

export class ProxyServer {
  private server?: http.Server;
  private mitm?: http2.Http2SecureServer;
  private readonly connections = new Set<net.Socket>();
  private readonly log: Logger;
  private boundHost = '';
  private boundPort = 0;
  /** CA generation the current `mitm` server was built for. */
  private mitmGeneration = -1;
  /** CONNECTs passed through unread because the CA was revoked. */
  private passthroughCount = 0;
  /** Sockets currently handed to the TLS-terminating server, so a CA change can drop them. */
  private readonly intercepted = new Set<net.Socket>();

  constructor(private readonly deps: ProxyServerDeps) {
    this.log = (deps.logger ?? rootLogger).child('proxy');
  }

  private get alpnProtocols(): string[] {
    return this.deps.enableHttp2 !== false ? ['h2', 'http/1.1'] : ['http/1.1'];
  }

  get address(): { host: string; port: number } | null {
    return this.server && this.boundPort ? { host: this.boundHost, port: this.boundPort } : null;
  }

  /** How many HTTPS tunnels were relayed without interception (revoked CA). */
  get passthroughTunnels(): number {
    return this.passthroughCount;
  }

  /**
   * Build the secure MITM server: terminates TLS with per-host leaf certs (SNI),
   * offers ALPN h2+http/1.1 (or just http/1.1 when h2 is disabled), and delivers
   * BOTH HTTP/2 and HTTP/1.1 through the http1-compatible 'request' event, so a
   * single request path handles both (HTTP/2 is translated to HTTP/1.1 to the
   * origin). WebSocket upgrades arrive via 'upgrade' (http/1.1 only).
   */
  private buildMitm(): http2.Http2SecureServer {
    const defaultLeaf = this.deps.ca.leafPemFor('localhost');
    const mitm = http2.createSecureServer({
      key: defaultLeaf.key,
      cert: defaultLeaf.cert,
      allowHTTP1: true,
      ALPNProtocols: this.alpnProtocols,
      SNICallback: (servername, cb) => {
        try {
          cb(null, this.deps.ca.secureContextFor(servername || 'localhost'));
        } catch (err) {
          cb(err as Error);
        }
      },
    });
    mitm.on(
      'request',
      (req, res) =>
        void this.onRequest(
          req as unknown as http.IncomingMessage,
          res as unknown as http.ServerResponse,
          'https',
        ),
    );
    mitm.on('upgrade', (req, sock, head) =>
      this.onUpgrade(req as unknown as http.IncomingMessage, sock as net.Socket, head, 'https'),
    );
    mitm.on('sessionError', (err) => this.log.debug('h2 session error', { err: String(err) }));
    mitm.on('tlsClientError', () => {
      /* client TLS errors (e.g. untrusted CA) are expected; ignore */
    });
    mitm.on('clientError', (_e, sock) => (sock as net.Socket).destroy());
    return mitm;
  }

  /**
   * The TLS-terminating server, built on first CONNECT and rebuilt whenever the
   * CA changes generation (a rotate invalidates every leaf it signed). Returns
   * undefined while the CA is revoked, which is the signal to tunnel a CONNECT
   * through unread instead of intercepting it.
   */
  private ensureMitm(): http2.Http2SecureServer | undefined {
    if (!this.deps.ca.active) {
      this.dropInterceptedSockets();
      return undefined;
    }
    if (this.mitm && this.mitmGeneration === this.deps.ca.generation) return this.mitm;
    try {
      const built = this.buildMitm();
      // Connections terminated with the retired CA cannot be validated by a
      // client that now trusts the new one, so they are dropped rather than
      // left serving a second chain. `closeAllConnections()` does not exist on
      // Http2SecureServer (it is an http.Server method), and sockets handed in
      // via `emit('connection')` are not counted by `close()` either — so the
      // sockets have to be tracked and destroyed explicitly.
      this.dropInterceptedSockets();
      this.mitm?.close();
      this.mitm = built;
      this.mitmGeneration = this.deps.ca.generation;
    } catch (err) {
      this.log.error('failed to build TLS interception server', { err: String(err) });
      return undefined;
    }
    return this.mitm;
  }

  /**
   * Destroy every socket currently being intercepted.
   *
   * Called when the CA changes. Without it, revoking only affected NEW tunnels:
   * a browser holds an HTTPS tunnel open for minutes, so plaintext kept being
   * decrypted and written to history while the status said interception was off
   * — the status and the behaviour disagreeing is worse than either state.
   */
  private dropInterceptedSockets(): void {
    for (const socket of this.intercepted) socket.destroy();
    this.intercepted.clear();
  }

  /**
   * React to a CA rotate or revoke without waiting for the next CONNECT. The
   * session calls this so the change takes effect on connections already open.
   */
  refreshCa(): void {
    if (!this.server) return;
    this.dropInterceptedSockets();
    if (!this.deps.ca.active) {
      this.mitm?.close();
      this.mitm = undefined;
      this.mitmGeneration = -1;
      this.log.warn('TLS interception stopped: the project CA was revoked');
      return;
    }
    if (this.mitmGeneration !== this.deps.ca.generation) this.ensureMitm();
  }

  async start(host: string, port: number): Promise<{ host: string; port: number }> {
    this.server = http.createServer();
    this.server.on('request', (req, res) => void this.onRequest(req, res, 'http'));
    this.server.on('connect', (req, sock, head) => this.onConnect(req, sock as net.Socket, head));
    this.server.on('upgrade', (req, sock, head) =>
      this.onUpgrade(req, sock as net.Socket, head, 'http'),
    );
    this.server.on('connection', (sock) => this.trackConnection(sock));
    // Malformed request lines etc. must not crash the proxy.
    this.server.on('clientError', (_err, socket) => {
      if (socket.writable) socket.end('HTTP/1.1 400 Bad Request\r\n\r\n');
      else socket.destroy();
    });

    await new Promise<void>((resolve, reject) => {
      this.server!.once('error', reject);
      this.server!.listen(port, host, () => {
        this.server!.off('error', reject);
        resolve();
      });
    });
    const addr = this.server.address() as net.AddressInfo;
    this.boundHost = host;
    this.boundPort = addr.port;
    this.log.info('proxy listening', { host, port: addr.port });
    return { host, port: addr.port };
  }

  async stop(): Promise<void> {
    this.deps.interceptor.releaseAll();
    // Force-terminate keep-alive/tunnel sockets so close() resolves promptly.
    this.server?.closeAllConnections?.();
    (this.mitm as unknown as { closeAllConnections?: () => void })?.closeAllConnections?.();
    this.dropInterceptedSockets();
    for (const sock of this.connections) sock.destroy();
    this.connections.clear();
    await Promise.all([closeServer(this.server), closeServer(this.mitm)]);
    this.server = undefined;
    this.mitm = undefined;
    this.mitmGeneration = -1;
    this.boundPort = 0;
    this.log.info('proxy stopped');
  }

  private trackConnection(sock: net.Socket): void {
    if (this.connections.size >= this.deps.limits.maxProxyConnections) {
      sock.destroy();
      return;
    }
    this.connections.add(sock);
    sock.on('close', () => this.connections.delete(sock));
    sock.on('error', () => this.connections.delete(sock));
  }

  // --- CONNECT (HTTPS MITM) ---

  private onConnect(req: http.IncomingMessage, clientSocket: net.Socket, head: Buffer): void {
    const { host, port } = parseAuthority(req.url ?? '', 443);
    clientSocket.on('error', () => clientSocket.destroy());
    const mitm = this.ensureMitm();
    if (!mitm) {
      // The CA is revoked, so we cannot present a certificate for this host.
      // Relay the bytes untouched instead of failing the connection: the client
      // still reaches the origin (over TLS we never see), and the operator gets
      // a truthful "not intercepted" state to test against.
      this.passthrough(host, port, clientSocket, head);
      return;
    }
    try {
      clientSocket.write('HTTP/1.1 200 Connection Established\r\nProxy-agent: TACNOC\r\n\r\n');
      if (head && head.length) clientSocket.unshift(head);
      // Stash the CONNECT authority on the raw socket; the secure MITM server
      // terminates TLS, negotiates ALPN (h2/http1) and delivers requests via the
      // compatibility 'request' event (h2 requests included) — see start().
      (clientSocket as unknown as Record<symbol, unknown>)[AUTHORITY] = { host, port };
      this.intercepted.add(clientSocket);
      clientSocket.on('close', () => this.intercepted.delete(clientSocket));
      mitm.emit('connection', clientSocket);
    } catch (err) {
      this.log.warn('CONNECT setup failed', { host, err: String(err) });
      clientSocket.destroy();
    }
  }

  /** Blind TCP relay for a CONNECT we are not intercepting. Captures nothing. */
  private passthrough(host: string, port: number, clientSocket: net.Socket, head: Buffer): void {
    if (!host) {
      clientSocket.destroy();
      return;
    }
    this.passthroughCount += 1;
    this.log.info('CONNECT tunneled without interception (CA revoked)', { host, port });
    const upstream = net.connect(port, host);
    const teardown = (): void => {
      upstream.destroy();
      clientSocket.destroy();
    };
    upstream.on('error', teardown);
    clientSocket.on('close', () => upstream.destroy());
    upstream.on('close', () => clientSocket.destroy());
    upstream.on('connect', () => {
      try {
        clientSocket.write('HTTP/1.1 200 Connection Established\r\nProxy-agent: TACNOC\r\n\r\n');
        if (head && head.length) upstream.write(head);
        clientSocket.pipe(upstream);
        upstream.pipe(clientSocket);
      } catch {
        teardown();
      }
    });
  }

  // --- request handling (shared by HTTP + decrypted HTTPS) ---

  private deriveContext(req: http.IncomingMessage, scheme: Scheme): RequestContext {
    let host = '';
    let port = scheme === 'https' ? 443 : 80;
    const rawUrl = req.url ?? '/';

    if (scheme === 'https') {
      // The secure MITM server wraps the raw CONNECT socket in a TLSSocket, so
      // the authority we stashed lives on `req.socket._parent`. Fall back to the
      // request's own socket (older path) and finally the Host/:authority header.
      const authority = readAuthority(req.socket);
      if (authority) {
        host = authority.host;
        port = authority.port;
      } else {
        const a = parseAuthority(
          req.headers.host ?? req.headers[':authority']?.toString() ?? '',
          443,
        );
        host = a.host;
        port = a.port;
      }
    } else if (/^https?:\/\//i.test(rawUrl)) {
      // Absolute-form is the NORMAL request line a client sends to a plain-HTTP
      // proxy. A malformed authority makes `new URL` throw; deriveContext is
      // called outside try/catch in onRequest/onUpgrade, so an unguarded throw
      // would crash the proxy (uncaughtException) or hang the socket. Parse
      // defensively and fall back to the Host header, leaving host empty (→ a
      // clean upstream failure) only when nothing is parseable.
      try {
        const u = new URL(rawUrl);
        host = u.hostname;
        port = u.port ? Number(u.port) : u.protocol === 'https:' ? 443 : 80;
      } catch {
        const a = parseAuthority(req.headers.host ?? '', 80);
        host = a.host;
        port = a.port;
      }
    } else {
      const a = parseAuthority(req.headers.host ?? '', 80);
      host = a.host;
      port = a.port;
    }

    const path = originForm(rawUrl);
    const url = buildUrl(scheme, host, port, rawUrl);
    const decision = evaluateScope(this.deps.getScope(), { scheme, host, port, path });
    const isH2 = req.httpVersion === '2.0';
    return {
      id: crypto.randomUUID(),
      scheme,
      host,
      port,
      method: req.method ?? 'GET',
      target: rawUrl,
      path,
      url,
      httpVersion: isH2 ? 'HTTP/2' : `HTTP/${req.httpVersion}`,
      headers: normalizeRequestHeaders(fromRawHeaders(req.rawHeaders), isH2, `${host}:${port}`),
      inScope: decision.inScope,
    };
  }

  private async onRequest(
    clientReq: http.IncomingMessage,
    clientRes: http.ServerResponse,
    scheme: Scheme,
  ): Promise<void> {
    const ctx = this.deriveContext(clientReq, scheme);
    const startedAt = Date.now();
    const contentEncoding = getHeader(ctx.headers, 'content-encoding');

    try {
      const interceptReq = this.deps.interceptor.getState().interceptRequests;

      let method = ctx.method;
      let target = ctx.target;
      let headers = ctx.headers;
      let requestBody: MessageBody;
      let originReq: http.ClientRequest;

      if (interceptReq) {
        // Buffer fully so the request can be shown for editing.
        const collector = new BodyCollector(
          this.deps.limits.body,
          this.deps.blobStore,
          contentEncoding,
        );
        await drainToCollector(clientReq, collector);
        requestBody = await collector.finish();
        if (requestBody.truncated) {
          // Interception buffers the whole body so it can be shown/edited, but it
          // exceeded the capture cap. Unlike the streaming (non-intercept) path,
          // there is no full copy to forward, so forwarding the stored copy would
          // silently truncate the request to the origin. Fail loud instead.
          respondError(
            clientRes,
            413,
            'Request body exceeds the interception capture limit; disable interception for this request or raise the limit.',
          );
          this.emitExchange(
            ctx,
            requestBody,
            startedAt,
            undefined,
            'intercept: request body exceeded capture limit — not forwarded',
          );
          return;
        }
        const bytes = await readBodyBytes(requestBody, this.deps.blobStore);

        const view: InterceptedRequestView = {
          id: ctx.id,
          createdAt: startedAt,
          scheme: ctx.scheme,
          host: ctx.host,
          port: ctx.port,
          inScope: ctx.inScope,
          method: ctx.method,
          target: ctx.target,
          httpVersion: ctx.httpVersion,
          headers: ctx.headers,
          bodyBase64: bytes.toString('base64'),
          bodyTruncated: requestBody.truncated,
        };
        const decision = await this.deps.interceptor.holdRequest(view);
        if (decision.action === 'drop') {
          clientRes.destroy();
          this.emitExchange(
            ctx,
            requestBody,
            startedAt,
            undefined,
            'dropped by interceptor (request)',
          );
          return;
        }
        if (decision.edit) {
          method = decision.edit.method ?? method;
          target = decision.edit.target ?? target;
          headers = decision.edit.headers ?? headers;
        }
        let sentBytes = bytes;
        if (decision.edit?.bodyBase64 !== undefined) {
          sentBytes = Buffer.from(decision.edit.bodyBase64, 'base64');
        }
        requestBody = await bytesToBody(
          sentBytes,
          this.deps.limits.body,
          this.deps.blobStore,
          contentEncoding,
        );
        originReq = this.openUpstream(
          ctx.scheme,
          ctx.host,
          ctx.port,
          method,
          originForm(target),
          headers,
        );
        originReq.end(sentBytes);
      } else {
        originReq = this.openUpstream(
          ctx.scheme,
          ctx.host,
          ctx.port,
          method,
          originForm(target),
          headers,
        );
        const collector = new BodyCollector(
          this.deps.limits.body,
          this.deps.blobStore,
          contentEncoding,
        );
        await streamTee(clientReq, originReq, collector);
        requestBody = await collector.finish();
      }

      await this.handleUpstreamResponse(ctx, originReq, clientRes, requestBody, startedAt, {
        method,
        target,
      });
    } catch (err) {
      this.log.warn('request handling error', { url: ctx.url, err: String(err) });
      respondError(clientRes, 502, 'Bad Gateway (proxy upstream error)');
      this.emitExchange(
        ctx,
        { size: 0, truncated: false },
        startedAt,
        undefined,
        `upstream error: ${String(err)}`,
      );
    }
  }

  private openUpstream(
    scheme: Scheme,
    host: string,
    port: number,
    method: string,
    path: string,
    headers: HttpHeader[],
  ): http.ClientRequest {
    const outHeaders = buildOutboundHeaders(headers);
    const common: http.RequestOptions = {
      host,
      port,
      method,
      path,
      headers: outHeaders,
      timeout: this.deps.limits.upstreamTimeoutMs,
    };
    if (scheme === 'https') {
      // We connect to the true origin. Origin cert validation is intentionally
      // relaxed so testing against self-signed origins is possible; certificate
      // problems are surfaced as passive findings rather than hard failures.
      return https.request({
        ...common,
        servername: host,
        rejectUnauthorized: false,
        ALPNProtocols: ['http/1.1'],
      } as https.RequestOptions & { ALPNProtocols?: string[] });
    }
    return http.request(common);
  }

  private handleUpstreamResponse(
    ctx: RequestContext,
    originReq: http.ClientRequest,
    clientRes: http.ServerResponse,
    requestBody: MessageBody,
    startedAt: number,
    sent: { method: string; target: string },
  ): Promise<void> {
    return new Promise<void>((resolve) => {
      let responseStarted = false;
      originReq.on('timeout', () => originReq.destroy(new Error('upstream timeout')));
      originReq.on('error', (err) => {
        this.log.warn('upstream error', { url: ctx.url, err: String(err) });
        // If the response has already begun streaming to the client, we must NOT
        // append an error message into the body — that would silently corrupt it
        // while the client still saw a "complete" 200. Abort the response instead
        // so the client sees a truncated/failed transfer (a real error signal).
        if (responseStarted || clientRes.headersSent) {
          clientRes.destroy(err instanceof Error ? err : new Error(String(err)));
        } else {
          respondError(clientRes, 502, 'Bad Gateway (proxy upstream error)');
        }
        this.emitExchange(
          ctx,
          requestBody,
          startedAt,
          undefined,
          `upstream error: ${String(err)}`,
          sent,
        );
        resolve();
      });

      originReq.on('response', (originRes) => {
        responseStarted = true;
        void this.pumpResponse(ctx, originRes, clientRes, requestBody, startedAt, sent)
          .catch((err) => {
            this.log.warn('response pump error', { err: String(err) });
            // If streaming to the client already began, ABORT it so the client
            // detects an incomplete transfer — never append an error string into
            // the in-flight body (which would masquerade as a complete 200).
            if (!clientRes.headersSent) {
              respondError(clientRes, 502, 'Bad Gateway');
            } else if (!clientRes.writableEnded) {
              clientRes.destroy(err instanceof Error ? err : new Error(String(err)));
            }
          })
          .finally(resolve);
      });
    });
  }

  private async pumpResponse(
    ctx: RequestContext,
    originRes: http.IncomingMessage,
    clientRes: http.ServerResponse,
    requestBody: MessageBody,
    startedAt: number,
    sent: { method: string; target: string },
  ): Promise<void> {
    const ttfbMs = Date.now() - startedAt;
    const resHeaders = fromRawHeaders(originRes.rawHeaders);
    const contentEncoding = getHeader(resHeaders, 'content-encoding');
    const interceptRes = this.deps.interceptor.getState().interceptResponses;

    let statusCode = originRes.statusCode ?? 0;
    let statusMessage = originRes.statusMessage ?? '';
    let headers = resHeaders;
    let responseBody: MessageBody;

    if (interceptRes) {
      const collector = new BodyCollector(
        this.deps.limits.body,
        this.deps.blobStore,
        contentEncoding,
      );
      await drainToCollector(originRes, collector);
      responseBody = await collector.finish();
      if (responseBody.truncated) {
        // Same fidelity guard as the request path: we buffered the whole response
        // to allow editing, but it exceeded the capture cap. Aborting the client
        // transfer is a real error signal — far better than delivering a
        // silently-truncated body that would masquerade as complete.
        clientRes.destroy(new Error('response body exceeded interception capture limit'));
        this.emitExchange(
          ctx,
          requestBody,
          startedAt,
          undefined,
          'intercept: response body exceeded capture limit — not forwarded',
          sent,
          ttfbMs,
        );
        return;
      }
      const bytes = await readBodyBytes(responseBody, this.deps.blobStore);
      const view: InterceptedResponseView = {
        id: ctx.id,
        createdAt: startedAt,
        scheme: ctx.scheme,
        host: ctx.host,
        port: ctx.port,
        method: sent.method,
        target: sent.target,
        statusCode,
        statusMessage,
        httpVersion: ctx.httpVersion,
        headers: resHeaders,
        bodyBase64: bytes.toString('base64'),
        bodyTruncated: responseBody.truncated,
      };
      const decision = await this.deps.interceptor.holdResponse(view);
      if (decision.action === 'drop') {
        clientRes.destroy();
        this.emitExchange(
          ctx,
          requestBody,
          startedAt,
          undefined,
          'dropped by interceptor (response)',
          sent,
        );
        return;
      }
      if (decision.edit) {
        statusCode = decision.edit.statusCode ?? statusCode;
        statusMessage = decision.edit.statusMessage ?? statusMessage;
        headers = decision.edit.headers ?? headers;
      }
      let sentBytes = bytes;
      if (decision.edit?.bodyBase64 !== undefined) {
        sentBytes = Buffer.from(decision.edit.bodyBase64, 'base64');
      }
      responseBody = await bytesToBody(
        sentBytes,
        this.deps.limits.body,
        this.deps.blobStore,
        contentEncoding,
      );
      writeResponseHead(
        clientRes,
        statusCode,
        statusMessage,
        headers,
        ctx.httpVersion === 'HTTP/2',
      );
      clientRes.end(sentBytes);
    } else {
      writeResponseHead(
        clientRes,
        statusCode,
        statusMessage,
        headers,
        ctx.httpVersion === 'HTTP/2',
      );
      const collector = new BodyCollector(
        this.deps.limits.body,
        this.deps.blobStore,
        contentEncoding,
      );
      await streamTee(originRes, clientRes, collector);
      responseBody = await collector.finish();
    }

    const response: CapturedResponse = {
      statusCode,
      statusMessage,
      httpVersion: ctx.httpVersion,
      headers,
      body: responseBody,
    };
    this.emitExchange(ctx, requestBody, startedAt, response, undefined, sent, ttfbMs);
  }

  private emitExchange(
    ctx: RequestContext,
    requestBody: MessageBody,
    startedAt: number,
    response: CapturedResponse | undefined,
    error: string | undefined,
    sent?: { method: string; target: string },
    ttfbMs?: number,
  ): void {
    const request: CapturedRequest = {
      method: sent?.method ?? ctx.method,
      target: sent?.target ?? ctx.target,
      url: ctx.url,
      httpVersion: ctx.httpVersion,
      headers: ctx.headers,
      body: requestBody,
    };
    const exchange: HttpExchange = {
      id: ctx.id,
      createdAt: startedAt,
      source: 'proxy',
      scheme: ctx.scheme,
      host: ctx.host,
      port: ctx.port,
      inScope: ctx.inScope,
      automated: false,
      request,
      tags: [],
      timing: {
        startedAt,
        ...(ttfbMs !== undefined ? { ttfbMs } : {}),
        durationMs: Date.now() - startedAt,
      },
      ...(response ? { response } : {}),
      ...(error ? { error } : {}),
    };
    try {
      this.deps.onExchange(exchange);
    } catch (err) {
      this.log.error('onExchange sink threw', { err: String(err) });
    }
  }

  // --- WebSocket upgrade (handshake capture + transparent tunnel) ---

  private onUpgrade(
    req: http.IncomingMessage,
    clientSocket: net.Socket,
    head: Buffer,
    scheme: Scheme,
  ): void {
    const ctx = this.deriveContext(req, scheme);
    const startedAt = Date.now();
    clientSocket.on('error', () => clientSocket.destroy());

    // A malformed/absent authority leaves host empty; there is nothing to tunnel
    // to, so close the socket instead of dialing an empty host.
    if (!ctx.host) {
      this.log.warn('websocket upgrade with unresolvable host', { target: ctx.target });
      clientSocket.destroy();
      return;
    }

    const upstream =
      scheme === 'https'
        ? tls.connect({
            host: ctx.host,
            port: ctx.port,
            servername: ctx.host,
            rejectUnauthorized: false,
            ALPNProtocols: ['http/1.1'],
          })
        : net.connect(ctx.port, ctx.host);

    upstream.on('error', () => {
      clientSocket.destroy();
    });

    const onConnect = (): void => {
      const requestLine = `${ctx.method} ${ctx.path} HTTP/1.1\r\n`;
      upstream.write(requestLine + serializeHeaders(ctx.headers) + '\r\n\r\n');
      if (head && head.length) upstream.write(head);

      // Sniff the 101 handshake response headers for capture, then tunnel.
      let handshakeBuf = Buffer.alloc(0);
      let handshakeDone = false;
      const onData = (chunk: Buffer): void => {
        if (handshakeDone) return;
        handshakeBuf = Buffer.concat([handshakeBuf, chunk]);
        // Bound the handshake buffer: a peer that never sends the header
        // terminator must not grow it without limit.
        if (handshakeBuf.length > MAX_HANDSHAKE_BYTES) {
          this.log.warn('websocket handshake exceeded limit', { host: ctx.host });
          upstream.destroy();
          clientSocket.destroy();
          return;
        }
        const idx = handshakeBuf.indexOf('\r\n\r\n');
        if (idx !== -1) {
          handshakeDone = true;
          upstream.off('data', onData);
          this.captureWebSocketHandshake(ctx, handshakeBuf.subarray(0, idx), startedAt);
          const earlyFrames = handshakeBuf.subarray(idx + 4); // server frames sent with the 101
          clientSocket.write(handshakeBuf); // forward full handshake + any early frames
          if (this.deps.captureWebSockets !== false && this.deps.onWebSocketMessage) {
            this.tunnelWithCapture(ctx.id, clientSocket, upstream, earlyFrames);
          } else {
            upstream.pipe(clientSocket);
            clientSocket.pipe(upstream);
          }
        }
      };
      upstream.on('data', onData);
    };

    if (scheme === 'https') upstream.once('secureConnect', onConnect);
    else upstream.once('connect', onConnect);
  }

  /**
   * Tunnel a WebSocket while OBSERVING frames in both directions. Bytes are
   * forwarded unchanged; parsers only read. Bounded by message count/size.
   */
  private tunnelWithCapture(
    exchangeId: string,
    clientSocket: net.Socket,
    upstream: net.Socket | tls.TLSSocket,
    earlyServerFrames: Buffer,
  ): void {
    const s2c = new WsFrameParser(WS_MAX_MESSAGE_BYTES);
    const c2s = new WsFrameParser(WS_MAX_MESSAGE_BYTES);
    let seq = 0;
    let count = 0;

    const emit = (
      direction: 'c2s' | 's2c',
      msg: ReturnType<WsFrameParser['push']>[number],
    ): void => {
      if (count >= WS_MAX_MESSAGES) return;
      count += 1;
      try {
        this.deps.onWebSocketMessage!({
          exchangeId,
          seq: seq++,
          direction,
          kind: msg.kind,
          size: msg.size,
          truncated: msg.truncated,
          payload: msg.payload,
          createdAt: Date.now(),
        });
      } catch (err) {
        this.log.warn('ws message sink threw', { err: String(err) });
      }
    };

    const observe = (parser: WsFrameParser, direction: 'c2s' | 's2c', chunk: Buffer): void => {
      try {
        for (const m of parser.push(chunk)) emit(direction, m);
      } catch (err) {
        this.log.debug('ws parse error (continuing tunnel)', { err: String(err) });
      }
    };

    if (earlyServerFrames.length) observe(s2c, 's2c', earlyServerFrames);

    upstream.on('data', (chunk: Buffer) => {
      observe(s2c, 's2c', chunk);
      if (!clientSocket.write(chunk)) upstream.pause();
    });
    clientSocket.on('drain', () => upstream.resume());

    clientSocket.on('data', (chunk: Buffer) => {
      observe(c2s, 'c2s', chunk);
      if (!upstream.write(chunk)) clientSocket.pause();
    });
    upstream.on('drain', () => clientSocket.resume());

    const teardown = (): void => {
      upstream.destroy();
      clientSocket.destroy();
    };
    upstream.on('end', () => clientSocket.end());
    clientSocket.on('end', () => upstream.end());
    upstream.on('close', teardown);
    clientSocket.on('close', teardown);
  }

  private captureWebSocketHandshake(
    ctx: RequestContext,
    responseHead: Buffer,
    startedAt: number,
  ): void {
    if (this.deps.captureWebSockets === false) return;
    const text = responseHead.toString('latin1');
    const lines = text.split('\r\n');
    const statusLine = lines.shift() ?? 'HTTP/1.1 101 Switching Protocols';
    const m = /HTTP\/\d\.\d\s+(\d+)\s*(.*)/.exec(statusLine);
    const headers: HttpHeader[] = [];
    for (const line of lines) {
      const c = line.indexOf(':');
      if (c > 0) headers.push({ name: line.slice(0, c).trim(), value: line.slice(c + 1).trim() });
    }
    const response: CapturedResponse = {
      statusCode: m ? Number(m[1]) : 101,
      statusMessage: m ? (m[2] ?? '') : 'Switching Protocols',
      httpVersion: 'HTTP/1.1',
      headers,
      body: { size: 0, truncated: false },
    };
    const exchange: HttpExchange = {
      id: ctx.id,
      createdAt: startedAt,
      source: 'proxy',
      scheme: ctx.scheme,
      host: ctx.host,
      port: ctx.port,
      inScope: ctx.inScope,
      automated: false,
      request: {
        method: ctx.method,
        target: ctx.target,
        url: ctx.url,
        httpVersion: ctx.httpVersion,
        headers: ctx.headers,
        body: { size: 0, truncated: false },
      },
      response,
      tags: ['websocket'],
      timing: { startedAt, durationMs: Date.now() - startedAt },
    };
    try {
      (this.deps.onWebSocket ?? this.deps.onExchange)(exchange);
    } catch (err) {
      this.log.error('websocket sink threw', { err: String(err) });
    }
  }
}

// --- module-private stream helpers ---

async function drainToCollector(src: Readable, collector: BodyCollector): Promise<void> {
  for await (const chunk of src) {
    await collector.write(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }
}

async function streamTee(src: Readable, dest: Writable, collector: BodyCollector): Promise<void> {
  for await (const chunk of src) {
    const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    await collector.write(buf);
    if (!dest.write(buf)) await once(dest, 'drain');
  }
  await new Promise<void>((resolve, reject) => {
    dest.end(() => resolve());
    dest.once('error', reject);
  });
}

function writeResponseHead(
  res: http.ServerResponse,
  statusCode: number,
  statusMessage: string,
  headers: readonly HttpHeader[],
  isH2 = false,
): void {
  const out = buildOutboundHeaders(headers);
  if (isH2) {
    // HTTP/2 requires lowercase field names and carries no reason phrase.
    const lower: http.OutgoingHttpHeaders = {};
    for (const [k, v] of Object.entries(out)) lower[k.toLowerCase()] = v;
    res.writeHead(statusCode, lower);
  } else if (statusMessage) {
    res.writeHead(statusCode, statusMessage, out);
  } else {
    res.writeHead(statusCode, out);
  }
}

/**
 * For HTTP/2 requests, drop pseudo-headers (":method", ":path", ":authority",
 * ":scheme") and synthesize a Host header from :authority so the captured/
 * forwarded request looks like an ordinary HTTP/1.1 message.
 */
function normalizeRequestHeaders(
  headers: HttpHeader[],
  isH2: boolean,
  fallbackAuthority: string,
): HttpHeader[] {
  if (!isH2) return headers;
  const authority = headers.find((h) => h.name === ':authority')?.value || fallbackAuthority;
  const regular = headers.filter((h) => !h.name.startsWith(':'));
  if (!regular.some((h) => h.name.toLowerCase() === 'host')) {
    regular.unshift({ name: 'Host', value: authority });
  }
  return regular;
}

/** Read the CONNECT authority stashed on a socket (or its TLS `_parent`). */
function readAuthority(sock: unknown): { host: string; port: number } | undefined {
  const s = sock as (Record<symbol, unknown> & { _parent?: unknown }) | undefined;
  if (!s) return undefined;
  const direct = s[AUTHORITY] as { host: string; port: number } | undefined;
  if (direct) return direct;
  const parent = s._parent as Record<symbol, unknown> | undefined;
  return parent ? (parent[AUTHORITY] as { host: string; port: number } | undefined) : undefined;
}

function respondError(res: http.ServerResponse, code: number, message: string): void {
  try {
    if (!res.headersSent) {
      res.writeHead(code, { 'Content-Type': 'text/plain; charset=utf-8' });
    }
    res.end(message);
  } catch {
    res.destroy();
  }
}

function closeServer(server?: http.Server | http2.Http2SecureServer): Promise<void> {
  if (!server) return Promise.resolve();
  return new Promise((resolve) => server.close(() => resolve()));
}
