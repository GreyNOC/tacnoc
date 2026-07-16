/**
 * Engine limits and proxy configuration types. Concrete defaults live in
 * `src/engine/config.ts`. These bounds are safety controls, not tuning knobs:
 * they cap memory use on hostile traffic and rate-limit automated work.
 */

export interface ProxyListenerConfig {
  /** Bind address. Defaults to 127.0.0.1 and is validated against a warn-list. */
  host: string;
  port: number;
}

export interface BodyLimits {
  /** Bodies larger than this (bytes) are spilled to the on-disk blob store. */
  spillToDiskAfterBytes: number;
  /** Absolute cap on captured body size (bytes). Beyond this, capture stops
   *  and the body is marked truncated. Prevents unbounded memory/disk use. */
  maxCapturedBytes: number;
}

export interface AutomationLimits {
  /** Max simultaneous in-flight automated requests. */
  maxConcurrency: number;
  /** Target requests per second (token-bucket). */
  requestsPerSecond: number;
  /** Per-request timeout in ms. */
  timeoutMs: number;
  /** Hard ceiling on total requests a single job may generate. */
  maxRequestsPerJob: number;
}

export interface EngineLimits {
  body: BodyLimits;
  automation: AutomationLimits;
  /** Max simultaneous proxied connections before new ones are refused. */
  maxProxyConnections: number;
  /** Idle socket timeout in ms for proxied upstream connections. */
  upstreamTimeoutMs: number;
}

export interface RedactionConfig {
  /** Mask cookies in stored/exported/logged data. */
  maskCookies: boolean;
  /** Mask Authorization / Proxy-Authorization headers. */
  maskAuthorization: boolean;
  /** Mask values that match secret patterns (tokens, keys). */
  maskSecretPatterns: boolean;
}

export interface EngineConfig {
  listener: ProxyListenerConfig;
  limits: EngineLimits;
  redaction: RedactionConfig;
  /** When true, the proxy captures WebSocket upgrade handshakes and frames. */
  captureWebSockets: boolean;
  /**
   * When true, the MITM offers ALPN "h2" so HTTP/2 clients are intercepted
   * (translated to HTTP/1.1 to the origin). When false, only "http/1.1" is
   * offered and h2-capable clients downgrade.
   */
  interceptHttp2: boolean;
}
