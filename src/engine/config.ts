/**
 * Default engine configuration and safety limits.
 *
 * Defaults are deliberately conservative: loopback-only listener, low
 * automation concurrency and rate, and bounded body sizes. Callers may raise
 * limits, but the *defaults* must never surprise a researcher into hammering a
 * target or exhausting memory.
 */

import { DEFAULT_PROXY_HOST, DEFAULT_PROXY_PORT } from '../shared/model.js';
import type { EngineConfig, EngineLimits } from '../shared/config.js';

/** 5 MiB in memory before spilling; 100 MiB absolute capture cap per body. */
export const DEFAULT_LIMITS: EngineLimits = {
  body: {
    spillToDiskAfterBytes: 5 * 1024 * 1024,
    maxCapturedBytes: 100 * 1024 * 1024,
  },
  automation: {
    maxConcurrency: 4,
    requestsPerSecond: 8,
    timeoutMs: 20_000,
    maxRequestsPerJob: 5_000,
  },
  maxProxyConnections: 512,
  upstreamTimeoutMs: 30_000,
};

/**
 * Hosts that are safe to bind without a warning. Anything else (0.0.0.0, a LAN
 * IP, etc.) should trigger an explicit confirmation in the UI because it
 * exposes the intercepting proxy beyond the local machine.
 */
export const SAFE_BIND_HOSTS = new Set(['127.0.0.1', '::1', 'localhost']);

export function isLoopbackBind(host: string): boolean {
  return SAFE_BIND_HOSTS.has(host.trim().toLowerCase());
}

export function defaultEngineConfig(): EngineConfig {
  return {
    listener: { host: DEFAULT_PROXY_HOST, port: DEFAULT_PROXY_PORT },
    limits: structuredClone(DEFAULT_LIMITS),
    redaction: {
      maskCookies: true,
      maskAuthorization: true,
      maskSecretPatterns: true,
    },
    captureWebSockets: true,
    interceptHttp2: true,
  };
}
