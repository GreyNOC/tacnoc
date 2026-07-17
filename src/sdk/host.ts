/**
 * Extension host — runs extensions inside an isolated CHILD PROCESS and talks to
 * them over a capability RPC bridge (IPC messages only; no shared object
 * references). See src/sdk/subprocessRuntime.ts and docs/extension-sdk.md for the
 * isolation model and its residual risks.
 *
 * The host holds only metadata about what extensions registered (ids, labels,
 * module versions); the extension code and its callbacks live entirely in the
 * child process. Passive checks and transforms are invoked via async RPC.
 */

import { fork, type ChildProcess } from 'node:child_process';
import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { getHeader, mimeType, type HttpExchange } from '../shared/model.js';
import type { Finding } from '../shared/findings.js';
import type { RedactionConfig } from '../shared/config.js';
import { Redactor } from '../engine/redaction/redactor.js';
import { Logger, rootLogger } from '../engine/logging/logger.js';
import { EXTENSION_HOST_SOURCE } from './subprocessRuntime.js';
import {
  ELEVATED_PERMISSIONS,
  type ExtensionManifest,
  type Permission,
  type SanitizedTrafficEvent,
} from './api.js';

/** A minimal, mostly-scrubbed environment for the extension child process. */
function childEnv(): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = { ELECTRON_RUN_AS_NODE: '1' };
  // Only the OS essentials needed to launch Node reliably cross-platform.
  for (const key of [
    'PATH',
    'SystemRoot',
    'windir',
    'TEMP',
    'TMP',
    'HOME',
    'USERPROFILE',
    'LANG',
    'TZ',
  ]) {
    const v = process.env[key];
    if (v !== undefined) env[key] = v;
  }
  return env;
}

interface Pending {
  resolve: (value: unknown) => void;
  reject: (err: Error) => void;
}

interface RawExtFinding {
  extId: string;
  module: string;
  version: string;
  finding: {
    dedupeKey: string;
    title: string;
    severity: Finding['severity'];
    confidence: Finding['confidence'];
    description: string;
    remediation: string;
    evidence: {
      location: Finding['evidence'][number]['location'];
      excerpt: string;
      field?: string;
    }[];
  };
}

interface Registrations {
  ok: boolean;
  error?: string;
  registrations?: {
    checks: { module: string; version: string }[];
    transforms: { id: string; label: string; category: string }[];
    tabs: { id: string; label: string }[];
    actions: { id: string; label: string }[];
    hasTraffic: boolean;
  };
}

export interface TransformMeta {
  id: string;
  label: string;
  category: string;
}

export class ExtensionHost {
  private child: ChildProcess;
  private readonly childDir: string;
  private readonly ready: Promise<void>;
  private seq = 0;
  private readonly pending = new Map<number, Pending>();
  private readonly redactor: Redactor;
  private readonly log: Logger;

  private readonly extensions: { manifest: ExtensionManifest; granted: Permission[] }[] = [];
  private transformsMeta: TransformMeta[] = [];
  private checksMeta: { module: string; version: string }[] = [];
  private tabsMeta: { extensionId: string; id: string; label: string }[] = [];
  private actionsMeta: { extensionId: string; id: string; label: string }[] = [];
  private trafficSubscribers = 0;
  private terminating = false;
  private dead = false;

  constructor(
    redaction: RedactionConfig,
    logger: Logger = rootLogger,
    private readonly onFinding?: (finding: Finding) => void,
  ) {
    this.redactor = new Redactor(redaction);
    this.log = logger.child('extensions');

    // Write the child bootstrap to a private temp dir and fork it as a separate
    // OS process (runs as plain Node even under Electron via ELECTRON_RUN_AS_NODE),
    // with a minimal env, a bounded heap, no inherited stdio, and its own cwd.
    this.childDir = fs.mkdtempSync(path.join(os.tmpdir(), 'belcher-ext-'));
    const entry = path.join(this.childDir, 'extension-host.cjs');
    fs.writeFileSync(entry, EXTENSION_HOST_SOURCE, { mode: 0o600 });
    this.child = fork(entry, [], {
      env: childEnv(),
      cwd: this.childDir,
      stdio: ['ignore', 'ignore', 'ignore', 'ipc'],
      execArgv: ['--max-old-space-size=256'],
      serialization: 'advanced',
    });
    // Don't let the extension process keep the parent alive on shutdown.
    this.child.unref();

    let resolveReady!: () => void;
    let rejectReady!: (err: Error) => void;
    let readySettled = false;
    this.ready = new Promise<void>((res, rej) => {
      resolveReady = () => {
        readySettled = true;
        res();
      };
      rejectReady = (err: Error) => {
        readySettled = true;
        rej(err);
      };
    });
    // Never let an unconsumed `ready` become an unhandled rejection; awaiters
    // still receive the rejection from their own `await this.ready`.
    this.ready.catch(() => {});

    this.child.on('error', (err) => {
      this.log.error('extension host process error', { err: String(err) });
      if (!readySettled) rejectReady(err instanceof Error ? err : new Error(String(err)));
    });
    this.child.on('exit', (code) => {
      this.dead = true;
      if (!readySettled) rejectReady(new Error('extension host process exited before ready'));
      for (const p of this.pending.values()) p.reject(new Error('extension host process exited'));
      this.pending.clear();
      if (!this.terminating) {
        // Unexpected death: LOUDLY drop all extension capabilities so the app
        // never silently advertises checks/transforms that can no longer run
        // (fail-closed, not a silent detection bypass). Re-fork on demand is
        // future work; for now the operator sees the error and can reload.
        this.log.error(
          'extension host process crashed — extension features disabled until reload',
          {
            code,
          },
        );
        this.extensions.length = 0;
        this.checksMeta = [];
        this.transformsMeta = [];
        this.tabsMeta = [];
        this.actionsMeta = [];
        this.trafficSubscribers = 0;
        // The child won't be reused after an unexpected exit, so remove its
        // bootstrap temp dir now instead of leaking it until app shutdown
        // (repeated crash/reload cycles would otherwise accumulate dirs).
        this.cleanupChildDir();
      }
    });
    this.child.on('message', (m) => this.onMessage(m as Record<string, unknown>, resolveReady));
  }

  private onMessage(m: Record<string, unknown>, resolveReady: () => void): void {
    // The child is untrusted; a malformed message must NEVER throw out of this
    // IPC listener (that would crash the host process).
    try {
      const type = m?.type as string;
      if (type === 'ready') {
        resolveReady();
        return;
      }
      if (type === 'log') {
        const level = (m.level as 'info' | 'warn' | 'error') ?? 'info';
        if (level === 'info' || level === 'warn' || level === 'error')
          this.log[level](String(m.msg));
        return;
      }
      if (type === 'finding') {
        // A createFinding() call (from a check or an onTraffic handler).
        const extId = String(m.extId ?? 'unknown');
        const f = m.finding;
        if (!f || typeof f !== 'object') return;
        const finding = this.materialize(
          String((f as { exchangeId?: unknown }).exchangeId ?? ''),
          `ext:${extId}`,
          '1.0.0',
          f as RawExtFinding['finding'],
        );
        try {
          this.onFinding?.(finding);
        } catch (err) {
          this.log.warn('onFinding sink threw', { err: String(err) });
        }
        return;
      }
      const reqId = m?.reqId as number | undefined;
      if (reqId === undefined) return;
      const p = this.pending.get(reqId);
      if (!p) return;
      this.pending.delete(reqId);
      p.resolve(m);
    } catch (err) {
      this.log.warn('malformed extension message ignored', { err: String(err) });
    }
  }

  private call<T = Record<string, unknown>>(
    msg: Record<string, unknown>,
    timeoutMs = 5000,
  ): Promise<T> {
    const reqId = ++this.seq;
    if (this.dead || !this.child.connected) {
      return Promise.reject(new Error('extension host process is not running'));
    }
    return new Promise<T>((resolve, reject) => {
      // A misbehaving extension can run an infinite loop the child process
      // cannot interrupt; time out the RPC so it never blocks the caller (e.g.
      // the passive-scan pipeline) indefinitely.
      const timer = setTimeout(() => {
        if (this.pending.delete(reqId)) reject(new Error(`extension RPC timed out (${msg.type})`));
      }, timeoutMs);
      if (typeof timer.unref === 'function') timer.unref();
      this.pending.set(reqId, {
        resolve: (v: unknown) => {
          clearTimeout(timer);
          resolve(v as T);
        },
        reject: (e: Error) => {
          clearTimeout(timer);
          reject(e);
        },
      });
      this.child.send({ ...msg, reqId });
    });
  }

  /** Load an extension into the child process with the user-approved permissions. */
  async load(manifest: ExtensionManifest, source: string, granted: Permission[]): Promise<void> {
    await this.ready;
    // Reject a duplicate id: ids are the rollback key in the child, so loading
    // two extensions with the same id could wipe the first's registrations.
    if (this.extensions.some((e) => e.manifest.id === manifest.id)) {
      throw new Error(`extension id "${manifest.id}" is already loaded`);
    }
    const grantedSet = granted.filter((p) => manifest.permissions.includes(p));
    const missingElevated = manifest.permissions
      .filter((p) => ELEVATED_PERMISSIONS.has(p))
      .filter((p) => !grantedSet.includes(p));
    if (missingElevated.length) {
      this.log.warn('extension loaded without some elevated permissions', {
        id: manifest.id,
        missing: missingElevated,
      });
    }

    const res = await this.call<Registrations>({
      type: 'load',
      manifest,
      source,
      granted: grantedSet,
    });
    if (!res.ok || !res.registrations) {
      throw new Error(`extension ${manifest.id} failed to load: ${res.error ?? 'unknown error'}`);
    }
    const reg = res.registrations;
    this.extensions.push({ manifest, granted: grantedSet });
    this.checksMeta.push(...reg.checks);
    this.transformsMeta.push(...reg.transforms);
    this.tabsMeta.push(
      ...reg.tabs.map((t) => ({ extensionId: manifest.id, id: t.id, label: t.label })),
    );
    this.actionsMeta.push(
      ...reg.actions.map((a) => ({ extensionId: manifest.id, id: a.id, label: a.label })),
    );
    if (reg.hasTraffic) this.trafficSubscribers += 1;
    this.log.info('extension loaded', { id: manifest.id, granted: grantedSet });
  }

  /** Deliver a sanitized traffic event to subscribed extensions (fire-and-forget). */
  dispatchTraffic(exchange: HttpExchange): void {
    if (this.trafficSubscribers === 0) return;
    if (this.child.connected) this.child.send({ type: 'traffic', event: this.sanitize(exchange) });
  }

  hasExtensionChecks(): boolean {
    return this.checksMeta.length > 0;
  }

  /** Run all extension passive checks against an exchange and return findings. */
  async runChecks(
    exchange: HttpExchange,
    requestBodyText: string,
    responseBodyText: string,
  ): Promise<Finding[]> {
    if (this.checksMeta.length === 0) return [];
    await this.ready;
    // Redact BEFORE crossing into the untrusted child. `passive-checks` is a
    // non-elevated permission; without this it would receive full unredacted
    // bodies and credential headers — strictly more sensitive data than the
    // elevated (sanitized) `read-traffic` path, which combined with the process's
    // own net/fs access is an exfiltration path for intercepted secrets.
    const res = await this.call<{ raw: RawExtFinding[] }>({
      type: 'runChecks',
      exchange: this.redactExchangeForChecks(exchange),
      requestBodyText: this.redactor.redactText(requestBodyText),
      responseBodyText: this.redactor.redactText(responseBodyText),
    });
    return (res.raw ?? []).map((r) =>
      this.materialize(exchange.id, r.module, r.version, r.finding),
    );
  }

  /**
   * Build a copy of an exchange safe to hand to an untrusted extension check:
   * headers and URL are redacted and raw body bytes are stripped (checks get the
   * redacted body text separately).
   */
  private redactExchangeForChecks(ex: HttpExchange): HttpExchange {
    const stripBody = (b: HttpExchange['request']['body']): HttpExchange['request']['body'] => ({
      size: b.size,
      truncated: b.truncated,
      ...(b.contentEncoding ? { contentEncoding: b.contentEncoding } : {}),
    });
    const redacted: HttpExchange = {
      ...ex,
      request: {
        ...ex.request,
        url: this.redactor.redactUrl(ex.request.url),
        headers: this.redactor.redactHeaders(ex.request.headers),
        body: stripBody(ex.request.body),
      },
    };
    if (ex.response) {
      redacted.response = {
        ...ex.response,
        headers: this.redactor.redactHeaders(ex.response.headers),
        body: stripBody(ex.response.body),
      };
    }
    return redacted;
  }

  private materialize(
    exchangeId: string,
    module: string,
    version: string,
    f: RawExtFinding['finding'],
  ): Finding {
    // `f` may be malformed (extension-supplied); coerce every field defensively.
    const sev: Finding['severity'] = ['info', 'low', 'medium', 'high', 'critical'].includes(
      f?.severity as string,
    )
      ? f.severity
      : 'info';
    const conf: Finding['confidence'] = ['tentative', 'firm', 'certain'].includes(
      f?.confidence as string,
    )
      ? f.confidence
      : 'tentative';
    const evidence = Array.isArray(f?.evidence) ? f.evidence : [];
    return {
      id: crypto.randomUUID(),
      exchangeId,
      dedupeKey: `${module}|${String(f?.dedupeKey ?? '')}`,
      title: String(f?.title ?? '(untitled finding)'),
      severity: sev,
      confidence: conf,
      module,
      moduleVersion: version,
      description: String(f?.description ?? ''),
      remediation: String(f?.remediation ?? ''),
      evidence: evidence.map((e) => ({
        location: (e?.location ?? 'response-body') as Finding['evidence'][number]['location'],
        excerpt: this.redactor.redactText(String(e?.excerpt ?? '')),
        ...(e?.field ? { field: String(e.field) } : {}),
      })),
      createdAt: Date.now(),
      suppressed: false,
    };
  }

  async applyTransform(id: string, input: string): Promise<string> {
    await this.ready;
    const res = await this.call<{ ok: boolean; value?: string; error?: string }>({
      type: 'applyTransform',
      id,
      input,
    });
    if (!res.ok) throw new Error(res.error ?? 'transform failed');
    return res.value ?? '';
  }

  async renderTab(id: string, event: SanitizedTrafficEvent): Promise<string> {
    await this.ready;
    const res = await this.call<{ ok: boolean; value?: string; error?: string }>({
      type: 'renderTab',
      id,
      event,
    });
    if (!res.ok) throw new Error(res.error ?? 'render failed');
    return res.value ?? '';
  }

  hasTransform(id: string): boolean {
    return this.transformsMeta.some((t) => t.id === id);
  }
  getTransforms(): TransformMeta[] {
    return [...this.transformsMeta];
  }
  getEditorTabs(): { extensionId: string; id: string; label: string }[] {
    return [...this.tabsMeta];
  }
  getContextMenuActions(): { extensionId: string; id: string; label: string }[] {
    return [...this.actionsMeta];
  }
  getCheckModules(): { module: string; version: string }[] {
    return [...this.checksMeta];
  }
  listExtensions(): { manifest: ExtensionManifest; granted: Permission[] }[] {
    return this.extensions.map((e) => ({ manifest: e.manifest, granted: [...e.granted] }));
  }

  /** PID of the isolated extension process (for diagnostics/tests). */
  pid(): number | undefined {
    return this.child.pid;
  }

  async terminate(): Promise<void> {
    this.terminating = true;
    const exited = new Promise<void>((resolve) => {
      // Already gone? `dead` is set by the exit handler for BOTH a normal exit
      // and a signal kill (where exitCode stays null) — checking it avoids a
      // hang waiting for an 'exit' that already fired and won't fire again.
      if (this.dead || (!this.child.connected && this.child.exitCode !== null)) return resolve();
      this.child.once('exit', () => resolve());
      // Ask nicely, then force-kill shortly after.
      try {
        if (this.child.connected) this.child.send({ type: 'shutdown' });
      } catch {
        /* channel already closed */
      }
      const t = setTimeout(() => this.child.kill('SIGKILL'), 500);
      if (typeof t.unref === 'function') t.unref();
    });
    await exited;
    this.cleanupChildDir();
  }

  /** Best-effort removal of the child bootstrap temp dir. Idempotent. */
  private cleanupChildDir(): void {
    try {
      fs.rmSync(this.childDir, { recursive: true, force: true });
    } catch {
      /* Windows may hold the file briefly; harmless to leave in tmp */
    }
  }

  private sanitize(exchange: HttpExchange): SanitizedTrafficEvent {
    const event: SanitizedTrafficEvent = {
      id: exchange.id,
      source: exchange.source,
      scheme: exchange.scheme,
      host: exchange.host,
      port: exchange.port,
      method: exchange.request.method,
      url: this.redactor.redactUrl(exchange.request.url),
      inScope: exchange.inScope,
      requestHeaders: this.redactor.redactHeaders(exchange.request.headers),
    };
    if (exchange.response) {
      event.statusCode = exchange.response.statusCode;
      event.responseHeaders = this.redactor.redactHeaders(exchange.response.headers);
      const mt = mimeType(exchange.response.headers);
      if (mt) event.responseMime = mt;
      const ct = getHeader(exchange.response.headers, 'content-type');
      if (ct && !event.responseMime) event.responseMime = ct;
    }
    return event;
  }
}
