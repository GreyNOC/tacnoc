/**
 * BelcherSession — the engine facade the desktop app talks to.
 *
 * It owns the open project and wires the proxy, passive scanner, repeater,
 * variation engine, and extension host together. Captured exchanges flow:
 *   proxy → history (persist) → passive scan → findings → 'finding' events
 *                             → extension traffic dispatch
 *                             → 'exchange' summary event (for the live table)
 *
 * The desktop main process subscribes to this emitter and forwards events to the
 * renderer; it never exposes engine internals directly to the page.
 */

import { EventEmitter } from 'node:events';
import { randomUUID } from 'node:crypto';
import { mimeType, type HttpExchange } from '../shared/model.js';
import type { ScopeConfig } from '../shared/scope.js';
import type { EngineConfig } from '../shared/config.js';
import type { HistoryFilter, HistoryPage, ExchangeSummary } from '../shared/query.js';
import type {
  ExchangeDetail,
  MessageDetail,
  RequestDetail,
  ResponseDetail,
  SensitivitySummary,
} from '../shared/detail.js';
import type { Finding, SuppressionRule } from '../shared/findings.js';
import type { RepeaterOptions, RepeaterResult } from '../shared/repeater.js';
import type { ProjectInfo, SavedRequest } from '../shared/project.js';
import type { JobProgress, VariationPlan, VariationResultRow } from '../shared/variation.js';
import type { InterceptState, RequestDecision, ResponseDecision } from '../shared/intercept.js';
import { ProjectStore } from './project/projectStore.js';
import { ProxyServer, type CapturedWsMessage } from './proxy/proxyServer.js';
import { Interceptor } from './proxy/interceptor.js';
import { PassiveScanner } from './scanner/passiveScanner.js';
import { Repeater } from './repeater/repeater.js';
import { CookieJar } from './repeater/cookieJar.js';
import { VariationEngine } from './variation/variationEngine.js';
import { ExtensionHost } from '../sdk/host.js';
import { readBodyBytes } from './storage/bodyCollector.js';
import { BUILTIN_TRANSFORMS, applyTransform as applyBuiltinTransform } from './transforms/codec.js';
import { detectSensitive } from './redaction/redactor.js';
import { isLoopbackBind } from './config.js';
import { Logger, rootLogger } from './logging/logger.js';
import type { SecretStore } from './ca/secretStore.js';
import type { Scheme } from '../shared/model.js';

const VIEW_MAX_BYTES = 4 * 1024 * 1024;

export interface SessionOptions {
  appVersion?: string;
  logger?: Logger;
  secretStoreFactory?: (dir: string) => SecretStore;
}

export interface ProxyStatus {
  running: boolean;
  host?: string;
  port?: number;
  loopbackOnly: boolean;
}

export class BelcherSession extends EventEmitter {
  private project?: ProjectStore;
  private proxy?: ProxyServer;
  private readonly interceptor = new Interceptor();
  private scanner?: PassiveScanner;
  private repeater?: Repeater;
  private variation?: VariationEngine;
  private readonly extHost: ExtensionHost;
  private readonly cookieJar = new CookieJar();
  private readonly log: Logger;
  private readonly appVersion: string;
  private readonly secretStoreFactory?: (dir: string) => SecretStore;

  constructor(options: SessionOptions = {}) {
    super();
    this.log = options.logger ?? rootLogger;
    this.appVersion = options.appVersion ?? '0.1.0';
    if (options.secretStoreFactory) this.secretStoreFactory = options.secretStoreFactory;
    this.extHost = new ExtensionHost(
      { maskCookies: true, maskAuthorization: true, maskSecretPatterns: true },
      this.log,
      // Findings created by extensions (from checks OR onTraffic) land here.
      (finding) => {
        const project = this.project;
        if (project && project.findings.upsert(finding)) this.emit('finding', finding);
      },
    );

    // Re-broadcast interceptor + variation events for the UI.
    this.interceptor.on('request-held', (v) => this.emit('intercept-request', v));
    this.interceptor.on('response-held', (v) => this.emit('intercept-response', v));
    this.interceptor.on('pending-changed', () => this.emit('intercept-pending'));
    this.interceptor.on('state', (s) => this.emit('intercept-state', s));
  }

  // ---- project lifecycle ----

  private secretStoreOpt(dir: string): { secretStore?: SecretStore } {
    return this.secretStoreFactory ? { secretStore: this.secretStoreFactory(dir) } : {};
  }

  async createProject(dir: string, name: string, authorizationRef?: string): Promise<void> {
    await this.closeProject();
    this.project = await ProjectStore.create(dir, {
      name,
      appVersion: this.appVersion,
      ...(authorizationRef ? { authorizationRef } : {}),
      ...this.secretStoreOpt(dir),
    });
    this.wireProject();
  }

  async openProject(dir: string): Promise<void> {
    await this.closeProject();
    this.project = await ProjectStore.open(dir, this.secretStoreOpt(dir));
    this.wireProject();
  }

  private wireProject(): void {
    const project = this.requireProject();
    this.scanner = new PassiveScanner(
      project.blobs,
      project.config.redaction,
      [],
      this.log,
      // Extension checks run in the isolated worker via async RPC.
      (payload) =>
        this.extHost.runChecks(payload.exchange, payload.requestBodyText, payload.responseBodyText),
    );
    this.repeater = new Repeater({
      blobStore: project.blobs,
      limits: project.config.limits,
      getScope: () => project.scope,
    });
    this.variation = new VariationEngine({
      blobStore: project.blobs,
      getScope: () => project.scope,
      onExchange: (ex) => this.ingest(ex),
      audit: { append: (e) => project.audit.append(e) },
      logger: this.log,
    });
    this.variation.on('progress', (p: JobProgress) => this.emit('job-progress', p));
    this.variation.on('done', (p: JobProgress) => this.emit('job-done', p));
    this.emit('project-open', project.info);
  }

  async closeProject(): Promise<void> {
    if (this.proxy) await this.stopProxy();
    if (this.variation) this.variation.emergencyStopAll();
    this.project?.close();
    this.project = undefined;
    this.scanner = undefined;
    this.repeater = undefined;
    this.variation = undefined;
  }

  /**
   * Tear the session down for good: stop the proxy, close the project, and
   * terminate the extension host child process (freeing its temp bootstrap
   * dir). The extension host lives for the whole session — NOT per project —
   * so it is only killed here, at app shutdown. Idempotent.
   */
  async dispose(): Promise<void> {
    await this.closeProject();
    await this.extHost.terminate();
    this.removeAllListeners();
  }

  private requireProject(): ProjectStore {
    if (!this.project) throw new Error('No project is open. Create or open a project first.');
    return this.project;
  }

  getProjectInfo(): ProjectInfo | undefined {
    return this.project?.info;
  }

  // ---- capture pipeline ----

  private ingest(ex: HttpExchange): void {
    const project = this.project;
    if (!project) return;
    try {
      project.history.insert(ex);
    } catch (err) {
      this.log.error('failed to persist exchange', { err: String(err) });
    }
    this.emit('exchange', summarize(ex));
    this.extHost.dispatchTraffic(ex);
    // passive scan (async, best-effort)
    if (this.scanner) {
      // Built-in checks plus isolated-worker extension checks (merged by scan()).
      this.scanner
        .scan(ex)
        .then((findings) => {
          for (const f of findings) {
            if (project.findings.upsert(f)) this.emit('finding', f);
          }
        })
        .catch((err) => this.log.warn('scan failed', { err: String(err) }));
    }
  }

  private ingestWsMessage(msg: CapturedWsMessage): void {
    const project = this.project;
    if (!project) return;
    try {
      project.wsMessages.insert({
        id: randomUUID(),
        exchangeId: msg.exchangeId,
        seq: msg.seq,
        direction: msg.direction,
        kind: msg.kind,
        size: msg.size,
        truncated: msg.truncated,
        payload: msg.payload,
        createdAt: msg.createdAt,
      });
      this.emit('ws-message', {
        exchangeId: msg.exchangeId,
        direction: msg.direction,
        kind: msg.kind,
      });
    } catch (err) {
      this.log.warn('failed to persist ws message', { err: String(err) });
    }
  }

  listWsMessages(exchangeId: string): import('../shared/websocket.js').WsMessage[] {
    return this.requireProject().wsMessages.listByExchange(exchangeId);
  }

  // ---- proxy ----

  async startProxy(host?: string, port?: number): Promise<ProxyStatus> {
    const project = this.requireProject();
    if (this.proxy) return this.getProxyStatus();
    const listener = project.config.listener;
    const bindHost = host ?? listener.host;
    const bindPort = port ?? listener.port;
    this.proxy = new ProxyServer({
      ca: project.ca,
      limits: project.config.limits,
      blobStore: project.blobs,
      interceptor: this.interceptor,
      getScope: () => project.scope,
      onExchange: (ex) => this.ingest(ex),
      onWebSocketMessage: (msg) => this.ingestWsMessage(msg),
      captureWebSockets: project.config.captureWebSockets,
      enableHttp2: project.config.interceptHttp2,
      logger: this.log,
    });
    const bound = await this.proxy.start(bindHost, bindPort);
    this.emit('proxy-state', this.getProxyStatus());
    this.log.info('proxy started via session', { ...bound, loopback: isLoopbackBind(bindHost) });
    return this.getProxyStatus();
  }

  async stopProxy(): Promise<ProxyStatus> {
    if (this.proxy) {
      await this.proxy.stop();
      this.proxy = undefined;
    }
    const status = this.getProxyStatus();
    this.emit('proxy-state', status);
    return status;
  }

  getProxyStatus(): ProxyStatus {
    const addr = this.proxy?.address ?? null;
    return {
      running: !!addr,
      ...(addr ? { host: addr.host, port: addr.port } : {}),
      loopbackOnly: addr ? isLoopbackBind(addr.host) : true,
    };
  }

  // ---- CA ----

  getCaInfo(): {
    certPem: string;
    fingerprint: string;
    secureBackend: boolean;
    backendName: string;
  } {
    const project = this.requireProject();
    return {
      certPem: project.ca.certificatePem,
      fingerprint: project.ca.fingerprint,
      secureBackend: false, // filled by main via secret store when available
      backendName: 'project',
    };
  }

  // ---- scope ----

  getScope(): ScopeConfig {
    return this.requireProject().scope;
  }
  setScope(scope: ScopeConfig): void {
    this.requireProject().meta.setScope(scope);
    this.emit('scope-changed', scope);
  }
  getConfig(): EngineConfig {
    return this.requireProject().config;
  }
  setConfig(config: EngineConfig): void {
    this.requireProject().meta.setConfig(config);
  }

  // ---- interception ----

  getInterceptState(): InterceptState {
    return this.interceptor.getState();
  }
  setInterceptState(partial: Partial<InterceptState>): InterceptState {
    this.interceptor.setState(partial);
    return this.interceptor.getState();
  }
  listPendingRequests() {
    return this.interceptor.listPendingRequests();
  }
  listPendingResponses() {
    return this.interceptor.listPendingResponses();
  }
  resolveRequest(id: string, decision: RequestDecision): boolean {
    return this.interceptor.resolveRequest(id, decision);
  }
  resolveResponse(id: string, decision: ResponseDecision): boolean {
    return this.interceptor.resolveResponse(id, decision);
  }

  // ---- history ----

  queryHistory(filter: HistoryFilter): HistoryPage<ExchangeSummary> {
    const page = this.requireProject().history.query(filter);
    return { ...page, rows: page.rows.map(summarize) };
  }

  async getExchangeDetail(id: string): Promise<ExchangeDetail | undefined> {
    const project = this.requireProject();
    const ex = project.history.get(id);
    if (!ex) return undefined;
    const request: RequestDetail = {
      method: ex.request.method,
      target: ex.request.target,
      url: ex.request.url,
      httpVersion: ex.request.httpVersion,
      ...(await this.messageDetail(ex.request.headers, ex.request.body)),
    };
    const detail: ExchangeDetail = {
      id: ex.id,
      createdAt: ex.createdAt,
      source: ex.source,
      scheme: ex.scheme,
      host: ex.host,
      port: ex.port,
      inScope: ex.inScope,
      automated: ex.automated,
      ...(ex.jobId ? { jobId: ex.jobId } : {}),
      ...(ex.error ? { error: ex.error } : {}),
      tags: ex.tags,
      ...(ex.notes ? { notes: ex.notes } : {}),
      ...(ex.timing ? { timing: ex.timing } : {}),
      request,
    };
    if (ex.response) {
      const response: ResponseDetail = {
        statusCode: ex.response.statusCode,
        statusMessage: ex.response.statusMessage,
        httpVersion: ex.response.httpVersion,
        ...(await this.messageDetail(ex.response.headers, ex.response.body)),
      };
      detail.response = response;
    }
    return detail;
  }

  private async messageDetail(
    headers: HttpExchange['request']['headers'],
    body: HttpExchange['request']['body'],
  ): Promise<MessageDetail> {
    const project = this.requireProject();
    let bytes = await readBodyBytes(body, project.blobs);
    let truncatedForView = false;
    if (bytes.length > VIEW_MAX_BYTES) {
      bytes = bytes.subarray(0, VIEW_MAX_BYTES);
      truncatedForView = true;
    }
    const sensitive: SensitivitySummary = detectSensitive(
      headers,
      bytes.toString('utf8').slice(0, 8192),
    );
    return {
      headers,
      bodyBase64: bytes.toString('base64'),
      bodySize: body.size,
      bodyTruncated: body.truncated,
      truncatedForView,
      ...(body.contentEncoding ? { contentEncoding: body.contentEncoding } : {}),
      sensitive,
    };
  }

  updateNotesTags(id: string, notes: string | null, tags: string[]): void {
    this.requireProject().history.updateNotesTags(id, notes, tags);
  }
  clearHistory(): void {
    this.requireProject().history.clear();
  }
  historyCount(): number {
    return this.requireProject().history.count();
  }

  // ---- findings ----

  listFindings(includeSuppressed = false): Finding[] {
    return this.requireProject().findings.list({ includeSuppressed });
  }
  setFindingSuppressed(id: string, suppressed: boolean): void {
    this.requireProject().findings.setSuppressed(id, suppressed);
  }
  addSuppression(rule: SuppressionRule): void {
    this.requireProject().findings.addSuppression(rule);
  }
  listSuppressions(): SuppressionRule[] {
    return this.requireProject().findings.listSuppressions();
  }
  scannerModules(): { module: string; version: string }[] {
    return [...(this.scanner?.listModules() ?? []), ...this.extHost.getCheckModules()];
  }

  // ---- repeater ----

  async sendRepeater(
    target: { scheme: Scheme; host: string; port: number; raw: string },
    options: RepeaterOptions,
  ): Promise<RepeaterResult> {
    if (!this.repeater) throw new Error('No project open.');
    const result = await this.repeater.send(
      target,
      options,
      options.useCookieJar ? this.cookieJar : undefined,
    );
    this.ingest(result.exchange);
    return result;
  }
  listCookies() {
    return this.cookieJar.list();
  }
  clearCookies(): void {
    this.cookieJar.clear();
  }
  saveRequest(req: SavedRequest): void {
    this.requireProject().saveRequest(req);
  }
  listSavedRequests(): SavedRequest[] {
    return this.requireProject().listSavedRequests();
  }

  // ---- variation ----

  createVariationJob(plan: VariationPlan): { id: string; count: number } {
    if (!this.variation) throw new Error('No project open.');
    return this.variation.createJob(plan);
  }
  runVariationJob(id: string): Promise<JobProgress> {
    if (!this.variation) throw new Error('No project open.');
    return this.variation.run(id);
  }
  pauseVariationJob(id: string): void {
    this.variation?.pause(id);
  }
  resumeVariationJob(id: string): void {
    this.variation?.resume(id);
  }
  stopVariationJob(id: string): void {
    this.variation?.stop(id);
  }
  listVariationJobs(): JobProgress[] {
    return this.variation?.listProgress() ?? [];
  }
  getVariationResults(id: string): VariationResultRow[] {
    return this.variation?.getResults(id) ?? [];
  }

  /** Global emergency stop for ALL automated work. */
  emergencyStop(): void {
    this.variation?.emergencyStopAll();
    this.interceptor.releaseAll();
    this.emit('emergency-stop');
    this.log.warn('EMERGENCY STOP invoked');
  }

  // ---- audit ----

  listAudit(limit = 500) {
    return this.requireProject().audit.list(limit);
  }

  // ---- extensions ----

  async loadExtension(
    manifest: import('../sdk/api.js').ExtensionManifest,
    source: string,
    granted: import('../sdk/api.js').Permission[],
  ): Promise<void> {
    // The scanner's extension runner queries the worker each scan, so no
    // scanner rebuild is needed after loading a new extension.
    await this.extHost.load(manifest, source, granted);
  }
  listExtensions() {
    return this.extHost.listExtensions();
  }
  extensionTransforms() {
    return this.extHost
      .getTransforms()
      .map((t) => ({ id: t.id, label: t.label, category: t.category }));
  }

  listTransforms(): { id: string; label: string; category: string }[] {
    const builtin = BUILTIN_TRANSFORMS.map((t) => ({
      id: t.id,
      label: t.label,
      category: t.category,
    }));
    return [...builtin, ...this.extensionTransforms()];
  }

  async applyTransform(id: string, input: string): Promise<string> {
    if (this.extHost.hasTransform(id)) return this.extHost.applyTransform(id, input);
    return applyBuiltinTransform(id, input);
  }

  // ---- export / import ----

  async exportProject(maxBodyBytes?: number) {
    return this.requireProject().export(maxBodyBytes !== undefined ? { maxBodyBytes } : {});
  }
  async importProject(
    data: Awaited<ReturnType<ProjectStore['export']>>,
    dir: string,
  ): Promise<void> {
    await this.closeProject();
    this.project = await ProjectStore.import(data, dir, this.secretStoreOpt(dir));
    this.wireProject();
  }
}

function summarize(ex: HttpExchange): ExchangeSummary {
  let path = ex.request.target;
  try {
    path = new URL(ex.request.url).pathname;
  } catch {
    /* keep target */
  }
  return {
    id: ex.id,
    createdAt: ex.createdAt,
    source: ex.source,
    scheme: ex.scheme,
    host: ex.host,
    port: ex.port,
    method: ex.request.method,
    url: ex.request.url,
    path,
    inScope: ex.inScope,
    automated: ex.automated,
    ...(ex.response ? { statusCode: ex.response.statusCode } : {}),
    ...(ex.response && mimeType(ex.response.headers)
      ? { mime: mimeType(ex.response.headers) }
      : {}),
    responseLength: ex.response?.body.size ?? 0,
    ...(ex.timing?.durationMs !== undefined ? { durationMs: ex.timing.durationMs } : {}),
    hasResponse: !!ex.response,
    ...(ex.error ? { error: ex.error } : {}),
    tags: ex.tags,
  };
}
