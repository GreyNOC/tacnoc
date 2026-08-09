/**
 * TacnocSession — the engine facade the desktop app talks to.
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
import * as path from 'node:path';
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
import { ProjectStore, resolveProjectDir } from './project/projectStore.js';
import { ProxyServer, type CapturedWsMessage } from './proxy/proxyServer.js';
import { Interceptor } from './proxy/interceptor.js';
import { PassiveScanner } from './scanner/passiveScanner.js';
import { Repeater } from './repeater/repeater.js';
import { CookieJar } from './repeater/cookieJar.js';
import { VariationEngine } from './variation/variationEngine.js';
import { ExtensionHost } from '../sdk/host.js';
import { readBodyBytes } from './storage/bodyCollector.js';
import { BUILTIN_TRANSFORMS, applyTransform as applyBuiltinTransform } from './transforms/codec.js';
import { detectSensitive, Redactor, redactAiValue } from './redaction/redactor.js';
import { isLoopbackBind } from './config.js';
import { Logger, rootLogger } from './logging/logger.js';
import type { SecretStore } from './ca/secretStore.js';
import type { Scheme } from '../shared/model.js';
import type { TargetMap } from '../shared/target.js';
import { buildTargetMap } from './target/siteMap.js';
import { emptyScope } from '../shared/scope.js';
import type { AiConfig, AiKeyStatus, MeshRun, MeshRunPlan, MeshRunProgress } from '../shared/ai.js';
import { normalizeAiConfig } from '../shared/ai.js';
import { MeshOrchestrator } from './ai/orchestrator.js';
import { buildTools } from './ai/tools.js';
import { AnthropicProvider } from './ai/providers/anthropic.js';
import type {
  CaRevocation,
  CaStatus,
  EngagementProfile,
  IdentityCompliance,
  PreflightReport,
  WorkspaceSummary,
} from '../shared/engagement.js';
import { defaultEngagementProfile, validateEngagementProfile } from '../shared/engagement.js';
import { checkIdentity, identityEnforced } from './engagement/identity.js';
import { buildPreflight } from './engagement/preflight.js';
import {
  proposeScope,
  type ProposalSource,
  type ScopeProposal,
} from './engagement/scopeProposal.js';
import { buildDocScan, isReadableDoc, nameRank, type DocScanResult } from './engagement/docScan.js';

import { caInstallInstructions } from './ca/installInstructions.js';
import { listWorkspace, readWorkspaceFile, searchWorkspace } from './workspace/workspace.js';
import { rankAttackSurface, type SurfaceRanking } from './analysis/surface.js';
import { proveDifferential, type ProofResult } from './analysis/proof.js';
import {
  HuntMemory,
  type HuntOutcomeInput,
  type HuntOutcomeRecord,
  type HuntRecallResult,
} from './analysis/huntMemory.js';

/**
 * Turn an operator-supplied project name into a directory name.
 *
 * The project directory is created inside a folder the operator picked, from
 * text they typed, so it must not be able to climb out of that folder or produce
 * a name the filesystem refuses.
 */
function sanitizeProjectName(name: string): string {
  const RESERVED = new Set(['<', '>', ':', '"', '/', '?', '*', '|', String.fromCharCode(92)]);
  let out = '';
  for (const ch of name) {
    const code = ch.codePointAt(0) ?? 0;
    if (code < 0x20 || code === 0x7f) continue; // control characters
    out += RESERVED.has(ch) ? '-' : ch;
  }
  // Windows silently drops a trailing dot or space, which would otherwise let
  // "foo." and "foo" resolve to the same directory.
  out = out
    .replace(/[. ]+$/, '')
    .replace(/\s+/g, ' ')
    .trim();
  return out.slice(0, 64) || 'Engagement';
}

const VIEW_MAX_BYTES = 4 * 1024 * 1024;
const ENGAGEMENT_KEY = 'project.engagement';
const CA_HISTORY_KEY = 'project.ca.history';
const MAX_CA_HISTORY = 50;

export interface SessionOptions {
  appVersion?: string;
  logger?: Logger;
  secretStoreFactory?: (dir: string) => SecretStore;
  /** App-level secret store for the AI provider API key (never per-project). */
  aiSecretStore?: SecretStore;
  /**
   * Directory for the cross-engagement hunt memory. App-level on purpose: the
   * point is that what one hunt learned is available to the next, including in
   * a different project. Omit to disable the feature entirely.
   */
  huntMemoryDir?: string;
}

export interface ProxyStatus {
  running: boolean;
  host?: string;
  port?: number;
  loopbackOnly: boolean;
}

export class TacnocSession extends EventEmitter {
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
  private readonly aiSecretStore?: SecretStore;
  private readonly huntMemory?: HuntMemory;
  private readonly mesh: MeshOrchestrator;
  private static readonly AI_KEY = 'anthropic.apiKey';
  /** Best-effort secret-pattern redaction for the AI egress path (opt-in). */
  private readonly aiRedactor = new Redactor({
    maskCookies: true,
    maskAuthorization: true,
    maskSecretPatterns: true,
  });

  constructor(options: SessionOptions = {}) {
    super();
    this.log = options.logger ?? rootLogger;
    this.appVersion = options.appVersion ?? '0.1.0';
    if (options.secretStoreFactory) this.secretStoreFactory = options.secretStoreFactory;
    if (options.aiSecretStore) this.aiSecretStore = options.aiSecretStore;
    if (options.huntMemoryDir) {
      this.huntMemory = new HuntMemory({ directory: options.huntMemoryDir });
    }
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

    // The AI mesh lives for the whole session; its runs are project-scoped and
    // read scope/audit live from the open project. Emergency stop aborts every
    // in-flight mesh run alongside the variation jobs.
    this.mesh = new MeshOrchestrator({
      getScope: () => this.project?.scope ?? emptyScope(),
      audit: (e) => this.project?.audit.append(e),
      onStep: (s) => this.emit('mesh-step', s),
      onProgress: (p) => this.emit('mesh-progress', p),
      redactResult: (v) => redactAiValue(v, this.aiRedactor),
      logger: this.log,
      briefing: () => this.engineBriefing(),
    });
    this.on('emergency-stop', () => this.mesh.stopAll());
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

  /**
   * Open a project, accepting either the project directory itself or a hunt
   * folder that contains one.
   *
   * Projects live inside the folder that holds the engagement — `TiffanyCo/
   * Tiffany.tacnocproj` next to `ENGAGEMENT.md` and the notes. Pointing the
   * open dialog at the hunt folder is the obvious thing to do, and it used to
   * fail with a raw `ENOENT ... belcher.db` naming a file the operator had
   * never heard of. Resolve it instead, and when the answer is genuinely
   * ambiguous, name the candidates rather than guessing.
   */
  async openProject(dir: string): Promise<void> {
    const resolved = await resolveProjectDir(dir);
    await this.closeProject();
    this.project = await ProjectStore.open(resolved, this.secretStoreOpt(resolved));
    this.wireProject();
  }

  private wireProject(): void {
    const project = this.requireProject();
    this.buildConfigComponents(project);
    this.variation = new VariationEngine({
      blobStore: project.blobs,
      getScope: () => project.scope,
      onExchange: (ex) => this.ingest(ex),
      audit: { append: (e) => project.audit.append(e) },
      logger: this.log,
      getEngagement: () => this.engagementProfileOrUndefined(),
    });
    this.variation.on('progress', (p: JobProgress) => this.emit('job-progress', p));
    this.variation.on('done', (p: JobProgress) => this.emit('job-done', p));
    this.emit('project-open', project.info);
  }

  /**
   * Build the config-derived components (passive scanner + repeater). They
   * snapshot redaction/limits at construction, so this is re-run by setConfig()
   * to apply config changes without requiring a project reopen.
   */
  private buildConfigComponents(project: ProjectStore): void {
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
      getEngagement: () => this.engagementProfileOrUndefined(),
    });
  }

  /** Profile for the enforcement path, tolerating a project closed mid-flight. */
  private engagementProfileOrUndefined(): EngagementProfile | undefined {
    return this.project ? this.getEngagementProfile() : undefined;
  }

  async closeProject(): Promise<void> {
    if (this.proxy) await this.stopProxy();
    if (this.variation) this.variation.emergencyStopAll();
    this.mesh.stopAll();
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
            if (project.findings.upsert(f, ex.host)) this.emit('finding', f);
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
    const proxy = new ProxyServer({
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
    // Assign this.proxy only AFTER a successful listen. If start() rejects
    // (e.g. EADDRINUSE), this.proxy stays undefined so the `if (this.proxy)`
    // guard above still permits a retry — otherwise a single failed start would
    // wedge the proxy as permanently unstartable until the project is reopened.
    const bound = await proxy.start(bindHost, bindPort);
    this.proxy = proxy;
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
    const backend = project.caKeyBackend;
    return {
      certPem: project.ca.certificatePem,
      fingerprint: project.ca.fingerprint,
      secureBackend: backend.secure,
      backendName: backend.name,
    };
  }

  /** Full certificate lifecycle state, including revocation history and evidence
   *  that interception is actually working. */
  getCaStatus(): CaStatus {
    const project = this.requireProject();
    const backend = project.caKeyBackend;
    const certificate = project.ca.status();
    const revocation = project.ca.revocation;
    return {
      ...(certificate ? { certificate } : {}),
      interceptionEnabled: project.ca.active,
      ...(revocation.revokedAt !== undefined ? { revokedAt: revocation.revokedAt } : {}),
      ...(revocation.reason ? { revokedReason: revocation.reason } : {}),
      secureBackend: backend.secure,
      backendName: backend.name,
      history: project.meta.getJson<CaRevocation[]>(CA_HISTORY_KEY) ?? [],
      observedHttpsExchanges: project.history.countByScheme('https'),
      installInstructions: caInstallInstructions(),
    };
  }

  /**
   * Issue a fresh CA, replacing the current one. Every client that trusted the
   * old certificate will reject interception until the new one is installed —
   * that break is the point of the operation, so it is audited and surfaced,
   * never silent.
   */
  async rotateCa(reason = '', actor: 'user' | 'ai-mesh' = 'user'): Promise<CaStatus> {
    const project = this.requireProject();
    const replaced = await project.ca.rotate(reason);
    if (replaced) this.recordCaEvent(project, replaced);
    // Apply to connections already open, not just the next CONNECT.
    this.proxy?.refreshCa();
    project.audit.append({
      ts: Date.now(),
      actor,
      action: 'ca.rotated',
      detail: { reason, replacedFingerprint: replaced?.fingerprint ?? null },
    });
    const status = this.getCaStatus();
    this.emit('ca-changed', status);
    return status;
  }

  /**
   * Destroy this project's CA. TLS interception stops — HTTPS CONNECTs are
   * relayed through unread — until `rotateCa` issues a new one.
   */
  async revokeCa(reason = '', actor: 'user' | 'ai-mesh' = 'user'): Promise<CaStatus> {
    const project = this.requireProject();
    const revoked = await project.ca.revoke(reason);
    if (revoked) this.recordCaEvent(project, revoked);
    // A browser holds an HTTPS tunnel open for minutes; without this, revoking
    // would leave those tunnels decrypting while the status said otherwise.
    this.proxy?.refreshCa();
    project.audit.append({
      ts: Date.now(),
      actor,
      action: 'ca.revoked',
      detail: { reason, fingerprint: revoked?.fingerprint ?? null },
    });
    const status = this.getCaStatus();
    this.emit('ca-changed', status);
    return status;
  }

  private recordCaEvent(project: ProjectStore, record: CaRevocation): void {
    const history = project.meta.getJson<CaRevocation[]>(CA_HISTORY_KEY) ?? [];
    history.unshift(record);
    project.meta.setJson(CA_HISTORY_KEY, history.slice(0, MAX_CA_HISTORY));
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
    const project = this.requireProject();
    project.meta.setConfig(config);
    // Apply redaction/limit changes to the scanner + repeater right away (they
    // snapshot config at build time). The proxy reads config live on its next
    // start; the variation engine takes limits per-job from the plan.
    this.buildConfigComponents(project);
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

  getTargetMap(maxExchanges = 100_000): TargetMap {
    const project = this.requireProject();
    const metadata = project.history.siteMapRows(maxExchanges);
    return buildTargetMap(metadata.rows, project.scope, metadata.total);
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
  removeSuppression(id: string): void {
    this.requireProject().findings.removeSuppression(id);
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

  /**
   * Global emergency stop for ALL automated work. The mesh is halted by the
   * 'emergency-stop' listener wired in the constructor.
   */
  emergencyStop(): void {
    this.variation?.emergencyStopAll();
    this.interceptor.releaseAll();
    this.emit('emergency-stop');
    this.log.warn('EMERGENCY STOP invoked');
  }

  // ---- engagement profile, workspace, preflight ----

  getEngagementProfile(): EngagementProfile {
    const stored = this.requireProject().meta.getJson<Partial<EngagementProfile>>(ENGAGEMENT_KEY);
    // Merge over defaults so a profile written by an older version (or an
    // imported project) is never missing a field the enforcement path reads.
    return { ...defaultEngagementProfile(), ...(stored ?? {}) };
  }

  /**
   * Persist the engagement profile. Refuses an invalid one outright: these
   * values are written into the wire bytes of every generated request, so a
   * CR/LF in a header value is header injection against a third party, not a
   * cosmetic problem.
   */
  setEngagementProfile(profile: EngagementProfile): void {
    const project = this.requireProject();
    const merged: EngagementProfile = { ...defaultEngagementProfile(), ...profile };
    const problems = validateEngagementProfile(merged);
    if (problems.length) {
      throw new Error(`engagement profile rejected: ${problems.join('; ')}`);
    }
    const previous = project.meta.getJson<EngagementProfile>(ENGAGEMENT_KEY);
    project.meta.setJson(ENGAGEMENT_KEY, merged);
    project.audit.append({
      ts: Date.now(),
      actor: 'user',
      action: 'engagement.profile-updated',
      detail: {
        userAgent: merged.userAgent.required,
        enforce: merged.userAgent.enforce,
        identityHeaders: merged.identityHeaders.map((h) => h.name),
        workspaceDir: merged.workspaceDir || '(project directory)',
        wasEnforced: previous?.userAgent?.enforce ?? false,
      },
    });
    this.emit('engagement-changed', merged);
  }

  /** The folder the AI may read: the operator's choice, or the project itself. */
  workspaceRoot(): string {
    const project = this.requireProject();
    return this.getEngagementProfile().workspaceDir.trim() || project.directory;
  }

  listWorkspace(options: { maxEntries?: number; maxDepth?: number } = {}) {
    return listWorkspace(this.workspaceRoot(), options);
  }

  readWorkspaceFile(relativePath: string, maxBytes?: number) {
    return readWorkspaceFile(this.workspaceRoot(), relativePath, maxBytes);
  }

  searchWorkspace(query: string, options: { maxMatches?: number; maxFiles?: number } = {}) {
    return searchWorkspace(this.workspaceRoot(), query, options);
  }

  private async workspaceSummary(): Promise<WorkspaceSummary> {
    const project = this.requireProject();
    const root = this.workspaceRoot();
    const isProjectDir = root === project.directory;
    try {
      const listing = await listWorkspace(root);
      return {
        root: listing.root,
        isProjectDir,
        fileCount: listing.fileCount,
        totalBytes: listing.totalBytes,
        notableFiles: listing.notableFiles,
        ...(await this.suggestWorkspaceRoot(listing.fileCount)),
      };
    } catch (err) {
      return {
        root,
        isProjectDir,
        fileCount: 0,
        totalBytes: 0,
        notableFiles: [],
        error: err instanceof Error ? err.message : String(err),
        ...(await this.suggestWorkspaceRoot(0)),
      };
    }
  }

  /**
   * Everything the engine knows about this engagement, as text.
   *
   * This is the recon a run gets when the model declines to write one: readiness,
   * the enforced scope, the engagement folder, and the ranked attack surface are
   * all computed here, deterministically, from the project. Handing it over keeps
   * a declined turn from costing the whole run.
   */
  async engineBriefing(): Promise<string> {
    const lines: string[] = [
      'ENGINE BRIEFING — produced by TACNOC itself, from the open project. Every fact below is ' +
        'read from the project, not inferred.',
      '',
    ];

    const scope = this.project?.scope ?? emptyScope();
    const included = scope.include.filter((r) => r.enabled !== false);
    lines.push('## Scope (enforced by the engine; out-of-scope requests are refused)');
    lines.push(
      included.length
        ? included.map((r) => `- ${r.hostMatch}: ${r.host}`).join('\n')
        : '- (empty — the fail-closed gate would refuse every request)',
    );
    const excluded = scope.exclude.filter((r) => r.enabled !== false);
    if (excluded.length) {
      lines.push('', '### Explicitly excluded');
      lines.push(excluded.map((r) => `- ${r.hostMatch}: ${r.host}`).join('\n'));
    }
    lines.push('');

    let blockers: string[] = [];
    try {
      const report = await this.getPreflight();
      blockers = report.checks.filter((c) => c.severity === 'blocker').map((c) => c.title);
      lines.push(`## Readiness: ${report.ready ? 'ready' : 'NOT ready — blockers below'}`);
      for (const c of report.checks) {
        lines.push(`- [${c.severity}] ${c.title}${c.detail ? ` — ${c.detail}` : ''}`);
      }
      lines.push('');
    } catch {
      /* readiness is best-effort here */
    }

    try {
      const listing = await this.listWorkspace();
      lines.push(`## Engagement folder: ${listing.root}`);
      lines.push(
        listing.fileCount
          ? `${listing.fileCount} document(s): ${listing.notableFiles.slice(0, 20).join(', ')}`
          : 'No readable documents. Read them with the workspace tools if this is wrong.',
      );
      lines.push('');
    } catch {
      /* folder is best-effort here */
    }

    try {
      const ranking = this.rankAttackSurface(20);
      lines.push('## Ranked attack surface (in-scope endpoints, best first)');
      lines.push(
        ranking.leads.length
          ? ranking.leads
              .map(
                (l, i) =>
                  `${i + 1}. ${l.methods.join('/')} ${l.site}${l.path} — ` +
                  `${l.classes.map((c) => `${c.kind} (${c.because.join(', ')})`).join('; ') || 'no class signal'}` +
                  ` [exchange ${l.exchangeId}]`,
              )
              .join('\n')
          : 'No in-scope endpoints have been captured yet. Proxy some traffic through the target first.',
      );
      if (ranking.outOfScopeSkipped > 0) {
        lines.push(`(${ranking.outOfScopeSkipped} captured endpoint(s) skipped as out of scope.)`);
      }
    } catch {
      /* ranking is best-effort here */
    }

    // A recon turn that spots a blocker halts the run by answering `BLOCKED: …`.
    // When the model declines and this briefing stands in for recon, that halt
    // has to come from here or it is silently lost — and the run would test an
    // engagement that preflight already said was not ready, with nobody having
    // reviewed it. The engine knows the blockers; it does not need a model to
    // decide this one.
    if (blockers.length) {
      return [
        `BLOCKED: preflight reports ${blockers.length} blocker(s) and no recon review was ` +
          `produced for this run: ${blockers.join('; ')}. Nothing was tested. Clear the blockers ` +
          `in Engagement and re-run.`,
        '',
        ...lines,
      ].join('\n');
    }
    return lines.join('\n');
  }

  /**
   * Look one level up when the configured root has nothing to read.
   *
   * The usual layout puts the project *inside* the hunt folder, next to the
   * engagement material — so the default root (the project directory) holds the
   * database and no documents, and everything worth reading is in the parent.
   * That produced the worst possible failure: the scope gate correctly refused
   * to open, having been pointed at a directory with no scope in it.
   *
   * This only ever *suggests*. Widening what leaves the machine is the
   * operator's call, made once, in the open — it is not something to infer.
   */
  private async suggestWorkspaceRoot(
    currentFileCount: number,
  ): Promise<{ suggestedRoot?: string; suggestedFileCount?: number }> {
    const project = this.requireProject();
    // Only when the operator hasn't already chosen a folder, and the one in use
    // is genuinely empty of readable material.
    if (currentFileCount > 0) return {};
    if (this.getEngagementProfile().workspaceDir.trim()) return {};
    const parent = path.dirname(project.directory);
    if (parent === project.directory) return {}; // filesystem root
    try {
      // Walk at the SAME depth the workspace reader uses once the folder is
      // adopted. Counting a shallower tree understated the consent figure: the
      // banner said "12 document(s)" and switching then exposed everything down
      // to MAX_DEPTH. The number the operator agrees to has to be the number
      // that egresses.
      const listing = await listWorkspace(parent);
      if (listing.fileCount === 0) return {};
      return { suggestedRoot: listing.root, suggestedFileCount: listing.fileCount };
    } catch {
      return {};
    }
  }

  /**
   * Compliance measured against traffic that was actually sent, not against
   * configuration. Proxy-captured traffic is excluded: the browser's own
   * User-Agent is not ours to control and is never rewritten.
   */
  getIdentityCompliance(sampleSize = 100): IdentityCompliance {
    const project = this.requireProject();
    const profile = this.getEngagementProfile();
    const required = profile.userAgent.required.trim();
    const limit = Math.min(Math.max(Math.trunc(sampleSize), 1), 500);
    const generated = project.history
      .query({ limit, sort: 'desc' })
      .rows.filter((ex) => ex.source === 'repeater' || ex.source === 'variation');

    const observed = new Set<string>();
    const missingHeaders = new Set<string>();
    let compliant = 0;
    for (const exchange of generated) {
      const check = checkIdentity(exchange.request.headers, profile);
      if (check.userAgent) observed.add(check.userAgent);
      for (const name of check.missing) missingHeaders.add(name);
      if (check.compliant) compliant += 1;
    }
    return {
      applicable: required.length > 0 || profile.identityHeaders.length > 0,
      required,
      enforced: identityEnforced(profile),
      sampled: generated.length,
      compliant,
      observedUserAgents: [...observed].slice(0, 10),
      missingHeaders: [...missingHeaders],
    };
  }

  // ---- proof of exploit + hunt memory ----

  /**
   * Rank in-scope endpoints by which defect class each most likely hides.
   * Deterministic and offline — it reorders attention and cannot add a target.
   */
  rankAttackSurface(limit = 25): SurfaceRanking {
    return rankAttackSurface(this.getTargetMap(), limit);
  }

  /**
   * Grade a control-versus-test differential from two captured exchanges. The
   * engine reads both and decides; a caller cannot assert a proof into
   * existence, which is what keeps a confident hypothesis from becoming a
   * reported finding on its own.
   */
  async proveFinding(
    controlExchangeId: string,
    testExchangeId: string,
    claim: string,
  ): Promise<ProofResult> {
    const control = await this.getExchangeDetail(controlExchangeId);
    if (!control) throw new Error(`control exchange ${controlExchangeId} not found`);
    const test = await this.getExchangeDetail(testExchangeId);
    if (!test) throw new Error(`test exchange ${testExchangeId} not found`);
    const result = proveDifferential(control, test, claim);
    this.project?.audit.append({
      ts: Date.now(),
      actor: 'ai-mesh',
      action: `proof.${result.outcome}`,
      target: test.request.url,
      detail: { claim, control: controlExchangeId, test: testExchangeId },
    });
    return result;
  }

  /** True when a cross-engagement hunt memory is configured. */
  get huntMemoryEnabled(): boolean {
    return this.huntMemory !== undefined;
  }

  /** Record what a hypothesis turned out to be, for future hunts to read. */
  async recordHuntOutcome(input: HuntOutcomeInput): Promise<HuntOutcomeRecord | undefined> {
    if (!this.huntMemory) return undefined;
    const program = input.program || this.engagementProfileOrUndefined()?.program || '';
    return this.huntMemory.record({ ...input, program });
  }

  /**
   * Merge what previous hunts learned about this shape and class.
   *
   * Scoped to the open engagement, and it FAILS CLOSED. Recall is read into an
   * AI context that is egressed to a model provider, so an unscoped query would
   * carry one client's notes and route shapes into another client's run — and
   * "recall everything" is exactly the query the recon prompt naturally makes.
   *
   * The label falls back through the engagement profile, the project's recorded
   * authorization reference, and finally the project name, because a freshly
   * created project has an empty profile and an earlier version silently
   * degraded that case into an unfiltered cross-client read. If no label can be
   * derived at all, nothing is recalled rather than everything.
   *
   * Cross-program recall is available, but only when the OPERATOR asks for it
   * (`allPrograms`) — never by a caller supplying a `program` string, since the
   * model that calls this reads untrusted target content.
   */
  async recallHuntHistory(
    query: { host?: string; pathShape?: string; klass?: string } = {},
    options: { allPrograms?: boolean } = {},
  ): Promise<HuntRecallResult> {
    if (!this.huntMemory) {
      return {
        entries: [],
        recordsConsidered: 0,
        notes: ['Hunt memory is not configured, so no prior outcomes are available.'],
      };
    }
    if (options.allPrograms) {
      const result = await this.huntMemory.recall(query);
      result.notes.push(
        'Recalled across ALL engagements at the operator’s request. Hostnames from other programs are withheld.',
      );
      return result;
    }
    const program = this.currentProgramLabel();
    if (!program) {
      return {
        entries: [],
        recordsConsidered: 0,
        notes: [
          'No prior hunts were recalled: this engagement has no program label, and hunt memory is shared across engagements, so an unscoped read could disclose another client’s work. Set the program name or authorization reference in the Engagement view to use hunt memory here.',
        ],
      };
    }
    const result = await this.huntMemory.recall({ ...query, program });
    result.notes.push(`Scoped to the "${program}" engagement.`);
    return result;
  }

  /**
   * Read the engagement folder and propose scope entries, with the document
   * line each came from. Proposals only — nothing is written to scope, because
   * a document is a claim about authorization, not authorization itself.
   */
  /**
   * Read the engagement folder and say which files matter to the hunt.
   *
   * A real hunt folder is mostly enumeration output. Reporting "342 documents"
   * tells the operator nothing; six of those decide what may legitimately be
   * touched and the rest are `amass` dumps. Filename order decides what gets
   * READ (reading is bounded), and content decides what each file IS.
   *
   * Deterministic on purpose — the ranking feeds the scope decision, so it has
   * to be reproducible and auditable. The model reads this; it does not produce
   * it.
   */
  async scanEngagementDocs(options: { maxRead?: number } = {}): Promise<DocScanResult> {
    const maxRead = Math.min(Math.max(Math.trunc(options.maxRead ?? 120), 1), 400);
    const root = this.workspaceRoot();
    const notes: string[] = [];
    let listing;
    try {
      listing = await listWorkspace(root);
    } catch (err) {
      return buildDocScan(
        root,
        [],
        [],
        [
          `The engagement folder could not be read: ${err instanceof Error ? err.message : String(err)}`,
        ],
      );
    }

    // Every file, not just the text ones. Filtering on `readable` here dropped
    // binaries from the result entirely, so the totals described a smaller folder
    // than the one on disk — and a silently shorter list reads as coverage.
    const files = listing.entries.filter((e) => e.kind === 'file');
    // Rank by filename first so the brief is never crowded out of the read
    // budget by tool output that happened to sort earlier.
    const ordered = files
      .map((e) => ({
        entry: e,
        rank: nameRank(e.path).score,
        readable: e.readable !== false && isReadableDoc(e.path),
      }))
      .sort((a, b) => Number(b.readable) - Number(a.readable) || b.rank - a.rank);

    const read: { path: string; content: string; bytes: number }[] = [];
    const listed: { path: string; bytes: number }[] = [];
    for (const item of ordered) {
      const bytes = item.entry.size ?? 0;
      if (!item.readable || read.length >= maxRead) {
        listed.push({ path: item.entry.path, bytes });
        continue;
      }
      try {
        const file = await this.readWorkspaceFile(item.entry.path);
        read.push({ path: item.entry.path, content: file.content, bytes });
      } catch {
        // Binary, too large, or refused by the sandbox. Still report it as seen
        // rather than dropping it — a silently shorter list reads as coverage.
        listed.push({ path: item.entry.path, bytes });
      }
    }

    if (listed.length) {
      notes.push(
        `${read.length} document(s) were read in full; ${listed.length} more were classified by ` +
          'filename only (binary, oversized, or beyond the read budget).',
      );
    }
    if (listing.truncated) {
      notes.push('The folder is larger than the listing bound, so this is not every file in it.');
    }
    return buildDocScan(listing.root, read, listed, notes);
  }

  /**
   * Open a hunt folder that predates TACNOC, creating the project inside it.
   *
   * The folder comes first in real work: the program policy, the brief, prior
   * reports, and `recon/` all exist before anyone opens a proxy. Requiring a
   * TACNOC project to exist before that material can be used had it backwards,
   * and made adopting an in-flight engagement a manual chore of creating a
   * project and then re-pointing the engagement folder at its own parent.
   *
   * Picking the folder IS the egress decision, and it is recorded as one: the
   * workspace is set to exactly the folder the operator chose, and the audit log
   * says so. Nothing is inferred and nothing is widened later.
   */
  async adoptHuntFolder(
    dir: string,
    options: { name?: string; authorizationRef?: string } = {},
  ): Promise<{ projectDirectory: string; created: boolean; scan: DocScanResult }> {
    let projectDirectory: string;
    let created = false;
    try {
      projectDirectory = await resolveProjectDir(dir);
      await this.openProject(projectDirectory);
    } catch {
      // No project here yet — this is the adopt case.
      const name = (options.name ?? path.basename(dir)).trim() || 'Engagement';
      projectDirectory = path.join(dir, `${sanitizeProjectName(name)}.tacnocproj`);
      await this.createProject(
        projectDirectory,
        name,
        options.authorizationRef?.trim() || undefined,
      );
      created = true;
    }

    // Point the engagement folder at what the operator actually picked. When the
    // project is nested inside it, that is the folder holding the material; when
    // they picked the project directory itself, this is a no-op.
    const profile = this.getEngagementProfile();
    if (dir !== projectDirectory && !profile.workspaceDir.trim()) {
      await this.setEngagementProfile({ ...profile, workspaceDir: dir });
    }

    const scan = await this.scanEngagementDocs();
    this.project?.audit.append({
      ts: Date.now(),
      actor: 'user',
      action: created ? 'project.adopted-folder' : 'project.opened-folder',
      detail: {
        folder: dir,
        projectDirectory,
        engagementFolder: this.workspaceRoot(),
        documentsSeen: scan.filesSeen,
        documentsRead: scan.filesRead,
        scopeDocuments: scan.byKind.scope,
      },
    });
    return { projectDirectory, created, scan };
  }

  async proposeScopeFromWorkspace(): Promise<ScopeProposal> {
    const listing = await this.listWorkspace();
    const readable = listing.entries.filter((e) => e.kind === 'file' && e.readable);
    // Read the likely policy documents first, then anything else, bounded.
    const ordered = [
      ...readable.filter((e) => listing.notableFiles.includes(e.path)),
      ...readable.filter((e) => !listing.notableFiles.includes(e.path)),
    ].slice(0, 60);

    const sources: ProposalSource[] = [];
    for (const entry of ordered) {
      try {
        const file = await this.readWorkspaceFile(entry.path);
        sources.push({ path: file.path, content: file.content });
      } catch {
        continue; // unreadable/binary: skip rather than fail the whole proposal
      }
    }
    return proposeScope(sources);
  }

  /** Erase the cross-engagement hunt memory. */
  async clearHuntMemory(): Promise<void> {
    await this.huntMemory?.clear();
    this.project?.audit.append({
      ts: Date.now(),
      actor: 'user',
      action: 'hunt-memory.cleared',
    });
  }

  /**
   * A stable label identifying THIS engagement, for scoping hunt memory.
   * Falls back to the project's own identity so a project whose engagement
   * profile was never filled in still gets its own scope rather than none.
   */
  private currentProgramLabel(): string | undefined {
    const project = this.project;
    if (!project) return undefined;
    const profile = this.getEngagementProfile();
    return (
      profile.program.trim() ||
      profile.authorizationRef.trim() ||
      project.info?.authorizationRef?.trim() ||
      project.info?.name?.trim() ||
      undefined
    );
  }

  /** The single readiness check the mesh runs before it plans anything. */
  async getPreflight(): Promise<PreflightReport> {
    const project = this.project;
    if (!project) {
      return buildPreflight({
        profile: defaultEngagementProfile(),
        scope: emptyScope(),
        ca: {
          interceptionEnabled: false,
          secureBackend: false,
          backendName: 'none',
          history: [],
          observedHttpsExchanges: 0,
          installInstructions: caInstallInstructions(),
        },
        identity: {
          applicable: false,
          required: '',
          enforced: false,
          sampled: 0,
          compliant: 0,
          observedUserAgents: [],
          missingHeaders: [],
        },
        proxy: this.getProxyStatus(),
        workspace: { root: '', isProjectDir: false, fileCount: 0, totalBytes: 0, notableFiles: [] },
        history: { exchanges: 0, findings: 0 },
      });
    }
    const info = project.info;
    // Only read the folder for proposals when scope is actually empty — that is
    // the one case where the answer changes what the operator should do next.
    let proposedScopeHosts: string[] = [];
    if (project.scope.include.filter((r) => r.enabled !== false).length === 0) {
      try {
        const proposal = await this.proposeScopeFromWorkspace();
        // Include the AMBIGUOUS candidates too. Most hunt folders are a bare
        // list of assets with no "In scope" heading above them, so everything
        // lands in `unclear` — and reporting only the confidently-classified
        // ones made preflight say "nothing found" about a folder that plainly
        // names the targets. The operator still ticks each one.
        proposedScopeHosts = [...proposal.include, ...proposal.unclear].map((c) => c.host);
      } catch {
        proposedScopeHosts = [];
      }
    }
    return buildPreflight({
      ...(proposedScopeHosts.length ? { proposedScopeHosts } : {}),
      project: {
        name: info?.name ?? '(unnamed)',
        directory: project.directory,
        ...(info?.authorizationRef ? { authorizationRef: info.authorizationRef } : {}),
        encryptedAtRest: project.encryptedAtRest,
      },
      profile: this.getEngagementProfile(),
      scope: project.scope,
      ca: this.getCaStatus(),
      identity: this.getIdentityCompliance(),
      proxy: this.getProxyStatus(),
      workspace: await this.workspaceSummary(),
      history: {
        exchanges: project.history.count(),
        findings: project.findings.list({ includeSuppressed: false }).length,
      },
    });
  }

  // ---- ai mesh ----

  getAiConfig(): AiConfig {
    return normalizeAiConfig(this.requireProject().meta.getJson<Partial<AiConfig>>('project.ai'));
  }

  setAiConfig(config: AiConfig): void {
    const project = this.requireProject();
    const prev = project.meta.getJson<AiConfig>('project.ai');
    project.meta.setJson('project.ai', config);
    // Egress toggles are security-relevant — always audited.
    if (!prev || prev.egressAcknowledged !== config.egressAcknowledged) {
      project.audit.append({
        ts: Date.now(),
        actor: 'user',
        action: config.egressAcknowledged ? 'ai.egress-enabled' : 'ai.egress-disabled',
      });
    }
  }

  async setAiApiKey(key: string): Promise<void> {
    if (!this.aiSecretStore) throw new Error('No secret store is configured for AI keys.');
    const trimmed = key.trim();
    if (!trimmed) throw new Error('API key is empty.');
    await this.aiSecretStore.set(TacnocSession.AI_KEY, trimmed);
  }

  /** Report only WHETHER a key is present and how it is held — never the key itself. */
  async getAiKeyStatus(): Promise<AiKeyStatus> {
    if (!this.aiSecretStore) return { configured: false, secure: false, backendName: 'none' };
    let configured = false;
    try {
      configured = (await this.aiSecretStore.get(TacnocSession.AI_KEY)) !== null;
    } catch {
      // Present but not decryptable on this OS user/machine — still "configured".
      configured = true;
    }
    return {
      configured,
      secure: this.aiSecretStore.isSecure(),
      backendName: this.aiSecretStore.backendName(),
    };
  }

  async clearAiApiKey(): Promise<void> {
    if (this.aiSecretStore) await this.aiSecretStore.delete(TacnocSession.AI_KEY);
  }

  /**
   * The empty-scope refusal, naming what the engagement folder contains.
   *
   * "Scope is empty, add hosts" is a dead end when the operator's own program
   * policy — sitting in the folder the app can already read — lists every asset.
   * Reading the folder here costs one pass over a handful of documents and only
   * happens on a refusal.
   */
  private async emptyScopeMessage(): Promise<string> {
    const base =
      'Scope is empty (fail-closed): add at least one ENABLED in-scope host before running the ' +
      'mesh — every request would otherwise be refused.';
    try {
      const proposal = await this.proposeScopeFromWorkspace();
      const hosts = [...proposal.include, ...proposal.unclear].map((c) => c.host);
      if (!hosts.length) return `${base} No hosts were found in the engagement folder either.`;
      return (
        `${base} Your engagement folder names ${hosts.length} host(s): ` +
        `${hosts.slice(0, 6).join(', ')}${hosts.length > 6 ? `, +${hosts.length - 6} more` : ''}. ` +
        'Open Engagement → Proposed scope to check them against the program page and add them.'
      );
    } catch {
      return `${base} If your program policy is in the engagement folder, Engagement → Proposed scope reads the hosts out of it.`;
    }
  }

  /** Start a closed-loop mesh run. The API key is read here, main-side, and never leaves. */
  async startMeshRun(plan: MeshRunPlan): Promise<MeshRunProgress> {
    const project = this.requireProject();
    // Scope is checked FIRST, ahead of the key. Both are blockers, but this one
    // is the safety gate, it is the likelier thing to be missing on a fresh
    // engagement, and it is fixable in one click from the folder — whereas the
    // key error masking it sent the operator to the wrong screen entirely.
    if (project.scope.include.filter((r) => r.enabled !== false).length === 0) {
      throw new Error(await this.emptyScopeMessage());
    }
    if (!this.aiSecretStore) throw new Error('No secret store is configured for AI keys.');
    const key = await this.aiSecretStore.get(TacnocSession.AI_KEY);
    if (key === null) {
      throw new Error('No Anthropic API key configured. Add one in AI settings first.');
    }
    const config = this.getAiConfig();
    const provider = new AnthropicProvider({
      apiKey: key,
      ...(config.baseUrl ? { baseUrl: config.baseUrl } : {}),
    });
    return this.mesh.start(plan, {
      provider,
      config,
      tools: buildTools(this, {
        workspaceAccess: config.workspaceAccess,
        allowCertOps: config.allowCertOps,
      }),
    });
  }

  stopMeshRun(id: string): void {
    this.mesh.stop(id);
  }

  getMeshRun(id: string): MeshRun | undefined {
    return this.mesh.get(id);
  }

  /** The run still in flight, so a remounted UI can reattach instead of idling. */
  getActiveMeshRun(): MeshRunProgress | undefined {
    return this.mesh.activeRun();
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
