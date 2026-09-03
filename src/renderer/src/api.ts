/** Typed wrapper around the preload bridge (window.tacnoc). */

import type { AppEvent, ProxyStatusDto, CaInfoDto, AiProviderCheckDto } from '@shared/ipc.js';
import type { CaInstallGuide } from '@engine/ca/installInstructions.js';
import type { ExchangeSummary, HistoryFilter, HistoryPage } from '@shared/query.js';
import type { ExchangeDetail } from '@shared/detail.js';
import type { WsMessage } from '@shared/websocket.js';
import type { ScopeConfig } from '@shared/scope.js';
import type { EngineConfig } from '@shared/config.js';
import type { Finding, SuppressionRule } from '@shared/findings.js';
import type { ProjectInfo, SavedRequest } from '@shared/project.js';
import type {
  InterceptState,
  InterceptedRequestView,
  InterceptedResponseView,
  RequestDecision,
  ResponseDecision,
} from '@shared/intercept.js';
import type { RepeaterOptions, RepeaterResult } from '@shared/repeater.js';
import type { StoredCookie } from '@engine/repeater/cookieJar.js';
import type { JobProgress, VariationPlan, VariationResultRow } from '@shared/variation.js';
import type { AuditEntry } from '@shared/project.js';
import type { JwtInspection } from '@engine/transforms/codec.js';
import type { LineDiff, JsonDiffEntry, ByteDiff } from '@engine/compare/compare.js';
import type { ExtensionManifest, Permission } from '@sdk/api.js';
import type { TargetMap } from '@shared/target.js';
import type { CaStatus, EngagementProfile, PreflightReport } from '@shared/engagement.js';
import type { HuntRecallResult } from '@engine/analysis/huntMemory.js';
import type { DocScanResult } from '@engine/engagement/docScan.js';
import type { ScopeProposal } from '@engine/engagement/scopeProposal.js';
import type {
  WorkspaceFile,
  WorkspaceListing,
  WorkspaceSearchResult,
} from '@engine/workspace/workspace.js';
import type { SequenceAnalysis, TokenEncoding } from '@shared/sequencer.js';
import type { AiConfig, AiKeyStatus, MeshRun, MeshRunPlan, MeshRunProgress } from '@shared/ai.js';

interface Bridge {
  invoke<T = unknown>(method: string, ...args: unknown[]): Promise<T>;
  onEvent(handler: (event: AppEvent) => void): () => void;
}

declare global {
  interface Window {
    tacnoc: Bridge;
  }
}

const b = (): Bridge => window.tacnoc;

export const api = {
  onEvent: (h: (e: AppEvent) => void) => b().onEvent(h),

  // window (frameless chrome)
  windowMinimize: () => b().invoke<null>('window:minimize'),
  windowToggleMaximize: () => b().invoke<boolean>('window:toggleMaximize'),
  windowClose: () => b().invoke<null>('window:close'),
  windowIsMaximized: () => b().invoke<boolean>('window:isMaximized'),
  windowUsesCustomControls: () => b().invoke<boolean>('window:usesCustomControls'),

  // project
  pickDirectory: () => b().invoke<string | null>('pickDirectory'),
  createProject: (dir: string, name: string, authRef?: string) =>
    b().invoke<ProjectInfo>('createProject', dir, name, authRef),
  openProject: (dir: string) => b().invoke<ProjectInfo>('openProject', dir),
  pickHuntFolder: () => b().invoke<string | null>('pickHuntFolder'),
  adoptHuntFolder: (dir: string, name?: string, authRef?: string) =>
    b().invoke<{
      projectDirectory: string;
      created: boolean;
      scan: DocScanResult;
      info: ProjectInfo;
    }>('adoptHuntFolder', dir, name, authRef),
  closeProject: () => b().invoke<boolean>('closeProject'),
  getProjectInfo: () => b().invoke<ProjectInfo | undefined>('getProjectInfo'),
  exportProjectToFile: () => b().invoke<string | null>('exportProjectToFile'),
  importProjectFromFile: (dir: string) =>
    b().invoke<ProjectInfo | null>('importProjectFromFile', dir),

  // proxy + ca
  startProxy: (host?: string, port?: number) =>
    b().invoke<ProxyStatusDto>('startProxy', host, port),
  stopProxy: () => b().invoke<ProxyStatusDto>('stopProxy'),
  getProxyStatus: () => b().invoke<ProxyStatusDto>('getProxyStatus'),
  getCaInfo: () => b().invoke<CaInfoDto>('getCaInfo'),
  getCaInstallGuide: (certPath?: string) =>
    b().invoke<CaInstallGuide>('getCaInstallGuide', certPath),
  saveCaCertificate: () => b().invoke<string | null>('saveCaCertificate'),
  getCaStatus: () => b().invoke<CaStatus>('getCaStatus'),
  rotateCa: (reason: string) => b().invoke<CaStatus>('rotateCa', reason),
  revokeCa: (reason: string) => b().invoke<CaStatus>('revokeCa', reason),

  // engagement
  getEngagementProfile: () => b().invoke<EngagementProfile>('getEngagementProfile'),
  setEngagementProfile: (profile: EngagementProfile) =>
    b().invoke<EngagementProfile>('setEngagementProfile', profile),
  getPreflight: () => b().invoke<PreflightReport>('getPreflight'),
  listWorkspace: () => b().invoke<WorkspaceListing>('listWorkspace'),
  readWorkspaceFile: (path: string, maxBytes?: number) =>
    b().invoke<WorkspaceFile>('readWorkspaceFile', path, maxBytes),
  searchWorkspace: (query: string) => b().invoke<WorkspaceSearchResult>('searchWorkspace', query),
  pickWorkspaceDirectory: () => b().invoke<string | null>('pickWorkspaceDirectory'),
  recallHuntHistory: (query: Record<string, string> = {}, allPrograms = false) =>
    b().invoke<HuntRecallResult>('recallHuntHistory', query, allPrograms),
  clearHuntMemory: () => b().invoke<void>('clearHuntMemory'),
  proposeScopeFromWorkspace: () => b().invoke<ScopeProposal>('proposeScopeFromWorkspace'),
  scanEngagementDocs: () => b().invoke<DocScanResult>('scanEngagementDocs'),

  // scope + config
  getScope: () => b().invoke<ScopeConfig>('getScope'),
  setScope: (scope: ScopeConfig) => b().invoke<void>('setScope', scope),
  getConfig: () => b().invoke<EngineConfig>('getConfig'),
  setConfig: (config: EngineConfig) => b().invoke<void>('setConfig', config),

  // intercept
  getInterceptState: () => b().invoke<InterceptState>('getInterceptState'),
  setInterceptState: (p: Partial<InterceptState>) =>
    b().invoke<InterceptState>('setInterceptState', p),
  listPendingRequests: () => b().invoke<InterceptedRequestView[]>('listPendingRequests'),
  listPendingResponses: () => b().invoke<InterceptedResponseView[]>('listPendingResponses'),
  resolveRequest: (id: string, d: RequestDecision) => b().invoke<boolean>('resolveRequest', id, d),
  resolveResponse: (id: string, d: ResponseDecision) =>
    b().invoke<boolean>('resolveResponse', id, d),

  // history
  queryHistory: (f: HistoryFilter) => b().invoke<HistoryPage<ExchangeSummary>>('queryHistory', f),
  getExchangeDetail: (id: string) =>
    b().invoke<ExchangeDetail | undefined>('getExchangeDetail', id),
  listWsMessages: (id: string) => b().invoke<WsMessage[]>('listWsMessages', id),
  updateNotesTags: (id: string, notes: string | null, tags: string[]) =>
    b().invoke<void>('updateNotesTags', id, notes, tags),
  clearHistory: () => b().invoke<void>('clearHistory'),
  historyCount: () => b().invoke<number>('historyCount'),
  getTargetMap: (maxExchanges = 100_000) => b().invoke<TargetMap>('getTargetMap', maxExchanges),

  // findings
  listFindings: (includeSuppressed = false) =>
    b().invoke<Finding[]>('listFindings', includeSuppressed),
  setFindingSuppressed: (id: string, s: boolean) => b().invoke<void>('setFindingSuppressed', id, s),
  addSuppression: (r: SuppressionRule) => b().invoke<void>('addSuppression', r),
  removeSuppression: (id: string) => b().invoke<void>('removeSuppression', id),
  listSuppressions: () => b().invoke<SuppressionRule[]>('listSuppressions'),
  scannerModules: () => b().invoke<{ module: string; version: string }[]>('scannerModules'),

  // repeater
  sendRepeater: (
    target: { scheme: string; host: string; port: number; raw: string },
    options: RepeaterOptions,
  ) => b().invoke<RepeaterResult>('sendRepeater', target, options),
  listSavedRequests: () => b().invoke<SavedRequest[]>('listSavedRequests'),
  saveRequest: (r: SavedRequest) => b().invoke<void>('saveRequest', r),
  listCookies: () => b().invoke<StoredCookie[]>('listCookies'),
  clearCookies: () => b().invoke<void>('clearCookies'),

  // transforms + compare
  listTransforms: () =>
    b().invoke<{ id: string; label: string; category: string }[]>('listTransforms'),
  applyTransform: (id: string, input: string) => b().invoke<string>('applyTransform', id, input),
  inspectJwt: (token: string) => b().invoke<JwtInspection>('inspectJwt', token),
  diffText: (a: string, bb: string) => b().invoke<LineDiff[]>('diffText', a, bb),
  diffJson: (a: string, bb: string) => b().invoke<JsonDiffEntry[]>('diffJson', a, bb),
  diffBytes: (a: string, bb: string) => b().invoke<ByteDiff>('diffBytes', a, bb),
  analyzeTokenSamples: (samples: string[], encoding: TokenEncoding) =>
    b().invoke<SequenceAnalysis>('analyzeTokenSamples', samples, encoding),

  // variation
  createVariationJob: (plan: VariationPlan) =>
    b().invoke<{ id: string; count: number }>('createVariationJob', plan),
  runVariationJob: (id: string) => b().invoke<JobProgress>('runVariationJob', id),
  pauseVariationJob: (id: string) => b().invoke<void>('pauseVariationJob', id),
  resumeVariationJob: (id: string) => b().invoke<void>('resumeVariationJob', id),
  stopVariationJob: (id: string) => b().invoke<void>('stopVariationJob', id),
  listVariationJobs: () => b().invoke<JobProgress[]>('listVariationJobs'),
  getVariationResults: (id: string) => b().invoke<VariationResultRow[]>('getVariationResults', id),
  emergencyStop: () => b().invoke<void>('emergencyStop'),

  // audit + extensions
  listAudit: (limit = 500) => b().invoke<AuditEntry[]>('listAudit', limit),
  listExtensions: () =>
    b().invoke<{ manifest: ExtensionManifest; granted: Permission[] }[]>('listExtensions'),
  loadExampleExtension: () =>
    b().invoke<{ manifest: ExtensionManifest; granted: Permission[] }[]>('loadExampleExtension'),

  // ai mesh
  getAiConfig: () => b().invoke<AiConfig>('getAiConfig'),
  setAiConfig: (c: AiConfig) => b().invoke<void>('setAiConfig', c),
  setAiApiKey: (key: string) => b().invoke<void>('setAiApiKey', key),
  getAiKeyStatus: () => b().invoke<AiKeyStatus>('getAiKeyStatus'),
  clearAiApiKey: () => b().invoke<void>('clearAiApiKey'),
  checkAiProvider: (role?: string) => b().invoke<AiProviderCheckDto>('checkAiProvider', role),
  startMeshRun: (plan: MeshRunPlan) => b().invoke<MeshRunProgress>('startMeshRun', plan),
  stopMeshRun: (id: string) => b().invoke<void>('stopMeshRun', id),
  getMeshRun: (id: string) => b().invoke<MeshRun | undefined>('getMeshRun', id),
  getActiveMeshRun: () => b().invoke<MeshRunProgress | undefined>('getActiveMeshRun'),
};

export type Api = typeof api;
