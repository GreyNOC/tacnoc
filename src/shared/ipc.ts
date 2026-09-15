/** IPC channel names and event payload types shared by main, preload, renderer. */

export const IPC_INVOKE = 'tacnoc:invoke';
export const IPC_EVENT = 'tacnoc:event';

/** Events pushed from main → renderer. */
export type AppEvent =
  | { type: 'exchange'; payload: import('./query.js').ExchangeSummary }
  | { type: 'finding'; payload: import('./findings.js').Finding }
  | { type: 'intercept-request'; payload: import('./intercept.js').InterceptedRequestView }
  | { type: 'intercept-response'; payload: import('./intercept.js').InterceptedResponseView }
  | { type: 'intercept-pending'; payload: null }
  | { type: 'intercept-state'; payload: import('./intercept.js').InterceptState }
  | { type: 'proxy-state'; payload: ProxyStatusDto }
  | { type: 'job-progress'; payload: import('./variation.js').JobProgress }
  | { type: 'job-done'; payload: import('./variation.js').JobProgress }
  | { type: 'scope-changed'; payload: import('./scope.js').ScopeConfig }
  | { type: 'emergency-stop'; payload: null }
  | { type: 'ws-message'; payload: { exchangeId: string; direction: string; kind: string } }
  | { type: 'project-open'; payload: import('./project.js').ProjectInfo | undefined }
  | { type: 'mesh-step'; payload: import('./ai.js').MeshStep }
  | { type: 'mesh-progress'; payload: import('./ai.js').MeshRunProgress }
  | { type: 'ca-changed'; payload: import('./engagement.js').CaStatus }
  | { type: 'engagement-changed'; payload: import('./engagement.js').EngagementProfile };

export interface ProxyStatusDto {
  running: boolean;
  host?: string;
  port?: number;
  loopbackOnly: boolean;
}

export interface CaInfoDto {
  certPem: string;
  fingerprint: string;
  secureBackend: boolean;
  backendName: string;
  installInstructions: string;
  /** Step-by-step, per-platform guidance for the guided setup. */
  installGuide: import('../engine/ca/installInstructions.js').CaInstallGuide;
  /**
   * HTTPS exchanges decrypted at the proxy. The setup guide reports this as
   * proof that the browser actually trusts the CA, so it counts proxy traffic
   * only — engine-generated HTTPS proves nothing about interception.
   */
  interceptedHttpsExchanges: number;
  proxyRunning: boolean;
  proxyHost?: string;
  proxyPort?: number;
}

/**
 * Result of a live credential/model check against the configured AI provider.
 *
 * Exists so a bad key or a mistyped model id surfaces before a run starts,
 * rather than as an opaque SDK error three roles deep — after the mesh has
 * already spent tokens and possibly sent traffic at the target.
 */
export interface AiProviderCheckDto {
  ok: boolean;
  /** Plain-language outcome, safe to show verbatim. Never contains the key. */
  detail: string;
  /** The model id that was checked. */
  model: string;
  /** What to do about a failure, when we can say. */
  remedy?: string;
}

/**
 * The set of invokable method names. `registerIpc` asserts at startup that this
 * list and the main-process `handlers` table are in exact parity, so a method
 * cannot be exposed here without an implementation (or vice versa).
 */
export const INVOKE_METHODS = [
  // Frameless-window controls: the renderer's top bar replaces the OS title bar
  // on Windows and Linux and has to be able to drive the window itself.
  'window:minimize',
  'window:toggleMaximize',
  'window:close',
  'window:isMaximized',
  'window:usesCustomControls',
  'pickDirectory',
  'createProject',
  'openProject',
  'pickHuntFolder',
  'adoptHuntFolder',
  'closeProject',
  'getProjectInfo',
  'exportProjectToFile',
  // Evidence bundles: one target's traffic, findings and handoff as a ZIP,
  // plus the diagnostic log tail and the live hand-off to the mesh.
  'exportTargetEvidence',
  'exportLogs',
  'previewTargetHandoff',
  'handoffTargetToMesh',
  'importProjectFromFile',
  'startProxy',
  'stopProxy',
  'getProxyStatus',
  'getCaInfo',
  'getCaInstallGuide',
  'saveCaCertificate',
  'getCaStatus',
  'rotateCa',
  'revokeCa',
  'getEngagementProfile',
  'setEngagementProfile',
  'getPreflight',
  'listWorkspace',
  'readWorkspaceFile',
  'searchWorkspace',
  'pickWorkspaceDirectory',
  'recallHuntHistory',
  'clearHuntMemory',
  'proposeScopeFromWorkspace',
  'scanEngagementDocs',
  'getScope',
  'setScope',
  'getConfig',
  'setConfig',
  'getInterceptState',
  'setInterceptState',
  'listPendingRequests',
  'listPendingResponses',
  'resolveRequest',
  'resolveResponse',
  'queryHistory',
  'getExchangeDetail',
  'listWsMessages',
  'updateNotesTags',
  'clearHistory',
  'historyCount',
  'getTargetMap',
  'listFindings',
  'setFindingSuppressed',
  'addSuppression',
  'removeSuppression',
  'listSuppressions',
  'scannerModules',
  'sendRepeater',
  'listCookies',
  'clearCookies',
  'saveRequest',
  'listSavedRequests',
  'applyTransform',
  'listTransforms',
  'inspectJwt',
  'diffText',
  'diffJson',
  'diffBytes',
  'analyzeTokenSamples',
  'createVariationJob',
  'runVariationJob',
  'pauseVariationJob',
  'resumeVariationJob',
  'stopVariationJob',
  'listVariationJobs',
  'getVariationResults',
  'emergencyStop',
  'listAudit',
  'listExtensions',
  'loadExampleExtension',
  'getAiConfig',
  'setAiConfig',
  'setAiApiKey',
  'getAiKeyStatus',
  'clearAiApiKey',
  'checkAiProvider',
  'startMeshRun',
  'stopMeshRun',
  'getMeshRun',
  'getActiveMeshRun',
] as const;

export type InvokeMethod = (typeof INVOKE_METHODS)[number];
