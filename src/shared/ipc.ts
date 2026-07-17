/** IPC channel names and event payload types shared by main, preload, renderer. */

export const IPC_INVOKE = 'belcher:invoke';
export const IPC_EVENT = 'belcher:event';

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
  | { type: 'project-open'; payload: import('./project.js').ProjectInfo | undefined };

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
}

/** The set of invokable method names (documented; enforced in main dispatch). */
export const INVOKE_METHODS = [
  'pickDirectory',
  'createProject',
  'openProject',
  'closeProject',
  'getProjectInfo',
  'exportProjectToFile',
  'importProjectFromFile',
  'startProxy',
  'stopProxy',
  'getProxyStatus',
  'getCaInfo',
  'saveCaCertificate',
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
] as const;

export type InvokeMethod = (typeof INVOKE_METHODS)[number];
