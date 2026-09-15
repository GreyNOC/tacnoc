/**
 * IPC dispatch for the main process. A single 'tacnoc:invoke' channel routes to
 * a whitelisted handler map; session events are forwarded to the renderer over
 * 'tacnoc:event'. The renderer never touches engine internals directly.
 */

import { ipcMain, dialog, BrowserWindow, app } from 'electron';
import { promises as fs } from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { TacnocSession } from '../engine/session.js';
import {
  IPC_INVOKE,
  IPC_EVENT,
  INVOKE_METHODS,
  type AppEvent,
  type CaInfoDto,
} from '../shared/ipc.js';
// One source of truth for the install guidance. This file used to carry a
// verbatim copy of the engine's per-platform text, so the two could (and did)
// drift while both looked authoritative.
import { caInstallGuide, caInstallInstructions } from '../engine/ca/installInstructions.js';
import { inspectJwt } from '../engine/transforms/codec.js';
import { diffLines, diffJson, diffBytes } from '../engine/compare/compare.js';
import { analyzeTokenSamples } from '../engine/analysis/sequencer.js';

type Handler = (
  session: TacnocSession,
  win: () => BrowserWindow | null,
  args: unknown[],
) => unknown;

const exampleExtensionDir = (): string => {
  // In dev the example lives in the repo; when packaged it is under resources.
  const devPath = path.resolve(
    fileURLToPath(import.meta.url),
    '../../../examples/extensions/header-hygiene',
  );
  const packaged = path.join(process.resourcesPath ?? '', 'examples/extensions/header-hygiene');
  return app.isPackaged ? packaged : devPath;
};

const handlers: Record<string, Handler> = {
  async pickDirectory(_s, win) {
    const w = win();
    const res = await dialog.showOpenDialog(w ?? undefined!, {
      properties: ['openDirectory', 'createDirectory'],
      title: 'Choose a project location',
    });
    return res.canceled ? null : res.filePaths[0];
  },

  async createProject(session, _w, [dir, name, authRef]) {
    const projectPath = ensureProjectPath(dir as string, name as string);
    await session.createProject(projectPath, name as string, (authRef as string) || undefined);
    return session.getProjectInfo();
  },

  async openProject(session, _w, [dir]) {
    await session.openProject(dir as string);
    return session.getProjectInfo();
  },

  /**
   * Open a folder that already holds an engagement, creating the project inside
   * it if there is not one yet. This is how an in-flight hunt gets adopted:
   * the operator points at the folder their material is already in.
   */
  async adoptHuntFolder(session, _w, [dir, name, authRef]) {
    const result = await session.adoptHuntFolder(dir as string, {
      ...(name ? { name: name as string } : {}),
      ...(authRef ? { authorizationRef: authRef as string } : {}),
    });
    return { ...result, info: session.getProjectInfo() };
  },

  async pickHuntFolder(_s, win) {
    const res = await dialog.showOpenDialog(win() ?? undefined!, {
      properties: ['openDirectory'],
      title: 'Choose the folder your engagement material is in',
    });
    return res.canceled ? null : res.filePaths[0];
  },

  async closeProject(session) {
    await session.closeProject();
    return true;
  },

  getProjectInfo(session) {
    return session.getProjectInfo();
  },

  async exportProjectToFile(session, win) {
    const data = await session.exportProject();
    const res = await dialog.showSaveDialog(win() ?? undefined!, {
      title: 'Export project',
      defaultPath: `${data.info.name}.gnbexport.json`,
      filters: [{ name: 'TACNOC export', extensions: ['json'] }],
    });
    if (res.canceled || !res.filePath) return null;
    await fs.writeFile(res.filePath, JSON.stringify(data, null, 2));
    return res.filePath;
  },

  async importProjectFromFile(session, win, [targetDir]) {
    const res = await dialog.showOpenDialog(win() ?? undefined!, {
      title: 'Import project export',
      filters: [{ name: 'TACNOC export', extensions: ['json'] }],
      properties: ['openFile'],
    });
    if (res.canceled || !res.filePaths[0]) return null;
    const data = JSON.parse(await fs.readFile(res.filePaths[0], 'utf8'));
    const dir = ensureProjectPath(targetDir as string, data.info?.name ?? 'imported');
    await session.importProject(data, dir);
    return session.getProjectInfo();
  },

  startProxy(session, _w, [host, port]) {
    return session.startProxy((host as string) || undefined, (port as number) ?? undefined);
  },
  stopProxy(session) {
    return session.stopProxy();
  },
  getProxyStatus(session) {
    return session.getProxyStatus();
  },

  getCaInfo(session): CaInfoDto {
    const info = session.getCaInfo();
    return {
      ...info,
      installInstructions: caInstallInstructions(),
      // Rendered with the placeholder path: the guide is shown before anything
      // has been saved, and re-fetched with the real path once it has.
      installGuide: caInstallGuide(),
    };
  },

  /**
   * The install guide rendered for a specific saved certificate path, so the
   * command the operator copies is the one that works — path quoted for their
   * shell. Quoting stays in the engine; the renderer must not build shell text.
   */
  getCaInstallGuide(_s, _w, [certPath]) {
    return caInstallGuide(typeof certPath === 'string' ? certPath : undefined);
  },

  async saveCaCertificate(session, win) {
    const info = session.getCaInfo();
    // A revoked CA has no certificate. Writing the empty string would hand the
    // operator a 0-byte .crt and report success.
    if (!info.certPem) {
      throw new Error(
        'This project has no CA certificate — it was revoked. Issue a new one first.',
      );
    }
    const res = await dialog.showSaveDialog(win() ?? undefined!, {
      title: 'Save project CA certificate',
      defaultPath: 'greynoc-tacnoc-ca.crt',
      filters: [{ name: 'Certificate', extensions: ['crt', 'pem'] }],
    });
    if (res.canceled || !res.filePath) return null;
    await fs.writeFile(res.filePath, info.certPem);
    return res.filePath;
  },

  // ---- frameless window controls ----
  //
  // The window has no OS chrome on Windows/Linux, so the renderer's top bar
  // draws the controls and calls these. Each one is a no-op when the window is
  // gone (quitting, or a renderer call that outlived it) rather than throwing
  // into the operator's face over a button that no longer has anything to act on.
  'window:minimize': (_s, win) => {
    win()?.minimize();
    return null;
  },
  'window:toggleMaximize': (_s, win) => {
    const w = win();
    if (!w) return false;
    if (w.isMaximized()) w.unmaximize();
    else w.maximize();
    return w.isMaximized();
  },
  'window:close': (_s, win) => {
    win()?.close();
    return null;
  },
  'window:isMaximized': (_s, win) => win()?.isMaximized() ?? false,
  /** Whether the renderer must draw its own controls (false on macOS). */
  'window:usesCustomControls': () => process.platform !== 'darwin',

  getScope: (s) => s.getScope(),
  setScope: (s, _w, [scope]) => s.setScope(scope as never),
  getConfig: (s) => s.getConfig(),
  setConfig: (s, _w, [c]) => s.setConfig(c as never),

  getInterceptState: (s) => s.getInterceptState(),
  setInterceptState: (s, _w, [p]) => s.setInterceptState(p as never),
  listPendingRequests: (s) => s.listPendingRequests(),
  listPendingResponses: (s) => s.listPendingResponses(),
  resolveRequest: (s, _w, [id, d]) => s.resolveRequest(id as string, d as never),
  resolveResponse: (s, _w, [id, d]) => s.resolveResponse(id as string, d as never),

  queryHistory: (s, _w, [f]) => s.queryHistory((f as never) ?? {}),
  getExchangeDetail: (s, _w, [id]) => s.getExchangeDetail(id as string),
  listWsMessages: (s, _w, [id]) => s.listWsMessages(id as string),
  updateNotesTags: (s, _w, [id, notes, tags]) =>
    s.updateNotesTags(id as string, notes as string | null, tags as string[]),
  clearHistory: (s) => s.clearHistory(),
  historyCount: (s) => s.historyCount(),
  getTargetMap: (s, _w, [max]) => s.getTargetMap((max as number) ?? 100_000),

  listFindings: (s, _w, [inc]) => s.listFindings(Boolean(inc)),
  setFindingSuppressed: (s, _w, [id, v]) => s.setFindingSuppressed(id as string, Boolean(v)),
  addSuppression: (s, _w, [r]) => s.addSuppression(r as never),
  removeSuppression: (s, _w, [id]) => s.removeSuppression(id as string),
  listSuppressions: (s) => s.listSuppressions(),
  scannerModules: (s) => s.scannerModules(),

  sendRepeater: (s, _w, [target, options]) => s.sendRepeater(target as never, options as never),
  listCookies: (s) => s.listCookies(),
  clearCookies: (s) => s.clearCookies(),
  saveRequest: (s, _w, [r]) => s.saveRequest(r as never),
  listSavedRequests: (s) => s.listSavedRequests(),

  applyTransform: (s, _w, [id, input]) => s.applyTransform(id as string, input as string),
  listTransforms: (s) => s.listTransforms(),
  inspectJwt: (_s, _w, [token]) => inspectJwt(token as string),
  diffText: (_s, _w, [a, b]) => diffLines(a as string, b as string),
  diffJson: (_s, _w, [a, b]) => diffJson(a as string, b as string),
  diffBytes: (_s, _w, [a, b]) =>
    diffBytes(Buffer.from(a as string, 'base64'), Buffer.from(b as string, 'base64')),
  analyzeTokenSamples: (_s, _w, [samples, encoding]) =>
    analyzeTokenSamples(samples as string[], encoding as never),

  createVariationJob: (s, _w, [plan]) => s.createVariationJob(plan as never),
  runVariationJob: (s, _w, [id]) => s.runVariationJob(id as string),
  pauseVariationJob: (s, _w, [id]) => s.pauseVariationJob(id as string),
  resumeVariationJob: (s, _w, [id]) => s.resumeVariationJob(id as string),
  stopVariationJob: (s, _w, [id]) => s.stopVariationJob(id as string),
  listVariationJobs: (s) => s.listVariationJobs(),
  getVariationResults: (s, _w, [id]) => s.getVariationResults(id as string),
  emergencyStop: (s) => s.emergencyStop(),

  listAudit: (s, _w, [limit]) => s.listAudit((limit as number) ?? 500),
  listExtensions: (s) => s.listExtensions(),

  async loadExampleExtension(session) {
    const dir = exampleExtensionDir();
    const manifest = JSON.parse(await fs.readFile(path.join(dir, 'manifest.json'), 'utf8'));
    const source = await fs.readFile(path.join(dir, 'extension.js'), 'utf8');
    await session.loadExtension(manifest, source, manifest.permissions);
    return session.listExtensions();
  },

  // ---- engagement profile, workspace, preflight ----
  getEngagementProfile: (s) => s.getEngagementProfile(),
  setEngagementProfile: (s, _w, [p]) => {
    s.setEngagementProfile(p as never);
    return s.getEngagementProfile();
  },
  getPreflight: (s) => s.getPreflight(),
  listWorkspace: (s) => s.listWorkspace(),
  readWorkspaceFile: (s, _w, [rel, maxBytes]) =>
    s.readWorkspaceFile(rel as string, typeof maxBytes === 'number' ? maxBytes : undefined),
  searchWorkspace: (s, _w, [q]) => s.searchWorkspace(q as string),
  async pickWorkspaceDirectory(_s, win) {
    const res = await dialog.showOpenDialog(win() ?? undefined!, {
      properties: ['openDirectory'],
      title: 'Choose the engagement folder the AI may read',
    });
    return res.canceled ? null : res.filePaths[0];
  },

  recallHuntHistory: (s, _w, [q, all]) =>
    s.recallHuntHistory((q as never) ?? {}, { allPrograms: Boolean(all) }),
  clearHuntMemory: (s) => s.clearHuntMemory(),
  proposeScopeFromWorkspace: (s) => s.proposeScopeFromWorkspace(),
  scanEngagementDocs: (s) => s.scanEngagementDocs(),

  // ---- certificate lifecycle ----
  getCaStatus: (s) => s.getCaStatus(),
  rotateCa: (s, _w, [reason]) => s.rotateCa((reason as string) ?? ''),
  revokeCa: (s, _w, [reason]) => s.revokeCa((reason as string) ?? ''),

  checkAiProvider: (s, _w, [role]) =>
    s.checkAiProvider(typeof role === 'string' ? (role as never) : undefined),
  getAiConfig: (s) => s.getAiConfig(),
  setAiConfig: (s, _w, [c]) => s.setAiConfig(c as never),
  setAiApiKey: (s, _w, [k]) => s.setAiApiKey(k as string),
  getAiKeyStatus: (s) => s.getAiKeyStatus(),
  clearAiApiKey: (s) => s.clearAiApiKey(),
  startMeshRun: (s, _w, [plan]) => s.startMeshRun(plan as never),
  stopMeshRun: (s, _w, [id]) => s.stopMeshRun(id as string),
  getMeshRun: (s, _w, [id]) => s.getMeshRun(id as string),
  getActiveMeshRun: (s) => s.getActiveMeshRun(),
};

function ensureProjectPath(dir: string, name: string): string {
  const safe = name.replace(/[^a-zA-Z0-9._-]+/g, '-').replace(/^-+|-+$/g, '') || 'project';
  return dir.endsWith('.tacnocproj') ? dir : path.join(dir, `${safe}.tacnocproj`);
}

/**
 * Fail loudly at startup if the renderer-facing allowlist (`INVOKE_METHODS`)
 * and the actual dispatch table (`handlers`) drift apart — a method listed but
 * unimplemented, or implemented but not on the allowlist. Keeps the allowlist a
 * real contract instead of stale documentation.
 */
function assertHandlerParity(): void {
  const implemented = new Set(Object.keys(handlers));
  const allowed = new Set<string>(INVOKE_METHODS);
  const missing = INVOKE_METHODS.filter((method) => !implemented.has(method));
  const unlisted = [...implemented].filter((method) => !allowed.has(method));
  if (missing.length || unlisted.length) {
    throw new Error(
      `IPC registry drift — missing handlers: [${missing.join(', ')}]; ` +
        `handlers absent from the allowlist: [${unlisted.join(', ')}]`,
    );
  }
}

export function registerIpc(session: TacnocSession, getWindow: () => BrowserWindow | null): void {
  assertHandlerParity();
  ipcMain.handle(IPC_INVOKE, async (_event, method: string, args: unknown[]) => {
    const handler = handlers[method];
    if (!handler) throw new Error(`unknown method: ${method}`);
    try {
      return await handler(session, getWindow, args ?? []);
    } catch (err) {
      // Surface a clean message to the renderer instead of a silent failure.
      throw new Error(err instanceof Error ? err.message : String(err));
    }
  });

  const forward = (type: AppEvent['type']) => (payload: unknown) => {
    const win = getWindow();
    if (win && !win.isDestroyed()) win.webContents.send(IPC_EVENT, { type, payload });
  };

  session.on('exchange', forward('exchange'));
  session.on('finding', forward('finding'));
  session.on('intercept-request', forward('intercept-request'));
  session.on('intercept-response', forward('intercept-response'));
  session.on('intercept-pending', forward('intercept-pending'));
  session.on('intercept-state', forward('intercept-state'));
  session.on('proxy-state', forward('proxy-state'));
  session.on('job-progress', forward('job-progress'));
  session.on('job-done', forward('job-done'));
  session.on('scope-changed', forward('scope-changed'));
  session.on('emergency-stop', forward('emergency-stop'));
  session.on('ws-message', forward('ws-message'));
  session.on('project-open', forward('project-open'));
  session.on('mesh-step', forward('mesh-step'));
  session.on('mesh-progress', forward('mesh-progress'));
  session.on('ca-changed', forward('ca-changed'));
  session.on('engagement-changed', forward('engagement-changed'));
}
