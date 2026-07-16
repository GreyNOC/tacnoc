/**
 * IPC dispatch for the main process. A single 'belcher:invoke' channel routes to
 * a whitelisted handler map; session events are forwarded to the renderer over
 * 'belcher:event'. The renderer never touches engine internals directly.
 */

import { ipcMain, dialog, BrowserWindow, app } from 'electron';
import { promises as fs } from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { BelcherSession } from '../engine/session.js';
import { IPC_INVOKE, IPC_EVENT, type AppEvent, type CaInfoDto } from '../shared/ipc.js';
import { inspectJwt } from '../engine/transforms/codec.js';
import { diffLines, diffJson, diffBytes } from '../engine/compare/compare.js';

type Handler = (
  session: BelcherSession,
  win: () => BrowserWindow | null,
  args: unknown[],
) => unknown;

function caInstallInstructions(): string {
  switch (process.platform) {
    case 'win32':
      return 'Windows: import the saved .crt into "Trusted Root Certification Authorities" for the CURRENT USER (certmgr.msc → Trusted Root → All Tasks → Import). Only trust it while testing; remove it when finished.';
    case 'darwin':
      return 'macOS: open the saved .pem in Keychain Access (login keychain), then set it to "Always Trust". Remove trust when finished.';
    default:
      return "Linux: install the saved .pem into your browser's certificate store (browsers usually manage their own trust). Avoid adding it system-wide. Remove it when finished.";
  }
}

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
      filters: [{ name: 'Belcher export', extensions: ['json'] }],
    });
    if (res.canceled || !res.filePath) return null;
    await fs.writeFile(res.filePath, JSON.stringify(data, null, 2));
    return res.filePath;
  },

  async importProjectFromFile(session, win, [targetDir]) {
    const res = await dialog.showOpenDialog(win() ?? undefined!, {
      title: 'Import project export',
      filters: [{ name: 'Belcher export', extensions: ['json'] }],
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
    return { ...info, installInstructions: caInstallInstructions() };
  },

  async saveCaCertificate(session, win) {
    const info = session.getCaInfo();
    const res = await dialog.showSaveDialog(win() ?? undefined!, {
      title: 'Save project CA certificate',
      defaultPath: 'greynoc-belcher-ca.crt',
      filters: [{ name: 'Certificate', extensions: ['crt', 'pem'] }],
    });
    if (res.canceled || !res.filePath) return null;
    await fs.writeFile(res.filePath, info.certPem);
    return res.filePath;
  },

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

  listFindings: (s, _w, [inc]) => s.listFindings(Boolean(inc)),
  setFindingSuppressed: (s, _w, [id, v]) => s.setFindingSuppressed(id as string, Boolean(v)),
  addSuppression: (s, _w, [r]) => s.addSuppression(r as never),
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
};

function ensureProjectPath(dir: string, name: string): string {
  const safe = name.replace(/[^a-zA-Z0-9._-]+/g, '-').replace(/^-+|-+$/g, '') || 'project';
  return dir.endsWith('.gnbproj') ? dir : path.join(dir, `${safe}.gnbproj`);
}

export function registerIpc(session: BelcherSession, getWindow: () => BrowserWindow | null): void {
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
}
