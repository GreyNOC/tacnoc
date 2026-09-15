/**
 * Electron main process entry.
 *
 * Security posture:
 *  - contextIsolation ON, nodeIntegration OFF, sandbox ON for the renderer.
 *  - The renderer talks to the engine only through the preload's contextBridge
 *    API (a single invoke channel + an event channel).
 *  - Captured response content is NEVER loaded as a page; the renderer displays
 *    it as inert text/hex only.
 */

import { app, BrowserWindow, shell } from 'electron';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { TacnocSession } from '../engine/session.js';
import { ElectronSecretStore } from './electronSecretStore.js';
import { registerIpc } from './ipc.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

/**
 * Pin the application identity before anything reads `userData`.
 *
 * Electron derives the app name — and therefore the userData directory — from
 * however the process was started. `npm run dev` resolved it to the package name,
 * a bare `electron out/main/index.js` resolved it to "Electron", and the packaged
 * build to the electron-builder productName. Three identities on one machine.
 *
 * That is not cosmetic. `safeStorage` keeps its master key in `<userData>/Local
 * State`, so each identity seals project secrets under a DIFFERENT key: a project
 * created in dev could not be opened by the release build at all, and the failure
 * surfaced as "sealed by a different OS user account or machine" — which sent the
 * operator looking at their Windows profile for a problem that was really the
 * launcher. In a tool whose value is the engagement evidence it retains, losing
 * access to a project because of how the binary was started is a data-availability
 * defect.
 *
 * Must run before `app.getPath('userData')` is called anywhere below.
 */
app.setName('TACNOC');

let mainWindow: BrowserWindow | null = null;

const session = new TacnocSession({
  appVersion: app.getVersion(),
  secretStoreFactory: (dir) => new ElectronSecretStore(dir),
  // The AI provider key is app-global, not per-project: held in OS secure
  // storage under userData so it never travels with a shared project folder and
  // never crosses the contextBridge to the renderer.
  aiSecretStore: new ElectronSecretStore(path.join(app.getPath('userData'), 'ai-secrets')),
  // Hunt memory is app-global for the same reason it is useful at all: what one
  // engagement settled should be available to the next, including in a different
  // project. Local only — it never leaves the machine.
  huntMemoryDir: path.join(app.getPath('userData'), 'hunt-memory'),
});

function createWindow(): void {
  mainWindow = new BrowserWindow({
    width: 1360,
    height: 860,
    minWidth: 960,
    minHeight: 600,
    backgroundColor: '#0d1117',
    title: 'TACNOC',
    // Windows and macOS take the window icon from the packaged executable or
    // bundle; Linux and `electron-vite dev` need to be handed a file.
    icon: path.join(__dirname, '../renderer/icon.png'),
    // Frameless: the app's own top bar IS the title bar, so the OS chrome is one
    // less strip of vertical space between the operator and the traffic table.
    //
    // Split by platform on purpose. macOS keeps its native traffic lights
    // (`hiddenInset` floats them over the content) because a Mac window without
    // them is a window most people cannot close; Windows and Linux go fully
    // frameless and the renderer draws its own minimise/maximise/close, wired
    // through the `window:*` IPC methods.
    ...(process.platform === 'darwin'
      ? { titleBarStyle: 'hiddenInset' as const, trafficLightPosition: { x: 14, y: 13 } }
      : { frame: false }),
    webPreferences: {
      preload: path.join(__dirname, '../preload/index.cjs'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      // Defense-in-depth: no remote content is ever loaded here.
      webviewTag: false,
    },
  });

  // Open external links in the OS browser, never in-app.
  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    void shell.openExternal(url);
    return { action: 'deny' };
  });

  // Block navigation away from the app shell.
  mainWindow.webContents.on('will-navigate', (event, url) => {
    const rendererUrl = process.env['ELECTRON_RENDERER_URL'];
    if (rendererUrl && url.startsWith(rendererUrl)) return;
    event.preventDefault();
  });

  const rendererUrl = process.env['ELECTRON_RENDERER_URL'];
  if (rendererUrl) {
    void mainWindow.loadURL(rendererUrl);
  } else {
    void mainWindow.loadFile(path.join(__dirname, '../renderer/index.html'));
  }

  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

app.whenReady().then(() => {
  registerIpc(session, () => mainWindow);
  createWindow();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});

// Full, ordered shutdown: stop automated work, close the project, and terminate
// the isolated extension child process (freeing its temp bootstrap dir). dispose()
// is async, so hold the quit until it completes, then let the quit proceed.
let quitting = false;
app.on('before-quit', (event) => {
  if (quitting) return;
  event.preventDefault();
  quitting = true;
  session.emergencyStop();
  void session.dispose().finally(() => app.quit());
});
