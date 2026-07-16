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
import { BelcherSession } from '../engine/session.js';
import { ElectronSecretStore } from './electronSecretStore.js';
import { registerIpc } from './ipc.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

let mainWindow: BrowserWindow | null = null;

const session = new BelcherSession({
  appVersion: app.getVersion(),
  secretStoreFactory: (dir) => new ElectronSecretStore(dir),
});

function createWindow(): void {
  mainWindow = new BrowserWindow({
    width: 1360,
    height: 860,
    minWidth: 960,
    minHeight: 600,
    backgroundColor: '#0d1117',
    title: 'GreyNOC Belcher',
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
  void session.closeProject().finally(() => {
    if (process.platform !== 'darwin') app.quit();
  });
});

app.on('before-quit', () => {
  session.emergencyStop();
});
