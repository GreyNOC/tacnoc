/**
 * Preload: exposes a minimal, typed bridge to the renderer via contextBridge.
 * The renderer gets exactly two capabilities: `invoke(method, ...args)` and an
 * event subscription. No Node, no engine internals.
 */

import { contextBridge, ipcRenderer } from 'electron';
import { IPC_INVOKE, IPC_EVENT, type AppEvent } from '../shared/ipc.js';

const api = {
  invoke<T = unknown>(method: string, ...args: unknown[]): Promise<T> {
    return ipcRenderer.invoke(IPC_INVOKE, method, args) as Promise<T>;
  },
  onEvent(handler: (event: AppEvent) => void): () => void {
    const listener = (_e: unknown, event: AppEvent): void => handler(event);
    ipcRenderer.on(IPC_EVENT, listener);
    return () => ipcRenderer.removeListener(IPC_EVENT, listener);
  },
};

export type TacnocBridge = typeof api;

contextBridge.exposeInMainWorld('tacnoc', api);
