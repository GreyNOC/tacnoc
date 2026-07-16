import React, { createContext, useContext, useEffect, useMemo, useState, useCallback } from 'react';
import { api } from './api.js';
import type { ProxyStatusDto } from '@shared/ipc.js';
import type {
  InterceptState,
  InterceptedRequestView,
  InterceptedResponseView,
} from '@shared/intercept.js';
import type { JobProgress } from '@shared/variation.js';
import type { ProjectInfo } from '@shared/project.js';

export type ViewId =
  | 'history'
  | 'intercept'
  | 'repeater'
  | 'findings'
  | 'scope'
  | 'variation'
  | 'encoder'
  | 'compare'
  | 'certificate'
  | 'extensions'
  | 'audit'
  | 'settings';

export interface RepeaterSeed {
  scheme: string;
  host: string;
  port: number;
  raw: string;
}

interface StoreValue {
  project?: ProjectInfo;
  proxy: ProxyStatusDto;
  intercept: InterceptState;
  pendingRequests: InterceptedRequestView[];
  pendingResponses: InterceptedResponseView[];
  findingsCount: number;
  jobs: JobProgress[];
  exchangeTick: number;
  view: ViewId;
  theme: 'dark' | 'light';
  toast?: string;
  repeaterSeed?: RepeaterSeed;

  setView: (v: ViewId) => void;
  toggleTheme: () => void;
  setToast: (m?: string) => void;
  seedRepeater: (s: RepeaterSeed) => void;
  refreshProxy: () => void;
  refreshIntercept: () => void;
  refreshFindings: () => void;
  refreshJobs: () => void;
  setProject: (p?: ProjectInfo) => void;
  emergencyStop: () => void;
}

const Ctx = createContext<StoreValue | null>(null);

export function useStore(): StoreValue {
  const v = useContext(Ctx);
  if (!v) throw new Error('useStore outside provider');
  return v;
}

export function StoreProvider({ children }: { children: React.ReactNode }): JSX.Element {
  const [project, setProject] = useState<ProjectInfo | undefined>(undefined);
  const [proxy, setProxy] = useState<ProxyStatusDto>({ running: false, loopbackOnly: true });
  const [intercept, setIntercept] = useState<InterceptState>({
    interceptRequests: false,
    interceptResponses: false,
  });
  const [pendingRequests, setPendingRequests] = useState<InterceptedRequestView[]>([]);
  const [pendingResponses, setPendingResponses] = useState<InterceptedResponseView[]>([]);
  const [findingsCount, setFindingsCount] = useState(0);
  const [jobs, setJobs] = useState<JobProgress[]>([]);
  const [exchangeTick, setExchangeTick] = useState(0);
  const [view, setView] = useState<ViewId>('history');
  const [theme, setTheme] = useState<'dark' | 'light'>('dark');
  const [toast, setToast] = useState<string | undefined>(undefined);
  const [repeaterSeed, setRepeaterSeed] = useState<RepeaterSeed | undefined>(undefined);

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme);
  }, [theme]);

  const refreshProxy = useCallback(() => {
    void api.getProxyStatus().then(setProxy);
  }, []);
  const refreshIntercept = useCallback(() => {
    void api.getInterceptState().then(setIntercept);
    void api.listPendingRequests().then(setPendingRequests);
    void api.listPendingResponses().then(setPendingResponses);
  }, []);
  const refreshFindings = useCallback(() => {
    void api.listFindings().then((f) => setFindingsCount(f.length));
  }, []);
  const refreshJobs = useCallback(() => {
    void api.listVariationJobs().then(setJobs);
  }, []);

  // Event subscription
  useEffect(() => {
    const off = api.onEvent((e) => {
      switch (e.type) {
        case 'proxy-state':
          setProxy(e.payload);
          break;
        case 'intercept-state':
          setIntercept(e.payload);
          break;
        case 'intercept-request':
        case 'intercept-response':
        case 'intercept-pending':
          refreshIntercept();
          break;
        case 'exchange':
          setExchangeTick((t) => t + 1);
          break;
        case 'finding':
          setFindingsCount((c) => c + 1);
          break;
        case 'job-progress':
        case 'job-done':
          setJobs((prev) => {
            const next = prev.filter((j) => j.id !== e.payload.id);
            next.push(e.payload);
            return next;
          });
          break;
        case 'emergency-stop':
          setToast('Emergency stop: all automated work halted.');
          refreshJobs();
          break;
        case 'project-open':
          setProject(e.payload);
          break;
        default:
          break;
      }
    });
    return off;
  }, [refreshIntercept, refreshJobs]);

  // Load initial state when a project opens
  useEffect(() => {
    if (!project) return;
    refreshProxy();
    refreshIntercept();
    refreshFindings();
    refreshJobs();
  }, [project, refreshProxy, refreshIntercept, refreshFindings, refreshJobs]);

  const emergencyStop = useCallback(() => {
    void api.emergencyStop().then(() => {
      setToast('Emergency stop invoked.');
      refreshJobs();
    });
  }, [refreshJobs]);

  const value = useMemo<StoreValue>(
    () => ({
      project,
      proxy,
      intercept,
      pendingRequests,
      pendingResponses,
      findingsCount,
      jobs,
      exchangeTick,
      view,
      theme,
      toast,
      repeaterSeed,
      setView,
      toggleTheme: () => setTheme((t) => (t === 'dark' ? 'light' : 'dark')),
      setToast,
      seedRepeater: (s) => {
        setRepeaterSeed(s);
        setView('repeater');
      },
      refreshProxy,
      refreshIntercept,
      refreshFindings,
      refreshJobs,
      setProject,
      emergencyStop,
    }),
    [
      project,
      proxy,
      intercept,
      pendingRequests,
      pendingResponses,
      findingsCount,
      jobs,
      exchangeTick,
      view,
      theme,
      toast,
      repeaterSeed,
      refreshProxy,
      refreshIntercept,
      refreshFindings,
      refreshJobs,
      emergencyStop,
    ],
  );

  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}
