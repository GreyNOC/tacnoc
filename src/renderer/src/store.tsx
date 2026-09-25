import React, {
  createContext,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  useCallback,
} from 'react';
import { api } from './api.js';
import type { ProxyStatusDto } from '@shared/ipc.js';
import type {
  InterceptState,
  InterceptedRequestView,
  InterceptedResponseView,
} from '@shared/intercept.js';
import type { JobProgress } from '@shared/variation.js';
import type { ProjectInfo } from '@shared/project.js';
import {
  TOUR_VERSION,
  advanceTour,
  defaultUiPreferences,
  resumeStep,
  restartTour,
  shouldOfferTour,
  skipTour as skippedTourState,
  type TourState,
  type UiPreferences,
} from '@shared/guide.js';
import { TOUR_STEPS, stepAt } from './guide/tourSteps.js';

export type ViewId =
  | 'setup'
  | 'history'
  | 'target'
  | 'intercept'
  | 'repeater'
  | 'findings'
  | 'scope'
  | 'variation'
  | 'sequencer'
  | 'encoder'
  | 'compare'
  | 'certificate'
  | 'engagement'
  | 'extensions'
  | 'audit'
  | 'ai'
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
  engagementTick: number;
  view: ViewId;
  theme: 'dark' | 'light';
  toast?: string;
  repeaterSeed?: RepeaterSeed;

  /** Persisted walkthrough state; `tourActive` is this session's view of it. */
  tour: TourState;
  tourActive: boolean;
  tourStep: number;

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
  startTour: () => void;
  skipTour: () => void;
  dismissTour: () => void;
  stepTour: (delta: number) => void;
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
  /**
   * Bumped by the events preflight reads but nothing else in the store tracked:
   * scope, CA and engagement changes. Without it the Setup checklist sat on a
   * stale verdict whenever something moved while it was on screen — the mesh
   * applying a proposed scope, or an extension — which is exactly the engine-vs-
   * checklist disagreement it exists to avoid.
   */
  const [engagementTick, setEngagementTick] = useState(0);
  // A fresh window lands on Setup: until scope and a CA exist the history
  // table is necessarily empty, which reads as 'broken' rather than 'not set up yet'.
  const [view, setView] = useState<ViewId>('setup');
  const [theme, setTheme] = useState<'dark' | 'light'>('dark');
  const [toast, setToast] = useState<string | undefined>(undefined);
  const [repeaterSeed, setRepeaterSeed] = useState<RepeaterSeed | undefined>(undefined);
  const [prefs, setPrefs] = useState<UiPreferences>(defaultUiPreferences());
  const [tourActive, setTourActive] = useState(false);
  const [tourStep, setTourStep] = useState(0);
  /** Offered at most once per session, not once per project-open. */
  const [tourOffered, setTourOffered] = useState(false);
  /**
   * Preferences arrive over IPC, so they can land AFTER a project opens.
   * Without this the offer would run against the defaults — status 'unseen' —
   * and re-show a walkthrough the operator had already skipped.
   */
  const [prefsLoaded, setPrefsLoaded] = useState(false);
  /**
   * Where the operator was before the walkthrough started driving the view.
   * Skipping puts them back: the tour navigated them to a view they never
   * chose, so abandoning it should not strand them there.
   */
  const tourReturnView = useRef<ViewId>('setup');

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme);
  }, [theme]);

  useEffect(() => {
    void api
      .getUiPrefs()
      .then(setPrefs)
      .catch(() => setPrefs(defaultUiPreferences()))
      .finally(() => setPrefsLoaded(true));
  }, []);

  /** Persist and keep the in-memory copy in step; failures are not worth a toast. */
  /**
   * Persist, and say so when it does not work.
   *
   * Settings promises the walkthrough "will not come back on its own once you
   * have skipped" — a read-only userData made that a lie in silence: the skip
   * held for the session and the tour returned on the next launch.
   */
  const persistTour = useCallback((tour: TourState) => {
    setPrefs((p) => ({ ...p, tour }));
    void api.setUiPrefs({ tour }).catch((e: unknown) => {
      setToast(
        `Could not save your walkthrough preference — it will not survive a restart. ${
          e instanceof Error ? e.message : String(e)
        }`,
      );
    });
  }, []);

  // Offer the walkthrough once a project is open — not on the welcome screen,
  // where the views it steps through do not exist yet.
  useEffect(() => {
    if (!project || tourOffered || !prefsLoaded) return;
    setTourOffered(true);
    if (!shouldOfferTour(prefs)) return;
    const step = resumeStep(prefs, TOUR_STEPS.length);
    setTourStep(step);
    setView((current) => {
      tourReturnView.current = current;
      return stepAt(step).view;
    });
    setTourActive(true);
  }, [project, prefs, tourOffered, prefsLoaded]);

  const startTour = useCallback(() => {
    const tour = restartTour();
    persistTour(tour);
    setTourStep(0);
    setTourActive(true);
    setView((current) => {
      tourReturnView.current = current;
      return stepAt(0).view;
    });
  }, [persistTour]);

  const skipTour = useCallback(() => {
    persistTour(skippedTourState());
    setTourActive(false);
    setView(tourReturnView.current);
  }, [persistTour]);

  /**
   * "Not now", as distinct from "never" — what Escape does.
   *
   * Leaves the tour in-progress so it resumes, rather than burning the operator's
   * one skip on a reflex keypress. Skip remains the button that means never.
   */
  const dismissTour = useCallback(() => {
    setTourStep((current) => {
      persistTour({ status: 'in-progress', step: current, version: TOUR_VERSION });
      return current;
    });
    setTourActive(false);
    setView(tourReturnView.current);
  }, [persistTour]);

  const stepTour = useCallback(
    (delta: number) => {
      setTourStep((current) => {
        const next = advanceTour(
          { status: 'in-progress', step: current, version: prefs.tour.version },
          delta,
          TOUR_STEPS.length,
        );
        persistTour(next);
        if (next.status === 'done') {
          setTourActive(false);
          return current;
        }
        setView(stepAt(next.step).view);
        return next.step;
      });
    },
    [persistTour, prefs.tour.version],
  );

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
        case 'scope-changed':
        case 'ca-changed':
        case 'engagement-changed':
          setEngagementTick((t) => t + 1);
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
      engagementTick,
      view,
      theme,
      toast,
      repeaterSeed,
      tour: prefs.tour,
      tourActive,
      tourStep,
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
      startTour,
      skipTour,
      dismissTour,
      stepTour,
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
      engagementTick,
      view,
      theme,
      toast,
      repeaterSeed,
      prefs.tour,
      tourActive,
      tourStep,
      refreshProxy,
      refreshIntercept,
      refreshFindings,
      refreshJobs,
      emergencyStop,
      startTour,
      skipTour,
      dismissTour,
      stepTour,
    ],
  );

  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}
