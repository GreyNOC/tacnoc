/** DTOs for the captured-traffic target/site map. */

import type { Scheme } from './model.js';

export interface TargetEndpoint {
  /** Stable within a generated map: origin + normalized path. */
  id: string;
  path: string;
  methods: string[];
  statusCodes: number[];
  mimeTypes: string[];
  parameterNames: string[];
  requestCount: number;
  firstSeen: number;
  lastSeen: number;
  latestExchangeId: string;
  inScope: boolean;
}

export interface TargetSite {
  id: string;
  scheme: Scheme;
  host: string;
  port: number;
  requestCount: number;
  firstSeen: number;
  lastSeen: number;
  inScopeEndpoints: number;
  endpoints: TargetEndpoint[];
}

export interface TargetMap {
  generatedAt: number;
  totalExchanges: number;
  analyzedExchanges: number;
  /**
   * True when the bounded metadata scan omitted older exchanges. When true, the
   * per-site/endpoint `requestCount` and `firstSeen` describe only the analyzed
   * window (the newest `analyzedExchanges` rows), not the full history.
   */
  truncated: boolean;
  sites: TargetSite[];
}
