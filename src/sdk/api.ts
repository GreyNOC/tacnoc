/**
 * GreyNOC Belcher Extension SDK — public API surface (v1).
 *
 * The API is CAPABILITY-BASED: an extension declares the permissions it needs in
 * its manifest, the user approves them, and the host injects an API object that
 * exposes ONLY the granted capabilities. There is deliberately NO permission
 * that grants filesystem, process, network, or secret access — extensions
 * cannot obtain those through this SDK.
 *
 * See docs/extension-sdk.md for the isolation model and its limits.
 */

import type { ScannerCheck } from '../engine/scanner/types.js';
import type { TextTransform } from '../engine/transforms/codec.js';
import type { Finding } from '../shared/findings.js';
import type { MessageSource, Scheme, HttpHeader } from '../shared/model.js';

export const SDK_VERSION = '1.0.0';

export type Permission =
  | 'read-traffic' // subscribe to sanitized traffic events (elevated)
  | 'passive-checks' // register passive scanner checks
  | 'transforms' // register data transformations
  | 'findings' // create findings (elevated)
  | 'ui-tabs' // register read-only editor tabs
  | 'context-menu'; // register context-menu actions

/** Permissions that expose data or write findings; require explicit approval. */
export const ELEVATED_PERMISSIONS: ReadonlySet<Permission> = new Set(['read-traffic', 'findings']);

export const ALL_PERMISSIONS: Permission[] = [
  'read-traffic',
  'passive-checks',
  'transforms',
  'findings',
  'ui-tabs',
  'context-menu',
];

export interface ExtensionManifest {
  id: string;
  name: string;
  version: string;
  description: string;
  author?: string;
  /** SDK major version the extension targets. */
  sdkVersion: string;
  permissions: Permission[];
}

/** Sanitized view of an exchange handed to `onTraffic` subscribers. Bodies are
 *  intentionally omitted; headers are redacted. */
export interface SanitizedTrafficEvent {
  id: string;
  source: MessageSource;
  scheme: Scheme;
  host: string;
  port: number;
  method: string;
  url: string;
  inScope: boolean;
  requestHeaders: HttpHeader[];
  statusCode?: number;
  responseHeaders?: HttpHeader[];
  responseMime?: string;
}

/** A finding an extension asks the host to create. The host fills id/timestamps. */
export interface ExtensionFinding {
  exchangeId: string;
  dedupeKey: string;
  title: string;
  severity: Finding['severity'];
  confidence: Finding['confidence'];
  description: string;
  remediation: string;
  evidence: {
    location: Finding['evidence'][number]['location'];
    excerpt: string;
    field?: string;
  }[];
}

/** A read-only editor tab. `render` returns PLAIN TEXT (never executed as HTML). */
export interface ExtensionEditorTab {
  id: string;
  label: string;
  render: (event: SanitizedTrafficEvent) => string;
}

export interface ExtensionContextMenuAction {
  id: string;
  label: string;
  /** Invoked with the selected exchange id; runs in the engine, not the page. */
  onInvoke: (exchangeId: string) => void | Promise<void>;
}

/**
 * The API object injected into an extension's `activate(belcher)` function.
 * Only methods for granted permissions are present.
 */
export interface BelcherExtensionApi {
  readonly version: string;
  readonly manifest: Readonly<ExtensionManifest>;
  /** Structured, redacted log line (local only). Always available. */
  log(message: string): void;

  onTraffic?(handler: (event: SanitizedTrafficEvent) => void): void;
  registerScannerCheck?(check: ScannerCheck): void;
  registerTransform?(transform: TextTransform): void;
  createFinding?(finding: ExtensionFinding): void;
  registerEditorTab?(tab: ExtensionEditorTab): void;
  registerContextMenuAction?(action: ExtensionContextMenuAction): void;
}

/** Shape of an extension module: it exports an `activate` function. */
export interface ExtensionModule {
  activate: (belcher: BelcherExtensionApi) => void;
}
