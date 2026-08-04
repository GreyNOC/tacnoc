/**
 * ProjectStore ties together the database, blob store, CA, and repositories for
 * one open research project. A project lives in a directory:
 *
 *   <name>.tacnocproj/
 *     belcher.db        SQLite (metadata, history rows, findings, audit)
 *     blobs/            content-addressed body store
 *     ca.pem            public project CA certificate (safe to share/trust)
 *     secrets.*         only in the file-secret-store fallback (headless/CI)
 *
 * The CA private key is held in the injected SecretStore (OS secure storage in
 * the app; file fallback for tests).
 */

import { promises as fs } from 'node:fs';
import * as path from 'node:path';
import * as crypto from 'node:crypto';
import { Database } from '../storage/database.js';
import { BlobStore } from '../storage/blobStore.js';
import { HistoryRepo } from '../storage/historyRepo.js';
import { MetaRepo } from '../storage/metaRepo.js';
import { FindingsRepo } from '../storage/findingsRepo.js';
import { AuditRepo } from '../storage/auditRepo.js';
import { WsMessageRepo } from '../storage/wsRepo.js';
import { readBodyBytes } from '../storage/bodyCollector.js';
import { CertificateAuthority } from '../ca/certificateAuthority.js';
import { FileSecretStore, type SecretStore } from '../ca/secretStore.js';
import { ContentCipher } from '../crypto/contentCipher.js';
import { defaultEngineConfig } from '../config.js';
import type { EngineConfig } from '../../shared/config.js';
import type { ScopeConfig } from '../../shared/scope.js';
import type { ProjectInfo, SavedRequest } from '../../shared/project.js';
import type { HttpExchange, MessageBody } from '../../shared/model.js';

export const PROJECT_FORMAT_VERSION = 1;
const DB_FILE = 'belcher.db';
const BLOBS_DIR = 'blobs';
const CA_FILE = 'ca.pem';
const DEK_SECRET = 'project-data-key';

/** Load the project data-encryption key, creating it on first use if allowed. */
async function loadOrCreateDek(
  secretStore: SecretStore,
  allowCreate: boolean,
): Promise<ContentCipher | undefined> {
  const existing = await secretStore.get(DEK_SECRET);
  if (existing) return new ContentCipher(Buffer.from(existing, 'base64'));
  if (!allowCreate) return undefined; // legacy/unencrypted project
  const key = ContentCipher.generateKey();
  await secretStore.set(DEK_SECRET, key.toString('base64'));
  return new ContentCipher(key);
}

export interface OpenProjectOptions {
  /** Custom secret store. Defaults to a file-backed store in the project dir. */
  secretStore?: SecretStore;
}

export interface CreateProjectOptions extends OpenProjectOptions {
  name: string;
  appVersion?: string;
  authorizationRef?: string;
  config?: EngineConfig;
}

export class ProjectStore {
  readonly history: HistoryRepo;
  readonly meta: MetaRepo;
  readonly findings: FindingsRepo;
  readonly audit: AuditRepo;
  readonly wsMessages: WsMessageRepo;
  readonly blobs: BlobStore;

  /** True when captured content (bodies/headers) is encrypted at rest. */
  readonly encryptedAtRest: boolean;

  private constructor(
    readonly directory: string,
    private readonly db: Database,
    readonly ca: CertificateAuthority,
    private readonly secretStore: SecretStore,
    private readonly cipher?: ContentCipher,
  ) {
    this.encryptedAtRest = !!cipher;
    this.blobs = new BlobStore(path.join(directory, BLOBS_DIR), cipher);
    this.history = new HistoryRepo(db, cipher);
    this.meta = new MetaRepo(db);
    this.findings = new FindingsRepo(db);
    this.audit = new AuditRepo(db);
    this.wsMessages = new WsMessageRepo(db, cipher);
  }

  static async create(directory: string, options: CreateProjectOptions): Promise<ProjectStore> {
    await fs.mkdir(directory, { recursive: true });
    await fs.mkdir(path.join(directory, BLOBS_DIR), { recursive: true });
    const secretStore = options.secretStore ?? new FileSecretStore(directory);
    const db = Database.open(path.join(directory, DB_FILE));
    const ca = await CertificateAuthority.loadOrCreate(path.join(directory, CA_FILE), secretStore);
    const cipher = await loadOrCreateDek(secretStore, true);
    const store = new ProjectStore(directory, db, ca, secretStore, cipher);

    const info: ProjectInfo = {
      name: options.name,
      createdAt: Date.now(),
      formatVersion: PROJECT_FORMAT_VERSION,
      appVersion: options.appVersion ?? '0.1.0',
      ...(options.authorizationRef ? { authorizationRef: options.authorizationRef } : {}),
    };
    store.meta.setInfo(info);
    store.meta.setConfig(options.config ?? defaultEngineConfig());
    store.meta.setScope(store.meta.getScope()); // persist an empty fail-closed scope
    return store;
  }

  static async open(directory: string, options: OpenProjectOptions = {}): Promise<ProjectStore> {
    const dbPath = path.join(directory, DB_FILE);
    await fs.access(dbPath); // throws a clear error if the project doesn't exist
    const secretStore = options.secretStore ?? new FileSecretStore(directory);
    const db = Database.open(dbPath);
    const ca = await CertificateAuthority.loadOrCreate(path.join(directory, CA_FILE), secretStore);
    const cipher = await loadOrCreateDek(secretStore, false);
    return new ProjectStore(directory, db, ca, secretStore, cipher);
  }

  get info(): ProjectInfo | undefined {
    return this.meta.getInfo();
  }
  get scope(): ScopeConfig {
    return this.meta.getScope();
  }
  get config(): EngineConfig {
    return this.meta.getConfig() ?? defaultEngineConfig();
  }

  /** How the CA private key is held, for the certificate status display. */
  get caKeyBackend(): { secure: boolean; name: string } {
    return { secure: this.secretStore.isSecure(), name: this.secretStore.backendName() };
  }

  // --- saved repeater requests ---

  saveRequest(req: SavedRequest): void {
    this.db.run(
      `INSERT INTO saved_requests (id, name, created_at, scheme, host, port, raw, notes)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(id) DO UPDATE SET name=excluded.name, raw=excluded.raw, notes=excluded.notes`,
      req.id,
      req.name,
      req.createdAt,
      req.scheme,
      req.host,
      req.port,
      req.raw,
      req.notes ?? null,
    );
  }

  listSavedRequests(): SavedRequest[] {
    const rows = this.db.all<{
      id: string;
      name: string;
      created_at: number;
      scheme: string;
      host: string;
      port: number;
      raw: string;
      notes: string | null;
    }>('SELECT * FROM saved_requests ORDER BY created_at DESC');
    return rows.map((r) => ({
      id: r.id,
      name: r.name,
      createdAt: r.created_at,
      scheme: r.scheme,
      host: r.host,
      port: r.port,
      raw: r.raw,
      ...(r.notes ? { notes: r.notes } : {}),
    }));
  }

  close(): void {
    this.db.close();
  }

  // --- export / import (versioned portable format) ---

  async export(options: { maxBodyBytes?: number } = {}): Promise<ProjectExportV1> {
    const maxBody = options.maxBodyBytes ?? 25 * 1024 * 1024;
    const exchanges: ExportedExchange[] = [];
    // Page through ALL exchanges so large projects export in full (not just the
    // first page).
    const pageSize = 2000;
    for (let offset = 0; ; offset += pageSize) {
      const page = this.history.query({ limit: pageSize, offset, sort: 'asc' });
      for (const ex of page.rows) {
        exchanges.push({
          ...stripBodies(ex),
          requestBody: await this.exportBody(ex.request.body, maxBody),
          responseBody: ex.response ? await this.exportBody(ex.response.body, maxBody) : undefined,
        });
      }
      if (offset + page.rows.length >= page.total || page.rows.length === 0) break;
    }
    // Page through ALL captured WebSocket messages so a WS-heavy project exports
    // in full (payloads are returned decrypted here and re-encrypted on import).
    const websockets: import('../../shared/websocket.js').WsMessage[] = [];
    const wsTotal = this.wsMessages.countAll();
    for (let offset = 0; offset < wsTotal; offset += pageSize) {
      const page = this.wsMessages.listAll(pageSize, offset);
      if (page.length === 0) break;
      websockets.push(...page);
    }

    const info = this.info;
    if (!info) throw new Error('project has no info record');
    return {
      format: 'greynoc-belcher-project',
      formatVersion: PROJECT_FORMAT_VERSION,
      exportedAt: Date.now(),
      info,
      scope: this.scope,
      config: this.config,
      exchanges,
      findings: this.findings.list({ includeSuppressed: true }),
      suppressions: this.findings.listSuppressions(),
      savedRequests: this.listSavedRequests(),
      audit: this.audit.list(5000),
      websockets,
    };
  }

  private async exportBody(body: MessageBody, maxBody: number): Promise<ExportedBody> {
    if (body.size === 0) return { size: 0, truncated: body.truncated };
    if (body.size > maxBody) {
      return { size: body.size, truncated: true, omitted: true };
    }
    const bytes = await readBodyBytes(body, this.blobs);
    return {
      size: body.size,
      truncated: body.truncated,
      ...(body.contentEncoding ? { contentEncoding: body.contentEncoding } : {}),
      dataB64: Buffer.from(bytes).toString('base64'),
    };
  }

  /** Rebuild a project directory from an export. */
  static async import(
    exported: ProjectExportV1,
    directory: string,
    options: OpenProjectOptions = {},
  ): Promise<ProjectStore> {
    if (exported.format !== 'greynoc-belcher-project') {
      throw new Error('unrecognized project export format');
    }
    if (exported.formatVersion > PROJECT_FORMAT_VERSION) {
      throw new Error(
        `export format v${exported.formatVersion} is newer than supported v${PROJECT_FORMAT_VERSION}`,
      );
    }
    const store = await ProjectStore.create(directory, {
      name: exported.info.name,
      appVersion: exported.info.appVersion,
      ...(exported.info.authorizationRef
        ? { authorizationRef: exported.info.authorizationRef }
        : {}),
      config: exported.config,
      ...(options.secretStore ? { secretStore: options.secretStore } : {}),
    });
    store.meta.setScope(exported.scope);
    store.meta.setInfo(exported.info);

    for (const ex of exported.exchanges) {
      const rebuilt = await store.rebuildExchange(ex);
      store.history.insert(rebuilt);
    }
    for (const f of exported.findings) store.findings.upsert(f);
    for (const s of exported.suppressions) store.findings.addSuppression(s);
    for (const r of exported.savedRequests) store.saveRequest(r);
    for (const a of exported.audit) store.audit.append(a);
    // Restore captured WebSocket frames (older exports omit the field). Insert
    // after exchanges so the ws_messages → exchanges foreign key is satisfied;
    // payloads are re-sealed under the new project's key by wsMessages.insert.
    for (const w of exported.websockets ?? []) {
      store.wsMessages.insert({
        id: w.id,
        exchangeId: w.exchangeId,
        seq: w.seq,
        direction: w.direction,
        kind: w.kind,
        size: w.size,
        truncated: w.truncated,
        payload: Buffer.from(w.payloadBase64, 'base64'),
        createdAt: w.createdAt,
      });
    }
    return store;
  }

  private async rebuildExchange(ex: ExportedExchange): Promise<HttpExchange> {
    const request = { ...ex.request, body: await this.importBody(ex.requestBody) };
    const rebuilt: HttpExchange = { ...ex, request } as HttpExchange;
    if (ex.response && ex.responseBody) {
      rebuilt.response = { ...ex.response, body: await this.importBody(ex.responseBody) };
    }
    return rebuilt;
  }

  private async importBody(body: ExportedBody | undefined): Promise<MessageBody> {
    if (!body || body.size === 0) return { size: 0, truncated: body?.truncated ?? false };
    if (body.omitted || !body.dataB64) {
      return { size: body.size, truncated: true };
    }
    const bytes = Buffer.from(body.dataB64, 'base64');
    const out: MessageBody = { size: bytes.byteLength, truncated: body.truncated };
    if (body.contentEncoding) out.contentEncoding = body.contentEncoding;
    // Small bodies inline; larger go to the blob store.
    if (bytes.byteLength <= 64 * 1024) {
      out.inline = bytes;
    } else {
      const ref = await this.blobs.putBytes(bytes);
      out.blobId = ref.id;
    }
    return out;
  }

  static newId(): string {
    return crypto.randomUUID();
  }
}

// --- export types ---

export interface ExportedBody {
  size: number;
  truncated: boolean;
  contentEncoding?: string;
  dataB64?: string;
  /** True if the body was too large to include in the export. */
  omitted?: boolean;
}

export type ExportedExchange = Omit<HttpExchange, 'request' | 'response'> & {
  request: Omit<HttpExchange['request'], 'body'>;
  response?: Omit<NonNullable<HttpExchange['response']>, 'body'>;
  requestBody: ExportedBody;
  responseBody?: ExportedBody;
};

export interface ProjectExportV1 {
  format: 'greynoc-belcher-project';
  formatVersion: number;
  exportedAt: number;
  info: ProjectInfo;
  scope: ScopeConfig;
  config: EngineConfig;
  exchanges: ExportedExchange[];
  findings: import('../../shared/findings.js').Finding[];
  suppressions: import('../../shared/findings.js').SuppressionRule[];
  savedRequests: SavedRequest[];
  audit: import('../../shared/project.js').AuditEntry[];
  /** Captured WebSocket frames. Optional: exports before this field omit it. */
  websockets?: import('../../shared/websocket.js').WsMessage[];
}

function stripBodies(ex: HttpExchange): Omit<ExportedExchange, 'requestBody' | 'responseBody'> {
  const { request, response, ...rest } = ex;
  const { body: _rb, ...requestNoBody } = request;
  const base = { ...rest, request: requestNoBody } as Omit<
    ExportedExchange,
    'requestBody' | 'responseBody'
  >;
  if (response) {
    const { body: _sb, ...responseNoBody } = response;
    (base as { response?: unknown }).response = responseNoBody;
  }
  return base;
}
