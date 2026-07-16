/**
 * History repository — persists and queries captured HTTP exchanges.
 *
 * The exchange is flattened into columns for fast filtering; headers/tags are
 * JSON, bodies are either inline BLOBs (small) or blob-store references (large).
 */

import type {
  CapturedRequest,
  CapturedResponse,
  HttpExchange,
  HttpHeader,
  MessageBody,
  MessageSource,
  Scheme,
} from '../../shared/model.js';
import { mimeType } from '../../shared/model.js';
import type { HistoryFilter, HistoryPage } from '../../shared/query.js';
import type { Database, SqlParam } from './database.js';
import type { ContentCipher } from '../crypto/contentCipher.js';

interface ExchangeRow {
  id: string;
  created_at: number;
  source: string;
  scheme: string;
  host: string;
  port: number;
  in_scope: number;
  automated: number;
  job_id: string | null;
  method: string;
  target: string;
  url: string;
  req_http_version: string;
  req_headers: string;
  req_body_size: number;
  req_body_trunc: number;
  req_body_enc: string | null;
  req_body_blob: string | null;
  req_body_inline: Uint8Array | null;
  status_code: number | null;
  status_message: string | null;
  res_http_version: string | null;
  res_headers: string | null;
  res_body_size: number;
  res_body_trunc: number;
  res_body_enc: string | null;
  res_body_blob: string | null;
  res_body_inline: Uint8Array | null;
  mime: string | null;
  timing_started: number | null;
  timing_ttfb: number | null;
  timing_duration: number | null;
  notes: string | null;
  tags: string;
  error: string | null;
}

const INSERT_SQL = `
  INSERT INTO exchanges (
    id, created_at, source, scheme, host, port, in_scope, automated, job_id,
    method, target, url, req_http_version, req_headers,
    req_body_size, req_body_trunc, req_body_enc, req_body_blob, req_body_inline,
    status_code, status_message, res_http_version, res_headers,
    res_body_size, res_body_trunc, res_body_enc, res_body_blob, res_body_inline,
    mime, timing_started, timing_ttfb, timing_duration, notes, tags, error
  ) VALUES (
    ?, ?, ?, ?, ?, ?, ?, ?, ?,
    ?, ?, ?, ?, ?,
    ?, ?, ?, ?, ?,
    ?, ?, ?, ?,
    ?, ?, ?, ?, ?,
    ?, ?, ?, ?, ?, ?, ?
  )`;

export class HistoryRepo {
  constructor(
    private readonly db: Database,
    private readonly cipher?: ContentCipher,
  ) {}

  private encText(s: string): string {
    return this.cipher ? this.cipher.sealText(s) : s;
  }
  private encBytes(b: Uint8Array): Buffer {
    return this.cipher ? this.cipher.seal(b) : Buffer.from(b);
  }

  insert(ex: HttpExchange): void {
    const req = ex.request;
    const res = ex.response;
    const params: SqlParam[] = [
      ex.id,
      ex.createdAt,
      ex.source,
      ex.scheme,
      ex.host,
      ex.port,
      ex.inScope ? 1 : 0,
      ex.automated ? 1 : 0,
      ex.jobId ?? null,
      req.method,
      req.target,
      req.url,
      req.httpVersion,
      this.encText(JSON.stringify(req.headers)),
      req.body.size,
      req.body.truncated ? 1 : 0,
      req.body.contentEncoding ?? null,
      req.body.blobId ?? null,
      req.body.inline ? this.encBytes(req.body.inline) : null,
      res?.statusCode ?? null,
      res?.statusMessage ?? null,
      res?.httpVersion ?? null,
      res ? this.encText(JSON.stringify(res.headers)) : null,
      res?.body.size ?? 0,
      res?.body.truncated ? 1 : 0,
      res?.body.contentEncoding ?? null,
      res?.body.blobId ?? null,
      res?.body.inline ? this.encBytes(res.body.inline) : null,
      res ? (mimeType(res.headers) ?? null) : null,
      ex.timing?.startedAt ?? null,
      ex.timing?.ttfbMs ?? null,
      ex.timing?.durationMs ?? null,
      ex.notes ? this.encText(ex.notes) : null,
      JSON.stringify(ex.tags ?? []),
      ex.error ?? null,
    ];
    this.db.run(INSERT_SQL, ...params);
  }

  get(id: string): HttpExchange | undefined {
    const row = this.db.get<ExchangeRow>('SELECT * FROM exchanges WHERE id = ?', id);
    return row ? rowToExchange(row, this.cipher) : undefined;
  }

  updateNotesTags(id: string, notes: string | null, tags: string[]): void {
    this.db.run(
      'UPDATE exchanges SET notes = ?, tags = ? WHERE id = ?',
      notes ? this.encText(notes) : null,
      JSON.stringify(tags),
      id,
    );
  }

  count(): number {
    const row = this.db.get<{ n: number }>('SELECT COUNT(*) AS n FROM exchanges');
    return row?.n ?? 0;
  }

  clear(): void {
    this.db.run('DELETE FROM exchanges');
  }

  query(filter: HistoryFilter): HistoryPage<HttpExchange> {
    const { where, params } = buildWhere(filter);
    const sort = filter.sort === 'asc' ? 'ASC' : 'DESC';
    const limit = Math.min(Math.max(filter.limit ?? 200, 1), 2000);
    const offset = Math.max(filter.offset ?? 0, 0);

    const totalRow = this.db.get<{ n: number }>(
      `SELECT COUNT(*) AS n FROM exchanges ${where}`,
      ...params,
    );
    const rows = this.db.all<ExchangeRow>(
      `SELECT * FROM exchanges ${where} ORDER BY created_at ${sort}, rowid ${sort} LIMIT ? OFFSET ?`,
      ...params,
      limit,
      offset,
    );
    return {
      rows: rows.map((r) => rowToExchange(r, this.cipher)),
      total: totalRow?.n ?? 0,
      limit,
      offset,
    };
  }
}

function buildWhere(filter: HistoryFilter): { where: string; params: SqlParam[] } {
  const clauses: string[] = [];
  const params: SqlParam[] = [];

  if (filter.text) {
    clauses.push('(url LIKE ? OR host LIKE ? OR method LIKE ?)');
    const like = `%${filter.text}%`;
    params.push(like, like, like);
  }
  if (filter.method) {
    clauses.push('method = ?');
    params.push(filter.method.toUpperCase());
  }
  if (filter.host) {
    clauses.push('host LIKE ?');
    params.push(`%${filter.host}%`);
  }
  if (typeof filter.status === 'number') {
    clauses.push('status_code = ?');
    params.push(filter.status);
  }
  if (typeof filter.statusClass === 'number') {
    clauses.push('status_code >= ? AND status_code < ?');
    params.push(filter.statusClass * 100, (filter.statusClass + 1) * 100);
  }
  if (filter.mime) {
    clauses.push('mime LIKE ?');
    params.push(`%${filter.mime.toLowerCase()}%`);
  }
  if (filter.source) {
    clauses.push('source = ?');
    params.push(filter.source);
  }
  if (filter.inScopeOnly) {
    clauses.push('in_scope = 1');
  }
  if (filter.automatedOnly) {
    clauses.push('automated = 1');
  }
  if (typeof filter.since === 'number') {
    clauses.push('created_at >= ?');
    params.push(filter.since);
  }
  if (typeof filter.until === 'number') {
    clauses.push('created_at <= ?');
    params.push(filter.until);
  }

  return { where: clauses.length ? `WHERE ${clauses.join(' AND ')}` : '', params };
}

function bodyFromRow(
  size: number,
  trunc: number,
  enc: string | null,
  blob: string | null,
  inline: Uint8Array | null,
  cipher?: ContentCipher,
): MessageBody {
  const body: MessageBody = { size, truncated: trunc === 1 };
  if (enc) body.contentEncoding = enc;
  if (blob) body.blobId = blob;
  if (inline) body.inline = cipher ? cipher.open(inline) : inline;
  return body;
}

function rowToExchange(row: ExchangeRow, cipher?: ContentCipher): HttpExchange {
  const decJson = (s: string): HttpHeader[] =>
    JSON.parse(cipher ? cipher.openText(s) : s) as HttpHeader[];

  const request: CapturedRequest = {
    method: row.method,
    target: row.target,
    url: row.url,
    httpVersion: row.req_http_version,
    headers: decJson(row.req_headers),
    body: bodyFromRow(
      row.req_body_size,
      row.req_body_trunc,
      row.req_body_enc,
      row.req_body_blob,
      row.req_body_inline,
      cipher,
    ),
  };

  let response: CapturedResponse | undefined;
  if (row.status_code !== null && row.res_headers !== null) {
    response = {
      statusCode: row.status_code,
      statusMessage: row.status_message ?? '',
      httpVersion: row.res_http_version ?? 'HTTP/1.1',
      headers: decJson(row.res_headers),
      body: bodyFromRow(
        row.res_body_size,
        row.res_body_trunc,
        row.res_body_enc,
        row.res_body_blob,
        row.res_body_inline,
        cipher,
      ),
    };
  }

  const ex: HttpExchange = {
    id: row.id,
    createdAt: row.created_at,
    source: row.source as MessageSource,
    scheme: row.scheme as Scheme,
    host: row.host,
    port: row.port,
    inScope: row.in_scope === 1,
    automated: row.automated === 1,
    request,
    tags: JSON.parse(row.tags) as string[],
  };
  if (response) ex.response = response;
  if (row.job_id) ex.jobId = row.job_id;
  if (row.notes) ex.notes = cipher ? cipher.openText(row.notes) : row.notes;
  if (row.error) ex.error = row.error;
  if (row.timing_started !== null) {
    ex.timing = {
      startedAt: row.timing_started,
      ...(row.timing_ttfb !== null ? { ttfbMs: row.timing_ttfb } : {}),
      ...(row.timing_duration !== null ? { durationMs: row.timing_duration } : {}),
    };
  }
  return ex;
}
