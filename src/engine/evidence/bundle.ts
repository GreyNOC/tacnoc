/**
 * Assembling one target's evidence into a bundle.
 *
 * The bundle is deliberately boring: a ZIP of text files a person can read
 * without this app, laid out so the interesting thing is findable in seconds.
 * Anything clever here would be a liability — evidence that needs the tool that
 * produced it to be understood is not evidence, it is a screenshot.
 *
 * What it must never do is leak. Three rules hold the line:
 *
 *  1. **Redacted by default.** Headers, bodies and URLs go through `Redactor`
 *     unless the operator explicitly asks for raw captures. Stored traffic is
 *     verbatim; a shareable derivative is not.
 *  2. **Nothing from the secret store, ever.** No CA private key, no DEK, no
 *     provider API key. This module is given exchanges, findings and audit
 *     rows, and has no route to any of them.
 *  3. **Exact host matching.** `HistoryRepo`'s host filter is a `LIKE '%host%'`
 *     substring match, which also matches `notexample.com.evil.net`. A bundle
 *     built on that would hand a triager another target's traffic, so the
 *     caller filters exactly and this module re-checks.
 *
 * Rule 3 binds every section, not only the ones that obviously carry traffic.
 * Two of them used to sit outside it: the engine briefing arrived pre-rendered
 * from the whole project, so a bundle for one host listed another's ranked
 * endpoints and the engagement folder named after the client; and the session
 * log tail went in by default with no host filter at all. The briefing is now
 * asked for by host, and logs are an opt-in the operator makes deliberately.
 */

import { createHash } from 'node:crypto';
import type { AuditEntry } from '../../shared/project.js';
import type { EngagementProfile } from '../../shared/engagement.js';
import type { ExchangeDetail, MessageDetail } from '../../shared/detail.js';
import type { ExchangeSummary } from '../../shared/query.js';
import type { Finding } from '../../shared/findings.js';
import type { HttpHeader } from '../../shared/model.js';
import type { ScopeConfig } from '../../shared/scope.js';
import type { TargetSite } from '../../shared/target.js';
import { SEVERITY_ORDER } from '../../shared/findings.js';
import type {
  AgentHandoff,
  AgentHandoffEvidenceEntry,
  EvidenceBundleOptions,
  EvidenceBundleSummary,
} from '../../shared/evidence.js';
import type { Redactor } from '../redaction/redactor.js';
import { tryDecompress } from '../redaction/redactor.js';
import { buildHandoff, renderHandoffMarkdown } from './handoff.js';
import { buildZip, listZip, type ZipEntry } from './zip.js';

/**
 * Bodies are capped per message so one large response cannot dominate a bundle.
 *
 * The cap binds on both paths. It used to apply only to the redacted one, so a
 * raw bundle carried whatever `session.ts` was willing to read for viewing —
 * 4 MiB per message — while the file it sat next to was capped at 256 KiB.
 */
const MAX_BODY_CHARS = 256 * 1024;
const DEFAULT_MAX_EXCHANGES = 500;

export interface BundleSource {
  appVersion: string;
  host: string;
  profile: EngagementProfile;
  scope: ScopeConfig;
  /** Sites from the target map for this host only. */
  sites: TargetSite[];
  /** Exchanges for this host, newest first, already capped by the caller. */
  exchanges: ExchangeSummary[];
  /** How many this host has in total, before the cap. */
  exchangesAvailable: number;
  detail: (id: string) => Promise<ExchangeDetail | undefined>;
  findings: Finding[];
  audit: AuditEntry[];
  /**
   * The engine's own recon, narrowed to `host`. It is asked for by host because
   * the unnarrowed briefing ranks every site in the project — a bundle is for
   * one target, and what the project knows about the others is not the
   * recipient's.
   */
  engineBriefing: (host: string) => Promise<string>;
  /** The session log tail. Written only when the operator opts in; see `includeLogs`. */
  logs: { jsonl: string; count: number; dropped: number } | null;
  redactor: Redactor;
  targetInScope: boolean;
  now: number;
}

export interface BuiltBundle {
  zip: Buffer;
  handoff: AgentHandoff;
  summary: Omit<EvidenceBundleSummary, 'path'>;
}

const sha256 = (b: Buffer): string => createHash('sha256').update(b).digest('hex');

/** A ZIP-safe, human-recognisable filename fragment. */
function slug(s: string, max = 48): string {
  const out = s
    .replace(/[^a-zA-Z0-9._-]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, max);
  return out || 'x';
}

function renderHeaders(headers: readonly HttpHeader[], redactor: Redactor, raw: boolean): string {
  const list = raw ? [...headers] : redactor.redactHeaders(headers);
  return list.map((h) => `${h.name}: ${h.value}`).join('\n');
}

const NEWLINE = Buffer.from('\n', 'utf8');
const NO_BYTES = Buffer.alloc(0);

interface RenderedBody {
  /** Exactly what to write. Bytes, not text — the raw path must not re-encode. */
  bytes: Uint8Array;
  /** What happened on the way here, for the `# content:` line. */
  note?: string;
}

/**
 * A captured body as something a reader can act on.
 *
 * `ExchangeDetail.bodyBase64` holds what the wire carried, which for nearly
 * every HTTPS response means gzip or br. Decoding those bytes as UTF-8 — which
 * is all this used to do — destroys them, so response bodies, the substance of
 * the evidence, arrived as mojibake. Worse, the file said `REDACTED` above
 * them: the redactor cannot mask a pattern in bytes it cannot read, so the
 * label was a claim about work that had not happened.
 *
 * Decompress first, with the same guarded helper the redactor and the passive
 * scanner already use. When that is impossible, say so — and on the redacted
 * path drop the body rather than ship bytes nothing has inspected.
 */
function renderBody(msg: MessageDetail, redactor: Redactor, raw: boolean): RenderedBody {
  if (!msg.bodyBase64) return { bytes: NO_BYTES };
  const stored = Buffer.from(msg.bodyBase64, 'base64');
  const encoding = msg.contentEncoding?.trim();
  let bytes: Uint8Array = stored;
  let note: string | undefined;

  if (encoding && encoding.toLowerCase() !== 'identity') {
    // A raw bundle promises the bytes the wire carried, and the header block
    // above it is emitted verbatim. Decompressing here would leave
    // `Content-Encoding: gzip` and a `Content-Length` sitting over bytes that
    // are neither — the reader can decompress it themselves, and only from the
    // original can they check it against the capture.
    const plain = raw ? null : tryDecompress(stored, encoding);
    if (raw) {
      note = `left ${encoding}-compressed, as captured`;
    } else if (plain) {
      bytes = plain;
      note = `decompressed from ${encoding}`;
    } else {
      return {
        bytes: Buffer.from(
          `[body omitted — Content-Encoding ${encoding} could not be decompressed, so it could ` +
            `not be redacted; ${msg.bodySize} byte(s) captured]`,
          'utf8',
        ),
        note: `${encoding} body omitted — unreadable here, therefore unredactable`,
      };
    }
  }

  const overCap = bytes.length > MAX_BODY_CHARS;
  const out = raw
    ? bytes.subarray(0, MAX_BODY_CHARS)
    : Buffer.from(redactor.redactBodyText(bytes, MAX_BODY_CHARS), 'utf8');
  const notes = [note, overCap ? `capped at ${MAX_BODY_CHARS} byte(s) for this bundle` : undefined]
    .filter((n): n is string => n !== undefined)
    .join(', ');
  return notes ? { bytes: out, note: notes } : { bytes: out };
}

/**
 * One exchange as something close to what went over the wire. Close, not exact:
 * redaction rewrites values, and a compressed body is written decompressed. The
 * header block says which, per body, so a reader never has to infer it.
 */
function renderExchange(d: ExchangeDetail, redactor: Redactor, raw: boolean): Buffer {
  const url = raw ? d.request.url : redactor.redactUrl(d.request.url);
  const requestBody = renderBody(d.request, redactor, raw);
  const responseBody = d.response ? renderBody(d.response, redactor, raw) : undefined;
  const bodyNotes = [
    requestBody.note ? `request body ${requestBody.note}` : undefined,
    responseBody?.note ? `response body ${responseBody.note}` : undefined,
  ].filter((n): n is string => n !== undefined);

  // Text lines and body bytes, kept apart: a line becomes UTF-8, a body is
  // written as it stands. Re-encoding a raw body through a string is the lossy
  // step this file is here to avoid.
  const chunks: (string | Uint8Array)[] = [
    `# TACNOC exchange ${d.id}`,
    `# captured: ${new Date(d.createdAt).toISOString()}`,
    `# source: ${d.source}${d.automated ? ' (automated)' : ''}  in-scope: ${d.inScope ? 'yes' : 'no'}`,
    `# url: ${url}`,
    `# content: ${raw ? 'RAW as captured' : 'REDACTED (credentials and secret patterns masked)'}` +
      (bodyNotes.length ? `; ${bodyNotes.join('; ')}` : ''),
  ];
  if (d.error) chunks.push(`# error: ${d.error}`);
  if (d.timing?.durationMs !== undefined) chunks.push(`# duration: ${d.timing.durationMs} ms`);
  if (d.tags.length) chunks.push(`# tags: ${d.tags.join(', ')}`);
  if (d.request.sensitive.fields.length) {
    chunks.push(`# request carries: ${d.request.sensitive.fields.join(', ')}`);
  }
  chunks.push('');
  chunks.push('===== REQUEST =====');
  // The request target is origin-form, so it carries the query string: a
  // capture of `/callback?code=...` puts the credential on the request line
  // itself. Redacting only the `# url:` comment above left it in the clear in a
  // bundle that says it is redacted. `redactUrl` is pure string work — it finds
  // `?` and masks sensitive parameter values — so it applies to a bare target.
  const target = raw ? d.request.target : redactor.redactUrl(d.request.target);
  chunks.push(`${d.request.method} ${target} ${d.request.httpVersion}`);
  chunks.push(renderHeaders(d.request.headers, redactor, raw));
  chunks.push('');
  if (requestBody.bytes.length) chunks.push(requestBody.bytes);
  if (d.request.bodyTruncated || d.request.truncatedForView) {
    chunks.push(`[body truncated — ${d.request.bodySize} byte(s) captured]`);
  }
  chunks.push('');
  chunks.push('===== RESPONSE =====');
  if (d.response && responseBody) {
    chunks.push(
      `${d.response.httpVersion} ${d.response.statusCode} ${d.response.statusMessage}`.trimEnd(),
    );
    chunks.push(renderHeaders(d.response.headers, redactor, raw));
    chunks.push('');
    if (responseBody.bytes.length) chunks.push(responseBody.bytes);
    if (d.response.bodyTruncated || d.response.truncatedForView) {
      chunks.push(`[body truncated — ${d.response.bodySize} byte(s) captured]`);
    }
  } else {
    chunks.push('(none recorded — the request was held, aborted, or errored)');
  }

  const parts: Uint8Array[] = [];
  for (const chunk of chunks) {
    parts.push(typeof chunk === 'string' ? Buffer.from(chunk, 'utf8') : chunk);
    parts.push(NEWLINE);
  }
  return Buffer.concat(parts);
}

function renderFindingsMarkdown(findings: Finding[], host: string): string {
  const L = [`# Findings — ${host}`, ''];
  if (!findings.length) {
    L.push('The passive scanner produced no findings for this host.');
    L.push('');
    L.push(
      'That is an absence of passive signal, not evidence of soundness. Nothing here has been ' +
        'actively tested.',
    );
    return L.join('\n') + '\n';
  }
  L.push(
    'Passive-scanner output. None of it has been actively verified — each entry is a hypothesis ' +
      'to prove or refute, not a confirmed defect.',
  );
  L.push('');
  for (const f of findings) {
    L.push(`## ${f.title}${f.suppressed ? ' (suppressed)' : ''}`);
    L.push('');
    L.push(`- Severity: **${f.severity}** | Confidence: ${f.confidence}`);
    L.push(`- Module: ${f.module} ${f.moduleVersion}`);
    L.push(`- Exchange: ${f.exchangeId}`);
    L.push(`- Detected: ${new Date(f.createdAt).toISOString()}`);
    if (f.note) L.push(`- Analyst note: ${f.note}`);
    L.push('');
    L.push(f.description);
    L.push('');
    if (f.evidence.length) {
      L.push('**Evidence** (excerpts are redacted at detection time):');
      L.push('');
      for (const e of f.evidence) {
        L.push(`- \`${e.location}\`${e.field ? ` (${e.field})` : ''}: \`${e.excerpt}\``);
      }
      L.push('');
    }
    L.push(`**Remediation.** ${f.remediation}`);
    L.push('');
  }
  return L.join('\n');
}

function renderReadme(
  host: string,
  redacted: boolean,
  counts: { exchanges: number; available: number; findings: number; logs: number },
): string {
  return (
    `# Evidence bundle — ${host}\n\n` +
    `Produced by TACNOC. Everything here was read out of one project; nothing was generated by ` +
    `a model.\n\n` +
    (redacted
      ? `**Redacted.** Credentials, cookies, tokens and secret-shaped strings are masked as ` +
        `\`[REDACTED]\` in headers, bodies and URLs. Ask the operator for a raw bundle if you ` +
        `need exact bytes.\n\n`
      : `> **RAW CAPTURES — treat this bundle as a secret.**\n>\n> Headers and bodies are exactly ` +
        `as captured, including live credentials, session cookies and any personal data in them. ` +
        `Store it accordingly and delete it when the engagement closes.\n\n`) +
    `## What is here\n\n` +
    `| Path | What it is |\n|---|---|\n` +
    `| \`HANDOFF.md\` | Start here. The state of play, and the rules that bind anyone continuing. |\n` +
    `| \`handoff.json\` | The same, for a program or an agent to parse. |\n` +
    `| \`FINDINGS.md\` / \`findings.json\` | ${counts.findings} passive finding(s), unverified. |\n` +
    `| \`exchanges/\` | ${counts.exchanges} captured exchange(s)` +
    `${counts.available > counts.exchanges ? ` of ${counts.available} available` : ''}, newest first. |\n` +
    `| \`engagement.json\` | Program, authorization reference, and the scope rules in force. |\n` +
    `| \`audit.json\` | Audited actions against this host. |\n` +
    (counts.logs
      ? `| \`logs/tacnoc.log.jsonl\` | ${counts.logs} log record(s), already redacted. |\n`
      : '') +
    `| \`manifest.json\` | SHA-256 of every file above. |\n\n` +
    `## Verifying\n\n` +
    `Every entry's SHA-256 is in \`manifest.json\`, and the bundle's own SHA-256 was reported when ` +
    `it was written. The hashes only mean something if you got them over a channel other than ` +
    `this file.\n\n` +
    `## What this is not\n\n` +
    `Not an authorization to test anything, and not a report. The findings are unverified ` +
    `scanner output; the exchanges are what a proxy saw. Read \`HANDOFF.md\` before acting on any ` +
    `of it.\n`
  );
}

export async function buildEvidenceBundle(
  src: BundleSource,
  options: EvidenceBundleOptions = {},
): Promise<BuiltBundle> {
  const raw = options.includeRawCaptures === true;
  // Opt-in, like raw captures. The tail is session-wide and has no reliable
  // host attribution — plenty of records carry no host at all, and others name
  // one only inside free text — so a "single target" bundle used to ship every
  // host the proxy had seen. Filtering it would be the same substring guesswork
  // rule 3 forbids, and would quietly present a partial log as a whole one.
  const includeLogs = options.includeLogs === true && src.logs !== null;
  const includeHandoff = options.includeHandoff !== false;
  const host = src.host.trim().toLowerCase();
  if (!host) throw new Error('An evidence bundle needs a target host.');

  // Rule 3: re-check exact host. The caller filters, but a substring match
  // slipping through here would put another target's traffic in the bundle.
  const mine = src.exchanges.filter((e) => e.host.toLowerCase() === host);
  const at = new Date(src.now);

  const entries: ZipEntry[] = [];
  const evidence: AgentHandoffEvidenceEntry[] = [];
  const exchangeFiles = new Map<string, string>();
  const add = (path: string, data: string | Buffer): void => {
    entries.push({ path, data, mtime: at });
  };

  // --- exchanges -----------------------------------------------------------
  let index = 0;
  for (const summary of mine) {
    const detail = await src.detail(summary.id);
    if (!detail) continue;
    index++;
    const name = `exchanges/${String(index).padStart(4, '0')}-${slug(
      `${summary.method}-${summary.path}`,
    )}.http`;
    add(name, renderExchange(detail, src.redactor, raw));
    exchangeFiles.set(summary.id, name);
  }
  if (index > 0) {
    evidence.push({
      file: 'exchanges/',
      kind: 'exchange',
      describes: `${index} captured exchange(s) for ${host}, newest first, as request/response text.`,
    });
  }

  // --- findings ------------------------------------------------------------
  const findings = [...src.findings].sort(
    (a, b) =>
      SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity] || a.title.localeCompare(b.title),
  );
  add('findings.json', JSON.stringify(findings, null, 2));
  add('FINDINGS.md', renderFindingsMarkdown(findings, host));
  evidence.push({
    file: 'FINDINGS.md',
    kind: 'findings',
    describes: `${findings.length} passive finding(s), unverified, highest severity first.`,
  });

  // --- engagement ----------------------------------------------------------
  // The profile carries no secret: program, platform, handle, authorization
  // reference and the user-agent policy. The scope rules are the important part
  // — they say what the gate permits.
  add(
    'engagement.json',
    JSON.stringify(
      {
        program: src.profile.program,
        platform: src.profile.platform,
        handle: src.profile.handle,
        authorizationRef: src.profile.authorizationRef,
        userAgent: src.profile.userAgent,
        scope: src.scope,
        targetInScope: src.targetInScope,
      },
      null,
      2,
    ),
  );
  evidence.push({
    file: 'engagement.json',
    kind: 'engagement',
    describes: 'Program, authorization reference, and the scope rules the engine enforces.',
  });

  // --- audit ---------------------------------------------------------------
  add('audit.json', JSON.stringify(src.audit, null, 2));
  evidence.push({
    file: 'audit.json',
    kind: 'audit',
    describes: `${src.audit.length} audited action(s) touching ${host}. Details are redacted at write time.`,
  });

  // --- logs ----------------------------------------------------------------
  if (includeLogs && src.logs) {
    add('logs/tacnoc.log.jsonl', src.logs.jsonl);
    evidence.push({
      file: 'logs/tacnoc.log.jsonl',
      kind: 'log',
      describes:
        `${src.logs.count} structured log record(s) from this session` +
        (src.logs.dropped ? `; ${src.logs.dropped} older record(s) already dropped` : '') +
        '. Redacted when written.',
    });
  }

  // --- handoff -------------------------------------------------------------
  const handoff = buildHandoff({
    host,
    appVersion: src.appVersion,
    profile: src.profile,
    scope: src.scope,
    sites: src.sites,
    exchanges: mine,
    findings,
    exchangeFiles,
    audit: src.audit,
    engineBriefing: await src.engineBriefing(host),
    evidence,
    redacted: !raw,
    targetInScope: src.targetInScope,
    now: src.now,
  });
  if (includeHandoff) {
    add('HANDOFF.md', renderHandoffMarkdown(handoff));
    add('handoff.json', JSON.stringify(handoff, null, 2));
  }

  add(
    'README.md',
    renderReadme(host, !raw, {
      exchanges: index,
      available: src.exchangesAvailable,
      findings: findings.length,
      logs: includeLogs && src.logs ? src.logs.count : 0,
    }),
  );

  // --- manifest ------------------------------------------------------------
  // Written last so it can hash everything else. It cannot hash itself; the
  // bundle's own SHA-256 is reported to the operator for that.
  const manifest = {
    schemaVersion: 1,
    tool: { name: 'TACNOC', version: src.appVersion },
    generatedAt: src.now,
    host,
    redacted: !raw,
    exchangeCount: index,
    exchangesAvailable: src.exchangesAvailable,
    findingCount: findings.length,
    auditCount: src.audit.length,
    logCount: includeLogs && src.logs ? src.logs.count : 0,
    files: entries
      .map((e) => ({
        path: e.path,
        bytes: (typeof e.data === 'string' ? Buffer.from(e.data, 'utf8') : e.data).length,
        sha256: sha256(typeof e.data === 'string' ? Buffer.from(e.data, 'utf8') : e.data),
      }))
      .sort((a, b) => a.path.localeCompare(b.path)),
  };
  add('manifest.json', JSON.stringify(manifest, null, 2));

  const zip = buildZip(entries, { mtime: at });

  // Read it back before anyone is told it worked. `listZip` re-inflates every
  // entry and checks its CRC, so a bundle that cannot be opened fails here
  // rather than on a triager's desk.
  const verified = listZip(zip);
  if (verified.length !== entries.length) {
    throw new Error(
      `bundle verification failed: wrote ${entries.length} entries, read back ${verified.length}`,
    );
  }

  return {
    zip,
    handoff,
    summary: {
      host,
      generatedAt: src.now,
      sizeBytes: zip.length,
      sha256: sha256(zip),
      exchangeCount: index,
      exchangesAvailable: src.exchangesAvailable,
      findingCount: findings.length,
      auditCount: src.audit.length,
      logCount: includeLogs && src.logs ? src.logs.count : 0,
      redacted: !raw,
      entries: entries.map((e) => e.path).sort(),
    },
  };
}

export { DEFAULT_MAX_EXCHANGES };
