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
 */

import { createHash } from 'node:crypto';
import type { AuditEntry } from '../../shared/project.js';
import type { EngagementProfile } from '../../shared/engagement.js';
import type { ExchangeDetail } from '../../shared/detail.js';
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
import { buildHandoff, renderHandoffMarkdown } from './handoff.js';
import { buildZip, listZip, type ZipEntry } from './zip.js';

/** Bodies are capped per message so one large response cannot dominate a bundle. */
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
  engineBriefing: () => Promise<string>;
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

function renderBody(base64: string, redactor: Redactor, raw: boolean): string {
  if (!base64) return '';
  const bytes = Buffer.from(base64, 'base64');
  if (raw) return bytes.toString('utf8');
  return redactor.redactBodyText(bytes, MAX_BODY_CHARS);
}

/**
 * One exchange as something close to what went over the wire. Close, not exact:
 * redaction rewrites values, and the body is decoded text rather than the
 * original compressed bytes. The header block says which.
 */
function renderExchange(d: ExchangeDetail, redactor: Redactor, raw: boolean): string {
  const url = raw ? d.request.url : redactor.redactUrl(d.request.url);
  const L: string[] = [
    `# TACNOC exchange ${d.id}`,
    `# captured: ${new Date(d.createdAt).toISOString()}`,
    `# source: ${d.source}${d.automated ? ' (automated)' : ''}  in-scope: ${d.inScope ? 'yes' : 'no'}`,
    `# url: ${url}`,
    `# content: ${raw ? 'RAW as captured' : 'REDACTED (credentials and secret patterns masked)'}`,
  ];
  if (d.error) L.push(`# error: ${d.error}`);
  if (d.timing?.durationMs !== undefined) L.push(`# duration: ${d.timing.durationMs} ms`);
  if (d.tags.length) L.push(`# tags: ${d.tags.join(', ')}`);
  if (d.request.sensitive.fields.length) {
    L.push(`# request carries: ${d.request.sensitive.fields.join(', ')}`);
  }
  L.push('');
  L.push('===== REQUEST =====');
  L.push(`${d.request.method} ${d.request.target} ${d.request.httpVersion}`);
  L.push(renderHeaders(d.request.headers, redactor, raw));
  L.push('');
  const reqBody = renderBody(d.request.bodyBase64, redactor, raw);
  if (reqBody) L.push(reqBody);
  if (d.request.bodyTruncated || d.request.truncatedForView) {
    L.push(`[body truncated — ${d.request.bodySize} byte(s) captured]`);
  }
  L.push('');
  if (d.response) {
    L.push('===== RESPONSE =====');
    L.push(
      `${d.response.httpVersion} ${d.response.statusCode} ${d.response.statusMessage}`.trimEnd(),
    );
    L.push(renderHeaders(d.response.headers, redactor, raw));
    L.push('');
    const resBody = renderBody(d.response.bodyBase64, redactor, raw);
    if (resBody) L.push(resBody);
    if (d.response.bodyTruncated || d.response.truncatedForView) {
      L.push(`[body truncated — ${d.response.bodySize} byte(s) captured]`);
    }
  } else {
    L.push('===== RESPONSE =====');
    L.push('(none recorded — the request was held, aborted, or errored)');
  }
  L.push('');
  return L.join('\n');
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
  const includeLogs = options.includeLogs !== false && src.logs !== null;
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
    engineBriefing: await src.engineBriefing(),
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
