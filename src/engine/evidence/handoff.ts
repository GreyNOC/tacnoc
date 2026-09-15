/**
 * The agent handoff: what one target's evidence means, written so the next
 * worker on it — a person, this app's own mesh, or somebody else's model — can
 * start from what is known instead of from zero.
 *
 * Everything here is assembled from the project by pure functions. No model
 * writes any of it, which is the property that matters: a handoff cannot claim
 * a finding the scanner did not produce, an endpoint that was never captured,
 * or an authorization that is not in the engagement profile. It is a view of
 * the project, not a summary of one.
 *
 * It is also not a permission slip. The scope block exists so an agent can see
 * what the gate will allow and stop early when the answer is "nothing"; it is
 * reported, never granted. `src/engine/scope/scope.ts` remains the only thing
 * that decides whether a request leaves.
 */

import type { AuditEntry } from '../../shared/project.js';
import type { EngagementProfile } from '../../shared/engagement.js';
import type { ExchangeSummary } from '../../shared/query.js';
import type { Finding } from '../../shared/findings.js';
import type { ScopeConfig } from '../../shared/scope.js';
import type { TargetSite } from '../../shared/target.js';
import { SEVERITY_ORDER } from '../../shared/findings.js';
import type {
  AgentHandoff,
  AgentHandoffEndpoint,
  AgentHandoffEvidenceEntry,
  AgentHandoffFinding,
} from '../../shared/evidence.js';

export interface HandoffInput {
  host: string;
  appVersion: string;
  profile: EngagementProfile;
  scope: ScopeConfig;
  /** Sites from the target map whose host matches, already filtered. */
  sites: TargetSite[];
  /** Exchanges included in the bundle, newest first. */
  exchanges: ExchangeSummary[];
  findings: Finding[];
  /** Exchange id → bundle-relative file, for findings that point at one. */
  exchangeFiles: ReadonlyMap<string, string>;
  /** Audit entries already filtered to this host. */
  audit: AuditEntry[];
  /** `session.engineBriefing()` — deterministic, produced with no model. */
  engineBriefing: string;
  evidence: AgentHandoffEvidenceEntry[];
  redacted: boolean;
  targetInScope: boolean;
  now: number;
}

const rule = (r: { hostMatch: string; host: string }): string => `${r.hostMatch}: ${r.host}`;
const enabled = <T extends { enabled?: boolean }>(rules: T[]): T[] =>
  rules.filter((r) => r.enabled !== false);

/**
 * Rules of engagement. Fixed text, because these do not vary by target and an
 * agent that negotiates its own constraints does not have any. They restate
 * what the engine enforces plus what it cannot — an engine can refuse an
 * out-of-scope host, it cannot refuse an over-broad interpretation of a finding.
 */
function constraints(failClosed: boolean, targetInScope: boolean): string[] {
  const out = [
    'Scope is enforced by the engine and fails closed. Requests to anything not matched by an ' +
      'enabled include rule are refused before they leave. Do not attempt to route around that, ' +
      'and do not treat this document as widening it.',
    'Prefer read-only verification. Demonstrate a defect with the least impactful request that ' +
      'demonstrates it; no destructive testing, no persistence, no lateral movement.',
    'No fabrication. Every claim must be reproducible from evidence in this bundle. If something ' +
      'cannot be reproduced it is not a finding — say so rather than inferring severity or impact.',
    'Minimal proof. Extract the smallest amount of data that establishes the issue. Do not ' +
      'enumerate or exfiltrate records to make a point that one record already makes.',
    'Respect the request budget. Volume against a live target is itself harm — availability ' +
      'impact and denial-of-wallet both count. Stop and report rather than brute-forcing.',
    'Coordinated disclosure only. Findings go to the program, not anywhere else.',
  ];
  if (failClosed) {
    out.unshift(
      'STOP CONDITION: this project has no enabled include rule, so the gate would refuse every ' +
        'request. Do not test anything. Report that scope is unset and wait for the operator.',
    );
  } else if (!targetInScope) {
    out.unshift(
      `STOP CONDITION: this target is NOT currently in scope — the gate will refuse requests to ` +
        `it. The evidence here was captured while it was in scope, or through the proxy, which ` +
        `does not imply authorization now. Do not test it; report the discrepancy.`,
    );
  }
  return out;
}

/**
 * Questions the evidence raises and does not answer. Derived from what was
 * actually captured — never speculative, because a speculative "open question"
 * is just a prompt to go looking for something that was never observed.
 */
function openQuestions(input: HandoffInput, endpoints: AgentHandoffEndpoint[]): string[] {
  const out: string[] = [];
  const { exchanges, findings } = input;

  const decrypted = exchanges.filter((e) => e.scheme === 'https' && e.source === 'proxy');
  if (exchanges.some((e) => e.scheme === 'https') && decrypted.length === 0) {
    out.push(
      'No HTTPS exchange for this host was captured through the proxy, so nothing here shows ' +
        'decrypted TLS traffic. Whatever HTTPS is listed came from the engine’s own requests. ' +
        'If browser traffic was expected, the CA is probably not trusted — see the Certificate view.',
    );
  }

  const authish = endpoints.filter((e) =>
    e.parameterNames.some((p) => /token|auth|session|key|sig|user|id$/i.test(p)),
  );
  if (authish.length) {
    out.push(
      `${authish.length} endpoint(s) take parameters that look identity- or ` +
        `authorization-bearing (${[...new Set(authish.flatMap((e) => e.parameterNames))]
          .slice(0, 8)
          .join(', ')}). Whether any of them is authorization-relevant is untested.`,
    );
  }

  const serverErrors = endpoints.filter((e) => e.statusCodes.some((s) => s >= 500));
  if (serverErrors.length) {
    out.push(
      `${serverErrors.length} endpoint(s) returned 5xx at least once. Unhandled server errors are ` +
        'worth reproducing deliberately — the captured cases may be incidental.',
    );
  }

  const denied = endpoints.filter((e) => e.statusCodes.some((s) => s === 401 || s === 403));
  const allowed = endpoints.filter((e) => e.statusCodes.some((s) => s >= 200 && s < 300));
  if (denied.length && allowed.length) {
    out.push(
      `Both authorized (2xx) and refused (401/403) responses were seen on this host. The boundary ` +
        'between them is where an access-control defect would show, and it has not been mapped.',
    );
  }

  const noResponse = exchanges.filter((e) => !e.hasResponse);
  if (noResponse.length) {
    out.push(
      `${noResponse.length} captured request(s) have no response recorded (held, aborted, or ` +
        'errored). They are included for completeness and prove nothing on their own.',
    );
  }

  if (findings.length === 0 && exchanges.length > 0) {
    out.push(
      'The passive scanner produced no findings for this host. That is an absence of passive ' +
        'signal, not evidence of soundness — nothing here has been actively tested.',
    );
  }

  const suppressed = findings.filter((f) => f.suppressed);
  if (suppressed.length) {
    out.push(
      `${suppressed.length} finding(s) are suppressed and are included but marked. They were ` +
        'judged false positives by the operator; re-check rather than assuming either way.',
    );
  }
  return out;
}

/**
 * What has already been done to this host, read from the audit log so an agent
 * does not repeat work or re-report something already proven. Audit details are
 * redacted at write time by `AuditRepo`, so these are safe to carry.
 */
function alreadyTried(audit: AuditEntry[]): string[] {
  const counts = new Map<string, number>();
  for (const e of audit) counts.set(e.action, (counts.get(e.action) ?? 0) + 1);
  return [...counts.entries()].sort((a, b) => b[1] - a[1]).map(([action, n]) => `${action} ×${n}`);
}

export function buildHandoff(input: HandoffInput): AgentHandoff {
  const inc = enabled(input.scope.include);
  const exc = enabled(input.scope.exclude);
  const failClosed = inc.length === 0;

  const endpoints: AgentHandoffEndpoint[] = input.sites
    .flatMap((s) => s.endpoints)
    .sort((a, b) => b.requestCount - a.requestCount)
    .map((e) => ({
      path: e.path,
      methods: e.methods,
      statusCodes: e.statusCodes,
      parameterNames: e.parameterNames,
      requestCount: e.requestCount,
      latestExchangeId: e.latestExchangeId,
      inScope: e.inScope,
    }));

  const findings: AgentHandoffFinding[] = [...input.findings]
    .sort(
      (a, b) =>
        SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity] || a.title.localeCompare(b.title),
    )
    .map((f) => {
      const file = input.exchangeFiles.get(f.exchangeId);
      return {
        id: f.id,
        title: f.title,
        severity: f.severity,
        confidence: f.confidence,
        module: f.module,
        exchangeId: f.exchangeId,
        suppressed: f.suppressed,
        ...(file ? { evidenceFile: file } : {}),
      };
    });

  const times = input.exchanges.map((e) => e.createdAt).filter((t) => Number.isFinite(t));
  const top = findings.filter((f) => !f.suppressed).slice(0, 3);

  const suggestedObjective = failClosed
    ? `Do not test. Report that ${input.host} has no enabled scope rule.`
    : top.length
      ? `Verify or refute the passive findings on ${input.host}, hardest first: ` +
        `${top.map((f) => f.title).join('; ')}. Use the captured exchanges in this bundle as the ` +
        `control, and prove each one with a differential rather than asserting it.`
      : `Map the authorization boundary on ${input.host} from the captured endpoints in this ` +
        `bundle, starting with the ones taking identity-bearing parameters. Establish a control ` +
        `before testing anything, and prove differentially.`;

  return {
    schemaVersion: 1,
    generatedAt: input.now,
    tool: { name: 'TACNOC', version: input.appVersion },
    redacted: input.redacted,
    authorization: {
      ...(input.profile.program ? { program: input.profile.program } : {}),
      ...(input.profile.platform ? { platform: input.profile.platform } : {}),
      ...(input.profile.handle ? { handle: input.profile.handle } : {}),
      ...(input.profile.authorizationRef
        ? { authorizationRef: input.profile.authorizationRef }
        : {}),
      inScope: inc.map(rule),
      outOfScope: exc.map(rule),
      failClosed,
      targetInScope: input.targetInScope,
    },
    target: {
      host: input.host,
      origins: input.sites.map((s) => s.id),
      endpoints,
      exchangeCount: input.exchanges.length,
      ...(times.length ? { firstSeen: Math.min(...times), lastSeen: Math.max(...times) } : {}),
    },
    findings,
    evidence: input.evidence,
    engineBriefing: input.engineBriefing,
    alreadyTried: alreadyTried(input.audit),
    openQuestions: openQuestions(input, endpoints),
    constraints: constraints(failClosed, input.targetInScope),
    suggestedObjective,
  };
}

const iso = (ms?: number): string => (ms === undefined ? 'unknown' : new Date(ms).toISOString());

/** The same facts as `handoff.json`, for a reader rather than a parser. */
export function renderHandoffMarkdown(h: AgentHandoff): string {
  const L: string[] = [];
  L.push(`# Handoff — ${h.target.host}`);
  L.push('');
  L.push(
    `Produced by ${h.tool.name} ${h.tool.version} at ${iso(h.generatedAt)} from the open project. ` +
      'Every fact below is read out of the project; nothing here was written by a model, and ' +
      'nothing here grants permission to do anything.',
  );
  L.push('');
  if (!h.redacted) {
    L.push(
      '> **This bundle contains RAW captures.** Headers and bodies are as they were seen, ' +
        'including any credentials, cookies and personal data in them. Treat it as a secret.',
    );
    L.push('');
  }

  L.push('## Read this first — rules of engagement');
  L.push('');
  for (const c of h.constraints) L.push(`- ${c}`);
  L.push('');

  L.push('## Authorization');
  L.push('');
  const a = h.authorization;
  L.push(`- Program: ${a.program || '(not recorded)'}`);
  L.push(`- Platform: ${a.platform || '(not recorded)'}`);
  L.push(`- Researcher handle: ${a.handle || '(not recorded)'}`);
  L.push(`- Authorization reference: ${a.authorizationRef || '(not recorded)'}`);
  L.push(`- This target in scope right now: **${a.targetInScope ? 'yes' : 'NO'}**`);
  L.push('');
  L.push('In-scope rules (the gate allows only these):');
  L.push(...(a.inScope.length ? a.inScope.map((r) => `- ${r}`) : ['- (none — fail-closed)']));
  if (a.outOfScope.length) {
    L.push('');
    L.push('Excluded (these veto):');
    L.push(...a.outOfScope.map((r) => `- ${r}`));
  }
  L.push('');

  L.push('## Target');
  L.push('');
  L.push(
    `${h.target.exchangeCount} exchange(s) in this bundle across ${h.target.origins.length} ` +
      `origin(s): ${h.target.origins.join(', ') || '(none)'}. ` +
      `First seen ${iso(h.target.firstSeen)}, last ${iso(h.target.lastSeen)}.`,
  );
  L.push('');
  if (h.target.endpoints.length) {
    L.push('| Endpoint | Methods | Statuses | Parameters | Requests | In scope |');
    L.push('|---|---|---|---|---|---|');
    for (const e of h.target.endpoints.slice(0, 60)) {
      L.push(
        `| \`${e.path}\` | ${e.methods.join(', ')} | ${e.statusCodes.join(', ') || '—'} | ` +
          `${e.parameterNames.slice(0, 6).join(', ') || '—'} | ${e.requestCount} | ` +
          `${e.inScope ? 'yes' : 'no'} |`,
      );
    }
    if (h.target.endpoints.length > 60) {
      L.push('');
      L.push(`_(${h.target.endpoints.length - 60} further endpoint(s) in \`handoff.json\`.)_`);
    }
  } else {
    L.push('_No endpoints were derived for this host._');
  }
  L.push('');

  L.push('## Findings so far');
  L.push('');
  if (h.findings.length) {
    L.push('| Severity | Confidence | Title | Module | Evidence |');
    L.push('|---|---|---|---|---|');
    for (const f of h.findings) {
      L.push(
        `| ${f.severity}${f.suppressed ? ' _(suppressed)_' : ''} | ${f.confidence} | ${f.title} | ` +
          `${f.module} | ${f.evidenceFile ? `\`${f.evidenceFile}\`` : f.exchangeId} |`,
      );
    }
    L.push('');
    L.push(
      '_These are passive-scanner output. None has been actively verified; treat every one as a ' +
        'hypothesis to prove or refute._',
    );
  } else {
    L.push('_None. The passive scanner produced nothing for this host._');
  }
  L.push('');

  L.push('## What the evidence does not answer');
  L.push('');
  L.push(
    ...(h.openQuestions.length ? h.openQuestions.map((q) => `- ${q}`) : ['- (nothing noted)']),
  );
  L.push('');

  L.push('## Already done');
  L.push('');
  L.push(
    ...(h.alreadyTried.length
      ? h.alreadyTried.map((t) => `- ${t}`)
      : ['- (no audited action against this host)']),
  );
  L.push('');

  L.push('## Evidence in this bundle');
  L.push('');
  L.push('| File | Kind | Contents |');
  L.push('|---|---|---|');
  for (const e of h.evidence) L.push(`| \`${e.file}\` | ${e.kind} | ${e.describes} |`);
  L.push('');

  L.push('## Suggested starting objective');
  L.push('');
  L.push(h.suggestedObjective);
  L.push('');

  L.push('## Engine briefing (verbatim)');
  L.push('');
  L.push('```');
  L.push(h.engineBriefing);
  L.push('```');
  L.push('');
  return L.join('\n');
}
