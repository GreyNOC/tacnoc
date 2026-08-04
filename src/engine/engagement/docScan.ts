/**
 * What is in this folder, and which of it matters to the hunt.
 *
 * Operators do not start with an empty TACNOC project. They start with a folder
 * that already holds the work: the program policy, an ENGAGEMENT.md, last
 * quarter's report, `recon/` full of subdomain dumps and endpoint lists, a
 * scratch `_notes.md`. Pointing the tool at that folder and having it say
 * "342 documents" is not useful — 300 of those are recon line-noise and six of
 * them decide what may legitimately be touched.
 *
 * This module reads a folder and says which files are which. It is deliberately
 * deterministic and content-based: no model is involved in deciding what the
 * scope document is, because that decision feeds the safety gate and has to be
 * reproducible and auditable. The model gets to READ the ranking; it does not
 * get to produce it.
 *
 * Classification is a bounded thing on purpose. A file's NAME is a weak signal
 * (plenty of engagements keep scope in `README.md`), its CONTENT is the strong
 * one, and neither is trusted beyond ranking — nothing here authorizes anything.
 * Scope still comes from `scopeProposal`, and the operator still ticks it.
 */

/** What a document is for, as far as a hunt is concerned. */
export type DocKind =
  /** States what may and may not be tested. The most important class here. */
  | 'scope'
  /** Program rules, engagement brief, rules of engagement, authorization. */
  | 'engagement'
  /** A previous finding or report — tells you what is already known. */
  | 'report'
  /** Enumeration output: subdomains, endpoints, ports, tech fingerprints. */
  | 'recon'
  /** The operator's own working notes. */
  | 'notes'
  /** Read, but nothing said it was relevant. */
  | 'other';

export interface ScannedDoc {
  /** Workspace-relative path. */
  path: string;
  kind: DocKind;
  /** Higher is more relevant to planning a hunt. */
  score: number;
  /** Why it was classified this way — shown to the operator verbatim. */
  reasons: string[];
  bytes: number;
  /** True when only the filename was judged (content was not read). */
  nameOnly: boolean;
}

export interface DocScanResult {
  root: string;
  /** Files present and readable. */
  filesSeen: number;
  /** Files whose content was actually read. */
  filesRead: number;
  /** Ranked, most relevant first. */
  docs: ScannedDoc[];
  byKind: Record<DocKind, number>;
  notes: string[];
}

const KIND_ORDER: DocKind[] = ['scope', 'engagement', 'report', 'recon', 'notes', 'other'];

/**
 * Filename signals. Weak by design — they order what to READ, and content then
 * decides. A folder that keeps its scope in `README.md` must still be handled,
 * so nothing here is allowed to be conclusive on its own.
 */
const NAME_RULES: { re: RegExp; kind: DocKind; score: number; why: string }[] = [
  { re: /(^|[/_-])scope\b/i, kind: 'scope', score: 40, why: 'named for scope' },
  {
    re: /in[_-]?scope|out[_-]?of[_-]?scope|targets?\b/i,
    kind: 'scope',
    score: 35,
    why: 'names in/out of scope',
  },
  {
    re: /(^|[/_-])(engagement|campaign|roe|rules[_-]?of[_-]?engagement)\b/i,
    kind: 'engagement',
    score: 38,
    why: 'engagement brief',
  },
  {
    re: /(^|[/_-])(program|policy|authoriz|contract|sow|permission)/i,
    kind: 'engagement',
    score: 34,
    why: 'program rules or authorization',
  },
  {
    re: /(^|[/_-])(report|finding|submission|advisory|writeup|poc)/i,
    kind: 'report',
    score: 30,
    why: 'prior report or finding',
  },
  {
    re: /(^|[/_-])(recon|surface|subdomain|endpoint|host|nmap|amass|httpx|nuclei|wayback|crawl|dns|port)/i,
    kind: 'recon',
    score: 22,
    why: 'enumeration output',
  },
  {
    re: /(^|[/_-])(notes?|todo|scratch|journal|log)\b/i,
    kind: 'notes',
    score: 18,
    why: 'working notes',
  },
  {
    re: /(^|[/_-])readme\b/i,
    kind: 'engagement',
    score: 20,
    why: 'README — often carries the brief',
  },
];

/**
 * Content signals. These carry the weight, because the phrase "out of scope" in
 * a file is a far better indicator than whatever the file happens to be called.
 */
/**
 * A statement of what is or is not in scope settles the classification outright.
 *
 * Without this, a policy that ALSO carries the rules of engagement scored higher
 * as 'engagement' than as 'scope' — and the operator hunting for "where is my
 * scope written down" would not find it under the heading they were looking at.
 * Scope is the class whose misfiling costs the most, so it wins the tie.
 */
const DECISIVE: DocKind = 'scope';

const CONTENT_RULES: {
  re: RegExp;
  kind: DocKind;
  score: number;
  why: string;
  decisive?: boolean;
}[] = [
  {
    re: /\bout[- ]of[- ]scope\b/i,
    kind: 'scope',
    score: 60,
    why: 'states what is OUT of scope',
    decisive: true,
  },
  {
    re: /\bin[- ]scope\b/i,
    kind: 'scope',
    score: 55,
    why: 'states what is in scope',
    decisive: true,
  },
  {
    re: /\b(eligible|qualifying|excluded|ineligible)\s+(assets?|domains?|targets?|vulnerabilit)/i,
    kind: 'scope',
    score: 45,
    why: 'lists eligible or excluded assets',
    decisive: true,
  },
  {
    re: /\brules?\s+of\s+engagement\b/i,
    kind: 'engagement',
    score: 50,
    why: 'rules of engagement',
  },
  {
    re: /\b(bug\s?bounty|responsible\s+disclosure|vulnerability\s+disclosure|safe\s+harbou?r)\b/i,
    kind: 'engagement',
    score: 40,
    why: 'bounty program terms',
  },
  {
    re: /\b(authoriz(ed|ation)|permission\s+to\s+test|signed\s+(sow|scope))\b/i,
    kind: 'engagement',
    score: 38,
    why: 'authorization language',
  },
  {
    re: /\b(do\s+not\s+test|prohibited|forbidden|must\s+not)\b/i,
    kind: 'engagement',
    score: 36,
    why: 'prohibitions the gate must respect',
  },
  {
    re: /\b(user[- ]agent|rate\s?limit|requests?\s+per\s+second)\b/i,
    kind: 'engagement',
    score: 24,
    why: 'identification or rate requirements',
  },
  {
    re: /\b(severity|cvss|impact|reproduc|steps?\s+to\s+reproduce)\b/i,
    kind: 'report',
    score: 30,
    why: 'report structure',
  },
  {
    re: /\b(triage[ds]?|duplicate|accepted|resolved|bounty\s+awarded)\b/i,
    kind: 'report',
    score: 26,
    why: 'submission outcome',
  },
  {
    re: /^\s*(GET|POST|PUT|PATCH|DELETE)\s+\//im,
    kind: 'recon',
    score: 22,
    why: 'raw HTTP requests',
  },
  {
    re: /\b(subdomain|wildcard\s+dns|open\s+port|http[sx]?\s+probe)\b/i,
    kind: 'recon',
    score: 20,
    why: 'enumeration vocabulary',
  },
];

/** Extensions worth reading. Anything else is listed but not opened. */
const READABLE_EXT = /\.(md|markdown|txt|json|ya?ml|csv|tsv|log|html?|rst|adoc)$/i;

/** A hostname-ish token, used only to notice that a file is dense with hosts. */
const HOST_TOKEN = /(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}/gi;

/**
 * Rank by filename alone, to decide READ ORDER.
 *
 * Reading is bounded, so the order matters: a 6-file scope set must not be
 * crowded out by 300 files of `amass` output that happened to sort first.
 */
export function nameRank(path: string): { kind: DocKind; score: number; reasons: string[] } {
  const reasons: string[] = [];
  // Score PER KIND and take the best, rather than summing every match. Summing
  // across kinds rewarded a path for merely matching several categories, so
  // `recon/old/2024/ENGAGEMENT.md` outranked a top-level `ENGAGEMENT.md` by
  // collecting the engagement points AND the recon points.
  const perKind = new Map<DocKind, number>();
  for (const rule of NAME_RULES) {
    if (!rule.re.test(path)) continue;
    reasons.push(rule.why);
    perKind.set(rule.kind, (perKind.get(rule.kind) ?? 0) + rule.score);
  }
  let best: DocKind = 'other';
  let bestScore = 0;
  for (const [kind, score] of perKind) {
    if (score > bestScore) {
      bestScore = score;
      best = kind;
    }
  }
  // Depth counts against a file: the brief sits at the top of a hunt folder far
  // more often than six levels down inside tool output.
  const depth = path.split('/').length - 1;
  return { kind: best, score: Math.max(0, bestScore - depth * 4), reasons };
}

/** Classify one document, using its content when it was read. */
export function classifyDocument(
  path: string,
  content: string | undefined,
  bytes: number,
): ScannedDoc {
  const byName = nameRank(path);
  const reasons = [...byName.reasons];
  const scores = new Map<DocKind, number>();
  const bump = (kind: DocKind, n: number): void => {
    scores.set(kind, (scores.get(kind) ?? 0) + n);
  };
  if (byName.score > 0) bump(byName.kind, byName.score);

  let decided = false;
  if (content !== undefined) {
    for (const rule of CONTENT_RULES) {
      if (!rule.re.test(content)) continue;
      reasons.push(rule.why);
      bump(rule.kind, rule.score);
      if (rule.decisive) decided = true;
    }
    // A file that is mostly hostnames is an asset list, whatever it is called.
    // Judged by DENSITY, not count: a 400-line policy naturally mentions plenty
    // of hosts without being a target dump.
    const hosts = content.match(HOST_TOKEN)?.length ?? 0;
    const lines = content.split('\n').length;
    if (hosts >= 15 && hosts / Math.max(lines, 1) > 0.5) {
      reasons.push(`${hosts} hostnames across ${lines} lines — an asset list`);
      bump('recon', 28);
    }
  }

  let kind: DocKind = 'other';
  let score = 0;
  for (const k of KIND_ORDER) {
    const s = scores.get(k) ?? 0;
    // KIND_ORDER is the tie-break, so a file that reads as both scope and recon
    // lands on scope — the class whose misfiling costs the most.
    if (s > score) {
      score = s;
      kind = k;
    }
  }
  // A file that states its scope IS the scope document, whatever else it holds.
  if (decided) {
    kind = DECISIVE;
    score = Math.max(score, scores.get(DECISIVE) ?? 0);
  }
  return {
    path,
    kind,
    score,
    reasons: reasons.length ? [...new Set(reasons)] : ['no hunting-relevant signal'],
    bytes,
    nameOnly: content === undefined,
  };
}

/** True when this file is worth opening rather than just listing. */
export function isReadableDoc(path: string): boolean {
  return READABLE_EXT.test(path);
}

/**
 * Assemble the ranked scan.
 *
 * `read` is what was actually opened; `listed` is everything else that was
 * present, classified on filename alone so the count is honest about coverage.
 */
export function buildDocScan(
  root: string,
  read: { path: string; content: string; bytes: number }[],
  listed: { path: string; bytes: number }[],
  notes: string[] = [],
): DocScanResult {
  const docs = [
    ...read.map((f) => classifyDocument(f.path, f.content, f.bytes)),
    ...listed.map((f) => classifyDocument(f.path, undefined, f.bytes)),
  ].sort(
    (a, b) =>
      b.score - a.score ||
      KIND_ORDER.indexOf(a.kind) - KIND_ORDER.indexOf(b.kind) ||
      a.path.localeCompare(b.path),
  );

  const byKind = Object.fromEntries(KIND_ORDER.map((k) => [k, 0])) as Record<DocKind, number>;
  for (const d of docs) byKind[d.kind] += 1;

  return { root, filesSeen: docs.length, filesRead: read.length, docs, byKind, notes };
}
