/**
 * Read the engagement folder and propose scope.
 *
 * The fail-closed scope gate is correct — nothing should be testable until the
 * operator says so — but "scope is empty, go add hosts" is an unhelpful thing to
 * say to someone whose program policy, sitting in the engagement folder two
 * inches away, lists every in-scope asset. Retyping that list by hand is both
 * tedious and a place to make a mistake in the direction that matters.
 *
 * So this extracts candidates and shows the evidence for each. It is
 * deliberately a PROPOSAL and nothing else:
 *
 *  - **It never writes scope.** `setScope` stays an operator action. Scope is
 *    the one boundary that decides whether a request is authorized, and a
 *    document is not authorization — it is a claim about authorization. The
 *    operator confirms against the program page.
 *  - **Every candidate carries its source** (file, line, and the line itself),
 *    so confirming is reading one line rather than trusting a parser.
 *  - **Exclusions are surfaced too**, and never proposed as includes. A policy
 *    that says "*.corp.example.com is OUT of scope" must not become an include
 *    because a regex found a domain on that line.
 *  - **When it cannot tell**, it says so instead of guessing.
 *
 * Deterministic and offline: pure string handling over already-read documents,
 * no model involved, so it produces the same answer every time.
 */

/** Where a candidate came from, so the operator can check it in one glance. */
export interface ScopeEvidence {
  file: string;
  line: number;
  text: string;
}

export interface ScopeCandidate {
  /** Host or wildcard pattern exactly as it should be entered, lowercased. */
  host: string;
  /** True when the pattern contains a `*` label. */
  wildcard: boolean;
  /** What the surrounding document says this is. */
  disposition: 'include' | 'exclude' | 'unclear';
  /** Every place this host was seen, most relevant first. */
  evidence: ScopeEvidence[];
  /** Why it was classified this way, in one line. */
  reason: string;
}

export interface ScopeProposal {
  include: ScopeCandidate[];
  exclude: ScopeCandidate[];
  unclear: ScopeCandidate[];
  filesRead: number;
  notes: string[];
}

export interface ProposalSource {
  path: string;
  content: string;
}

/**
 * Section headings that flip the reading of everything under them. Ordered
 * longest-first so "not in scope" wins over "in scope" on the same line.
 */
const EXCLUDE_MARKERS = [
  'not in scope',
  'out-of-scope',
  'out of scope',
  'outofscope',
  'excluded',
  'exclusions',
  'exclude',
  'do not test',
  'don’t test',
  "don't test",
  'off-limits',
  'off limits',
  'forbidden',
  'prohibited',
];

const INCLUDE_MARKERS = [
  'in scope',
  'in-scope',
  'inscope',
  'scope',
  'targets',
  'target',
  'assets',
  'domains',
  'hosts',
  'eligible',
];

/**
 * Hosts that appear in engagement paperwork but are never the target: the
 * bounty platform itself, and the documentation/code-hosting domains policies
 * routinely link to. Proposing these would be actively dangerous.
 */
const NEVER_PROPOSE = new Set([
  'hackerone.com',
  'bugcrowd.com',
  'intigriti.com',
  'yeswehack.com',
  'synack.com',
  'openbugbounty.org',
  'github.com',
  'gitlab.com',
  'google.com',
  'example.com',
  'example.org',
  'example.net',
  'localhost',
  'schema.org',
  'w3.org',
  'mozilla.org',
  'owasp.org',
]);

/** File extensions that make a "domain-looking" token actually a filename. */
const FILE_EXTENSIONS = new Set([
  'md',
  'txt',
  'json',
  'yml',
  'yaml',
  'html',
  'htm',
  'js',
  'ts',
  'py',
  'sh',
  'png',
  'jpg',
  'jpeg',
  'gif',
  'svg',
  'pdf',
  'csv',
  'log',
  'zip',
  'tar',
  'gz',
  'exe',
  'dll',
  'so',
  'php',
  'asp',
  'aspx',
  'jsp',
  'xml',
  'toml',
  'ini',
  'conf',
  'lock',
  'map',
]);

/**
 * A domain or wildcard domain. Deliberately conservative: at least two labels,
 * an alphabetic TLD of 2+ characters, and an optional leading `*.`.
 *
 * The lookbehind does two jobs. A leading `` would not match before `*`, so
 * `*.dev.example.test` silently lost its wildcard and proposed the bare host
 * instead — a narrower rule than the policy grants, which is the safe
 * direction but still wrong. It also skips the domain half of an email
 * address, so a `security@` contact line does not become a target.
 */
const HOST_RE =
  /(?<![A-Za-z0-9.@-])(\*\.)?((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24})\b/gi;

/** Strip a URL down to its host, and drop obvious non-host noise. */
function normalizeHost(raw: string): string | undefined {
  const host = raw
    .trim()
    .toLowerCase()
    .replace(/[.,;:)\]}"'>]+$/, '');
  if (!host) return undefined;
  const wildcard = host.startsWith('*.');
  const bare = wildcard ? host.slice(2) : host;
  const labels = bare.split('.');
  if (labels.length < 2) return undefined;
  const tld = labels[labels.length - 1] ?? '';
  if (FILE_EXTENSIONS.has(tld)) return undefined;
  if (!/^[a-z]{2,24}$/.test(tld)) return undefined;
  if (NEVER_PROPOSE.has(bare)) return undefined;
  // A version string like 1.2.3 never reaches here (numeric TLD), but a token
  // with no letters at all in the second-level label is still noise.
  if (!/[a-z]/.test(labels[labels.length - 2] ?? '')) return undefined;
  return host;
}

/** Does this line (or heading) put what follows out of scope? */
function markerDisposition(text: string): 'include' | 'exclude' | undefined {
  const lower = text.toLowerCase();
  if (EXCLUDE_MARKERS.some((m) => lower.includes(m))) return 'exclude';
  if (INCLUDE_MARKERS.some((m) => lower.includes(m))) return 'include';
  return undefined;
}

const isHeading = (line: string): boolean =>
  /^\s{0,3}#{1,6}\s/.test(line) || /^\s*[-*]?\s*\*\*[^*]+\*\*\s*:?\s*$/.test(line);

/**
 * Extract scope candidates from engagement documents.
 *
 * Classification is per line first (a line that says "out of scope" governs the
 * hosts on it), then by the nearest preceding heading. A host seen in both an
 * include and an exclude context resolves to **exclude** — the safe direction.
 */
export function proposeScope(sources: ProposalSource[]): ScopeProposal {
  const byHost = new Map<string, ScopeCandidate>();
  let filesRead = 0;

  for (const source of sources) {
    filesRead += 1;
    const lines = source.content.split(/\r?\n/);
    let sectionDisposition: 'include' | 'exclude' | undefined;

    for (let i = 0; i < lines.length; i += 1) {
      const line = lines[i] ?? '';
      if (isHeading(line)) {
        sectionDisposition = markerDisposition(line) ?? sectionDisposition;
      }
      const lineDisposition = markerDisposition(line);

      HOST_RE.lastIndex = 0;
      let match: RegExpExecArray | null;
      while ((match = HOST_RE.exec(line)) !== null) {
        const host = normalizeHost(match[0]);
        if (!host) continue;

        // A line saying "out of scope" beats the section it sits in; otherwise
        // inherit the section; otherwise we genuinely do not know.
        const disposition = lineDisposition ?? sectionDisposition ?? 'unclear';
        const reason =
          lineDisposition === 'exclude'
            ? 'the line naming it says it is out of scope'
            : lineDisposition === 'include'
              ? 'the line naming it says it is in scope'
              : sectionDisposition === 'exclude'
                ? 'it appears under an out-of-scope heading'
                : sectionDisposition === 'include'
                  ? 'it appears under an in-scope heading'
                  : 'it appears in the engagement documents with no scope wording nearby';

        const existing = byHost.get(host);
        const evidence: ScopeEvidence = {
          file: source.path,
          line: i + 1,
          text: line.trim().slice(0, 240),
        };
        if (!existing) {
          byHost.set(host, {
            host,
            wildcard: host.startsWith('*.'),
            disposition,
            evidence: [evidence],
            reason,
          });
          continue;
        }
        if (existing.evidence.length < 5) existing.evidence.push(evidence);
        // Resolve conflicts toward exclusion, and let a definite reading beat
        // an unclear one.
        if (disposition === 'exclude' && existing.disposition !== 'exclude') {
          existing.disposition = 'exclude';
          existing.reason = `${reason} (it is also mentioned elsewhere — excluded wins)`;
        } else if (existing.disposition === 'unclear' && disposition === 'include') {
          existing.disposition = 'include';
          existing.reason = reason;
        }
      }
    }
  }

  const all = [...byHost.values()].sort((a, b) => a.host.localeCompare(b.host));
  const include = all.filter((c) => c.disposition === 'include');
  const exclude = all.filter((c) => c.disposition === 'exclude');
  const unclear = all.filter((c) => c.disposition === 'unclear');

  const notes: string[] = [
    'These are PROPOSALS read out of your engagement documents, not authorization. Check each one against the program page before adding it — a document can be out of date, and scope is the boundary that decides whether a request is legitimate.',
  ];
  if (!filesRead) {
    notes.push(
      'No readable documents were found in the engagement folder, so there was nothing to read scope from.',
    );
  } else if (!all.length) {
    notes.push(
      'No host-shaped text was found in the engagement documents. If the policy is a PDF, export it to .txt or .md so it can be read.',
    );
  }
  if (exclude.length) {
    notes.push(
      `${exclude.length} host(s) are described as OUT of scope; they are listed separately and are never proposed as includes.`,
    );
  }
  if (unclear.length) {
    notes.push(
      `${unclear.length} host(s) appear in the documents with no scope wording nearby — decide on those yourself.`,
    );
  }

  return { include, exclude, unclear, filesRead, notes };
}

// ---- turning proposals into scope rules -------------------------------------

/**
 * Build the scope rules for a set of ticked candidates.
 *
 * This lives in the engine, not the view, for one reason: it decides what the
 * safety gate will and will not permit, so it has to be testable against the
 * real evaluator rather than eyeballed inside a React component.
 *
 * The wildcard translation is the part that matters. A policy writes
 * `*.example.com` to mean "subdomains of example.com", and TACNOC's glob gives
 * `*` the meaning "exactly one label" — so a literal `*.example.com` rule would
 * match `api.example.com` and silently REFUSE `api.eu.example.com`, leaving the
 * operator believing a host is in scope that the gate rejects. It is translated
 * to `**.example.com` (one or more labels) instead.
 *
 * It deliberately does NOT widen to the apex. `subdomain` matching would also
 * put `example.com` itself in scope, and a policy that lists only `*.example.com`
 * has not authorized the apex. Erring toward refusing a request costs a moment;
 * erring toward permitting one is an unauthorized request.
 */
export function scopeRulesFromProposal(
  proposal: ScopeProposal,
  selectedHosts: Iterable<string>,
  existing: { include: { host: string }[]; exclude: { host: string }[] },
  makeId: () => string = () =>
    `ws-${Math.random().toString(36).slice(2, 10)}${Date.now().toString(36)}`,
): { include: ScopeRuleDraft[]; exclude: ScopeRuleDraft[] } {
  const picked = new Set([...selectedHosts].map((h) => h.trim().toLowerCase()));
  const haveInclude = new Set(existing.include.map((r) => r.host.trim().toLowerCase()));
  const haveExclude = new Set(existing.exclude.map((r) => r.host.trim().toLowerCase()));

  const toRule = (candidate: ScopeCandidate): ScopeRuleDraft => {
    const wildcard = candidate.host.startsWith('*.');
    const host = wildcard ? `**.${candidate.host.slice(2)}` : candidate.host;
    return {
      id: makeId(),
      enabled: true,
      hostMatch: wildcard ? 'wildcard' : 'exact',
      host,
      schemes: [],
      ports: [],
      label: `from ${candidate.evidence[0]?.file ?? 'engagement folder'}`,
    };
  };

  // Only hosts the operator ticked become includes. Excluded candidates are
  // added regardless of the ticks — an exclusion the operator declines to add
  // is an exclusion that silently stops applying.
  const include = [...proposal.include, ...proposal.unclear]
    .filter((c) => picked.has(c.host.toLowerCase()) && !haveInclude.has(c.host.toLowerCase()))
    .map(toRule);
  const exclude = proposal.exclude
    .filter((c) => !haveExclude.has(c.host.toLowerCase()))
    .map(toRule);

  return { include, exclude };
}

/** The shape `ScopeRule` requires, without importing the renderer's types here. */
export interface ScopeRuleDraft {
  id: string;
  enabled: boolean;
  hostMatch: 'exact' | 'subdomain' | 'wildcard';
  host: string;
  schemes: never[];
  ports: never[];
  label: string;
}
