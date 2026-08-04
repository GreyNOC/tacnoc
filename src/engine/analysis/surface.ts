/**
 * Deterministic attack-surface ranking over captured traffic.
 *
 * This is the veteran baseline: the judgement an experienced hunter applies in
 * the first ten minutes of looking at a target map, written as code so it is
 * always available, costs nothing, and produces the same answer twice. A
 * parameter called `returnUrl` on a login page, `tpl` on a renderer, `file` on
 * a download endpoint, a numeric `id` on an object route — each of those says
 * something specific about which defect class the endpoint most likely hides,
 * and a scanner that treats every parameter identically throws that away.
 *
 * The approach is borrowed from GreyIQ's BugHunter hunt brain, and so is the
 * discipline around it: **this only REORDERS work.** It cannot introduce a
 * host, an endpoint, a payload, or a finding. Everything it surfaces still has
 * to pass the scope gate to be touched and still needs a real observed-versus-
 * control differential to become a confirmed finding. At worst a bad ranking
 * spends a little attention in the wrong place.
 *
 * Pure and offline: it reads the already-captured target map and returns an
 * ordered list of leads. It sends nothing.
 */

import type { TargetMap } from '../../shared/target.js';

/** Defect classes this ranker can point at. Names match how hunters talk. */
export type SurfaceClass =
  | 'access-control'
  | 'ssrf'
  | 'path-traversal'
  | 'injection'
  | 'template-injection'
  | 'command-injection'
  | 'open-redirect'
  | 'reflection'
  | 'auth'
  | 'state-change';

/**
 * Parameter-name vocabulary per class. These are the names that, in practice,
 * sit in front of the corresponding sink often enough to be worth looking at
 * first. Matching is on tokenized names (camelCase split), never on values.
 */
const SIGNALS: Record<SurfaceClass, ReadonlySet<string>> = {
  'access-control': new Set([
    'id',
    'uid',
    'userid',
    'user',
    'account',
    'accountid',
    'order',
    'orderid',
    'invoice',
    'document',
    'doc',
    'file',
    'record',
    'item',
    'itemid',
    'product',
    'productid',
    'customer',
    'tenant',
    'org',
    'organization',
    'workspace',
    'team',
    'project',
    'group',
    'member',
    'key',
    'uuid',
    'guid',
    'ref',
  ]),
  ssrf: new Set([
    'url',
    'uri',
    'link',
    'src',
    'source',
    'target',
    'endpoint',
    'host',
    'hostname',
    'domain',
    'server',
    'proxy',
    'fetch',
    'load',
    'import',
    'webhook',
    'callback',
    'feed',
    'image',
    'imageurl',
    'avatar',
    'remote',
    'upstream',
  ]),
  'path-traversal': new Set([
    'file',
    'filename',
    'filepath',
    'path',
    'download',
    'export',
    'attachment',
    'document',
    'doc',
    'include',
    'folder',
    'directory',
    'archive',
    'backup',
    'log',
    'read',
    'name',
  ]),
  injection: new Set([
    'id',
    'search',
    'query',
    'q',
    'filter',
    'sort',
    'order',
    'orderby',
    'where',
    'report',
    'lookup',
    'list',
    'category',
    'page',
    'limit',
    'offset',
    'column',
    'table',
    'selector',
    'criteria',
  ]),
  'template-injection': new Set([
    'template',
    'tpl',
    'render',
    'renderer',
    'preview',
    'theme',
    'view',
    'layout',
    'invoice',
    'email',
    'mail',
    'format',
    'generate',
    'subject',
    'body',
  ]),
  'command-injection': new Set([
    'cmd',
    'command',
    'exec',
    'execute',
    'shell',
    'ping',
    'host',
    'hostname',
    'ip',
    'convert',
    'converter',
    'resize',
    'compile',
    'diagnostic',
    'traceroute',
    'lookup',
    'dns',
  ]),
  'open-redirect': new Set([
    'redirect',
    'redirecturi',
    'redirecturl',
    'return',
    'returnurl',
    'returnto',
    'next',
    'continue',
    'destination',
    'dest',
    'callback',
    'callbackurl',
    'goto',
    'forward',
    'relaystate',
    'target',
    'url',
    'back',
  ]),
  reflection: new Set([
    'q',
    'query',
    'search',
    'term',
    'keyword',
    'message',
    'comment',
    'feedback',
    'name',
    'title',
    'description',
    'content',
    'html',
    'text',
    'error',
    'notice',
    'msg',
    'note',
  ]),
  auth: new Set([
    'auth',
    'login',
    'logout',
    'signin',
    'signout',
    'oauth',
    'oidc',
    'sso',
    'callback',
    'token',
    'session',
    'password',
    'passwd',
    'reset',
    'invite',
    'register',
    'verify',
    'otp',
    'mfa',
    '2fa',
    'code',
  ]),
  'state-change': new Set([
    'create',
    'update',
    'delete',
    'remove',
    'change',
    'transfer',
    'checkout',
    'purchase',
    'admin',
    'settings',
    'profile',
    'invite',
    'upload',
    'approve',
    'grant',
    'role',
    'permission',
  ]),
};

/** Why an endpoint scored: which class, and the evidence for it. */
export interface SurfaceLead {
  site: string;
  path: string;
  methods: string[];
  /** Exchange to start from — the most recent capture of this endpoint. */
  exchangeId: string;
  inScope: boolean;
  requestCount: number;
  /** Highest-scoring classes first. */
  classes: { kind: SurfaceClass; score: number; because: string[] }[];
  score: number;
}

export interface SurfaceRanking {
  generatedAt: number;
  /** Leads that are in scope, best first. */
  leads: SurfaceLead[];
  /** Endpoints skipped because they are out of scope. Reported, never ranked. */
  outOfScopeSkipped: number;
  notes: string[];
}

/**
 * Split a path or parameter name into lowercase word tokens, handling camelCase.
 *
 * Only names are tokenized, never values — but do not mistake that for "not
 * user-controlled". Parameter names come from captured traffic, and the target
 * chooses the links and XHR URLs the operator's browser follows, so a target CAN
 * steer this ranking by emitting a decoy `?imageUrl=` on an endpoint of its
 * choosing. The cost is misspent attention: the scope gate still bounds what may
 * be touched, and the proof gate still decides what is real.
 */
export function signalWords(value: string): Set<string> {
  const spaced = String(value ?? '').replace(/([a-z0-9])([A-Z])/g, '$1 $2');
  const words = spaced.match(/[A-Za-z0-9]+/g) ?? [];
  return new Set(words.map((w) => w.toLowerCase()).filter(Boolean));
}

/** True when a path segment looks like an object identifier a caller could change. */
function objectIdSegments(path: string): string[] {
  const hits: string[] = [];
  for (const segment of path.split('/')) {
    if (!segment) continue;
    if (/^\d+$/.test(segment)) hits.push(segment);
    else if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(segment)) {
      hits.push(segment);
    } else if (/^[0-9a-f]{24,}$/i.test(segment)) hits.push(segment);
  }
  return hits;
}

const MUTATING_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

/**
 * Rank the in-scope endpoints of a captured target map by which defect class
 * each most likely hides. Out-of-scope endpoints are counted and dropped — this
 * never surfaces something the engine would refuse to touch.
 */
export function rankAttackSurface(map: TargetMap, limit = 25): SurfaceRanking {
  const leads: SurfaceLead[] = [];
  let outOfScopeSkipped = 0;

  for (const site of map.sites) {
    const origin = `${site.scheme}://${site.host}:${site.port}`;
    for (const endpoint of site.endpoints) {
      if (!endpoint.inScope) {
        outOfScopeSkipped += 1;
        continue;
      }
      const pathWords = signalWords(endpoint.path);
      const params = endpoint.parameterNames ?? [];
      const scores = new Map<SurfaceClass, { score: number; because: string[] }>();

      const bump = (kind: SurfaceClass, amount: number, why: string): void => {
        const entry = scores.get(kind) ?? { score: 0, because: [] };
        entry.score += amount;
        if (!entry.because.includes(why)) entry.because.push(why);
        scores.set(kind, entry);
      };

      for (const [kind, vocabulary] of Object.entries(SIGNALS) as [
        SurfaceClass,
        ReadonlySet<string>,
      ][]) {
        for (const param of params) {
          for (const word of signalWords(param)) {
            // A parameter name is stronger evidence than a path word: it is the
            // thing you would actually vary.
            if (vocabulary.has(word)) bump(kind, 3, `parameter "${param}"`);
          }
        }
        for (const word of pathWords) {
          if (vocabulary.has(word)) bump(kind, 1, `path segment "${word}"`);
        }
      }

      // An identifier sitting in the path is the classic object-level
      // authorization lead, and it does not show up as a query parameter.
      const ids = objectIdSegments(endpoint.path);
      if (ids.length) {
        bump('access-control', 4, `identifier "${ids[0]}" in the path`);
      }

      // A state-changing method raises the stakes of any authorization gap and
      // is where business-logic defects live.
      const mutating = endpoint.methods.filter((m) => MUTATING_METHODS.has(m.toUpperCase()));
      if (mutating.length) {
        bump('state-change', 2, `${mutating.join('/')} on this endpoint`);
        if (scores.has('access-control')) {
          bump('access-control', 2, 'state-changing method with an identifier');
        }
      }

      if (scores.size === 0) continue;
      const classes = [...scores.entries()]
        .map(([kind, v]) => ({ kind, score: v.score, because: v.because.slice(0, 4) }))
        .sort((a, b) => b.score - a.score);
      leads.push({
        site: origin,
        path: endpoint.path,
        methods: endpoint.methods,
        exchangeId: endpoint.latestExchangeId,
        inScope: true,
        requestCount: endpoint.requestCount,
        classes,
        score: classes.reduce((sum, c) => sum + c.score, 0),
      });
    }
  }

  leads.sort((a, b) => b.score - a.score || b.requestCount - a.requestCount);

  const notes: string[] = [
    'Ranking only reorders where to look. It cannot add a host, an endpoint, or a finding, and every lead still needs an observed-versus-control differential before it is real.',
  ];
  if (map.truncated) {
    notes.push(
      'The target map was truncated to the most recent exchanges, so older endpoints may be missing.',
    );
  }
  if (!leads.length) {
    notes.push(
      'No in-scope endpoint scored. Either nothing is in scope yet, or the captured traffic carries no parameters worth ranking — browse the target through the proxy first.',
    );
  }

  return {
    generatedAt: map.generatedAt,
    leads: leads.slice(0, Math.max(1, Math.min(limit, 100))),
    outOfScopeSkipped,
    notes,
  };
}
