/**
 * Preflight — "is this engagement actually ready to test?", answered once, from
 * evidence, before anything is planned.
 *
 * The failure this exists to prevent is the quiet one. A CA that expired three
 * weeks ago, a browser that was never told to trust it, a proxy bound to
 * 0.0.0.0, an empty scope, a User-Agent the program requires but nothing sends —
 * each of these produces the same symptom, which is a session that looks like it
 * is working and finds nothing. Hours disappear into it.
 *
 * So every check here is grounded in something observable (a certificate's
 * validity window, the count of decrypted HTTPS exchanges actually captured, the
 * User-Agent on requests already sent), never in configuration alone. Checks are
 * graded: a `blocker` means testing would be invalid or unauthorized and the
 * mesh must stop and report; a `warning` means proceed with a known gap.
 *
 * Pure: it takes a snapshot and returns a report, so it is trivially testable
 * and cannot itself fail the way the things it inspects can.
 */

import type {
  CaStatus,
  EngagementProfile,
  IdentityCompliance,
  PreflightCheck,
  PreflightReport,
  WorkspaceSummary,
} from '../../shared/engagement.js';
import type { ScopeConfig } from '../../shared/scope.js';

export interface PreflightInputs {
  project?: {
    name: string;
    directory: string;
    authorizationRef?: string;
    encryptedAtRest: boolean;
  };
  profile: EngagementProfile;
  scope: ScopeConfig;
  ca: CaStatus;
  identity: IdentityCompliance;
  proxy: { running: boolean; host?: string; port?: number; loopbackOnly: boolean };
  workspace: WorkspaceSummary;
  history: { exchanges: number; findings: number };
  /** Hosts the engagement documents describe as in scope, if any were found. */
  proposedScopeHosts?: string[];
  now?: number;
}

export function buildPreflight(inputs: PreflightInputs): PreflightReport {
  const now = inputs.now ?? Date.now();
  const checks: PreflightCheck[] = [];
  const include = inputs.scope.include.filter((r) => r.enabled !== false);
  const hosts = [...new Set(include.map((r) => r.host))].sort();
  const failClosed = include.length === 0;

  // --- authorization ---------------------------------------------------------
  const authorizationRef =
    inputs.profile.authorizationRef?.trim() || inputs.project?.authorizationRef?.trim() || '';
  if (!inputs.project) {
    checks.push({
      id: 'project',
      title: 'No project is open',
      severity: 'blocker',
      detail: 'There is nothing to test against and nowhere to record evidence.',
      remedy: 'Create or open a project first.',
    });
  } else if (!authorizationRef) {
    checks.push({
      id: 'authorization',
      title: 'No authorization reference recorded',
      severity: 'blocker',
      detail:
        'Nothing on file states what authorizes this testing. Findings produced without a recorded authorization cannot be defended after the fact.',
      remedy:
        'Record the program URL, engagement ticket, or scope document in the engagement profile.',
    });
  } else {
    checks.push({
      id: 'authorization',
      title: 'Authorization recorded',
      severity: 'ok',
      detail: authorizationRef,
    });
  }

  // --- scope -----------------------------------------------------------------
  if (failClosed) {
    // If the engagement folder already lists the assets, say so — telling
    // someone their scope is empty while their own program policy sits unread
    // two directories away is not help.
    const proposed = inputs.proposedScopeHosts ?? [];
    checks.push({
      id: 'scope',
      title: 'Scope is empty (fail-closed)',
      severity: 'blocker',
      detail: proposed.length
        ? `No include rule exists, so every automated request would be refused. Your engagement documents name ${proposed.length} host(s) as in scope: ${proposed.slice(0, 8).join(', ')}${proposed.length > 8 ? `, +${proposed.length - 8} more` : ''}.`
        : 'No include rule exists, so the engine would refuse every automated request. Nothing is in scope by default, deliberately.',
      remedy: proposed.length
        ? 'Open Engagement → Proposed scope, check each host against the program page, and add the ones you are authorized to test.'
        : 'Add the program’s in-scope hosts to project scope.',
    });
  } else {
    checks.push({
      id: 'scope',
      title: `${include.length} in-scope rule(s) across ${hosts.length} host(s)`,
      severity: 'ok',
      detail:
        hosts.slice(0, 10).join(', ') + (hosts.length > 10 ? `, +${hosts.length - 10} more` : ''),
    });
  }

  // --- certificate authority -------------------------------------------------
  const cert = inputs.ca.certificate;
  if (!inputs.ca.interceptionEnabled) {
    checks.push({
      id: 'ca-revoked',
      title: 'TLS interception is off — the project CA is revoked',
      severity: 'warning',
      detail:
        'HTTPS CONNECT tunnels pass through unread, so no encrypted traffic is captured. This is a valid state to test in, but it is not the state to hunt in.',
      remedy: 'Issue a new CA when you are ready to capture HTTPS again.',
    });
  } else if (cert?.expired) {
    checks.push({
      id: 'ca-expired',
      title: 'The project CA has expired',
      severity: 'blocker',
      detail: `Valid until ${new Date(cert.notAfter).toISOString()}. Clients will reject every intercepted connection, so HTTPS capture silently produces nothing.`,
      remedy: 'Issue a new CA and install it in the test browser.',
    });
  } else if (cert?.expiringSoon) {
    checks.push({
      id: 'ca-expiring',
      title: `The project CA expires in ${cert.daysRemaining} day(s)`,
      severity: 'warning',
      detail: `Valid until ${new Date(cert.notAfter).toISOString()}.`,
      remedy: 'Rotate the CA before it lapses mid-engagement.',
    });
  } else if (cert) {
    checks.push({
      id: 'ca',
      title: 'Project CA is valid',
      severity: 'ok',
      detail: `${cert.subject} · SHA-256 ${cert.fingerprint.slice(0, 23)}… · ${cert.daysRemaining} day(s) remaining`,
    });
  }

  if (!inputs.ca.secureBackend && inputs.ca.interceptionEnabled) {
    checks.push({
      id: 'ca-key-storage',
      title: 'CA private key is not in OS secure storage',
      severity: 'warning',
      detail: `The key is held by the "${inputs.ca.backendName}" backend. Anyone who reads it can impersonate any site to a browser that trusts this CA.`,
      remedy: 'Run the desktop app so the key is sealed with OS secure storage.',
    });
  }

  // Configuration says interception is on; captured traffic says whether it is.
  if (inputs.ca.interceptionEnabled && inputs.history.exchanges > 0) {
    if (inputs.ca.observedHttpsExchanges === 0) {
      checks.push({
        id: 'ca-trust',
        title: 'No decrypted HTTPS traffic has ever been captured',
        severity: 'warning',
        detail: `${inputs.history.exchanges} exchange(s) captured, none of them HTTPS. The usual cause is that the test browser does not trust this CA, so it refuses the intercepted connection.`,
        remedy: 'Save the CA certificate and install it into the browser or profile you test with.',
      });
    } else {
      checks.push({
        id: 'ca-trust',
        title: 'TLS interception is working',
        severity: 'ok',
        detail: `${inputs.ca.observedHttpsExchanges} decrypted HTTPS exchange(s) captured.`,
      });
    }
  }

  // --- engagement identity (User-Agent) --------------------------------------
  const identity = inputs.identity;
  if (!identity.applicable) {
    checks.push({
      id: 'user-agent',
      title: 'No User-Agent requirement configured',
      severity: 'warning',
      detail:
        'Many programs require researcher traffic to be identifiable. If this one does, set it before generating traffic; if it does not, this is fine.',
      remedy: 'Check the program policy and set the required User-Agent in the engagement profile.',
    });
  } else if (!identity.enforced) {
    checks.push({
      id: 'user-agent',
      title: 'A User-Agent is configured but not enforced',
      severity: 'warning',
      detail: `Requests are not rewritten, so generated traffic may not carry "${identity.required}".`,
      remedy: 'Turn on identity enforcement so every generated request carries it.',
    });
  } else if (identity.sampled > 0 && identity.compliant < identity.sampled) {
    checks.push({
      id: 'user-agent',
      title: 'Some already-sent traffic does not carry the required identity',
      severity: 'warning',
      detail: `${identity.compliant}/${identity.sampled} recent generated requests were compliant. Observed User-Agents: ${identity.observedUserAgents.slice(0, 3).join(' | ') || 'none'}.`,
      remedy:
        'Traffic sent before enforcement was enabled stays as it was; new requests will comply.',
    });
  } else {
    checks.push({
      id: 'user-agent',
      title: 'Engagement identity is enforced',
      severity: 'ok',
      detail: `Every generated request carries "${identity.required}"${
        identity.missingHeaders.length ? '' : ' and all identity headers'
      }.`,
    });
  }

  // --- proxy -----------------------------------------------------------------
  if (!inputs.proxy.loopbackOnly) {
    checks.push({
      id: 'proxy-bind',
      title: 'The proxy is bound to a non-loopback address',
      severity: 'blocker',
      detail: `Listening on ${inputs.proxy.host}:${inputs.proxy.port}. Anyone who can reach that address can proxy through this engagement — and be captured by it.`,
      remedy: 'Bind the proxy to 127.0.0.1 unless you have a specific, controlled reason not to.',
    });
  }
  if (!inputs.proxy.running) {
    checks.push({
      id: 'proxy',
      title: 'The proxy is not running',
      severity: 'warning',
      detail: 'New traffic cannot be captured. Already-captured history is still available.',
      remedy: 'Start the proxy and route the test browser through it.',
    });
  }

  // --- material to work from -------------------------------------------------
  if (inputs.workspace.error) {
    checks.push({
      id: 'workspace',
      title: 'The engagement folder could not be read',
      severity: 'warning',
      detail: inputs.workspace.error,
      remedy: 'Point the workspace at the folder holding the program policy and engagement notes.',
    });
  } else if (inputs.workspace.fileCount === 0) {
    checks.push({
      id: 'workspace',
      title: 'The engagement folder has no readable documents',
      severity: 'warning',
      detail:
        'There is no program policy, scope document, or notes file to read, so planning rests on captured traffic alone.',
      remedy: 'Drop the program policy and target notes into the engagement folder as text.',
    });
  } else {
    checks.push({
      id: 'workspace',
      title: `${inputs.workspace.fileCount} document(s) in the engagement folder`,
      severity: 'ok',
      detail: inputs.workspace.notableFiles.slice(0, 8).join(', ') || inputs.workspace.root,
    });
  }

  if (inputs.history.exchanges === 0) {
    checks.push({
      id: 'history',
      title: 'No traffic has been captured yet',
      severity: 'warning',
      detail:
        'Planning from an empty history means guessing at endpoints. Browse the target through the proxy first.',
      remedy: 'Route the test browser through the proxy and exercise the application.',
    });
  }

  return {
    generatedAt: now,
    ...(inputs.project ? { project: inputs.project } : {}),
    scope: {
      includeRules: include.length,
      excludeRules: inputs.scope.exclude.filter((r) => r.enabled !== false).length,
      hosts,
      failClosed,
    },
    ca: inputs.ca,
    identity,
    proxy: inputs.proxy,
    workspace: inputs.workspace,
    history: inputs.history,
    checks,
    ready: !checks.some((c) => c.severity === 'blocker'),
  };
}
