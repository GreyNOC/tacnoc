/**
 * Regressions for the v0.5.3 QA/QC pass.
 *
 * Each test pins one defect found by auditing the app against what its own UI
 * and documentation claim. Several of them were green-suite defects: the code
 * did something reasonable-looking that contradicted the promise made about it,
 * and no existing test asserted the promise.
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import * as os from 'node:os';
import * as path from 'node:path';
import { promises as fs } from 'node:fs';
import * as crypto from 'node:crypto';

import { Interceptor } from '../../src/engine/proxy/interceptor.js';
import { ProjectStore } from '../../src/engine/project/projectStore.js';
import { TacnocSession } from '../../src/engine/session.js';
import { InMemorySecretStore } from '../../src/engine/ca/secretStore.js';
import {
  caInstallGuide,
  caInstallInstructions,
  CERT_PATH_TOKEN,
} from '../../src/engine/ca/installInstructions.js';
import type { Finding } from '../../src/shared/findings.js';
import type { HttpExchange, MessageSource } from '../../src/shared/model.js';
import type { InterceptedRequestView } from '../../src/shared/intercept.js';

let dir: string;

beforeAll(() => {
  dir = path.join(os.tmpdir(), `tacnoc-qaqc53-${crypto.randomBytes(6).toString('hex')}`);
});

afterAll(async () => {
  await fs.rm(dir, { recursive: true, force: true });
});

function exchange(
  source: MessageSource,
  scheme: 'http' | 'https',
  id: string = crypto.randomUUID(),
) {
  const ex: HttpExchange = {
    id,
    createdAt: Date.now(),
    source,
    scheme,
    host: 'app.example.test',
    port: scheme === 'https' ? 443 : 80,
    inScope: true,
    automated: source !== 'proxy',
    request: {
      method: 'GET',
      target: '/',
      url: `${scheme}://app.example.test/`,
      httpVersion: 'HTTP/1.1',
      headers: [{ name: 'Host', value: 'app.example.test' }],
      body: { size: 0, truncated: false },
    },
    response: {
      statusCode: 200,
      statusMessage: 'OK',
      httpVersion: 'HTTP/1.1',
      headers: [{ name: 'Content-Type', value: 'application/json' }],
      body: { size: 0, truncated: false },
    },
    tags: [],
  };
  return ex;
}

const requestView = (id: string): InterceptedRequestView =>
  ({
    id,
    exchangeId: id,
    scheme: 'https',
    host: 'app.example.test',
    port: 443,
    method: 'GET',
    url: 'https://app.example.test/delete-everything',
    headers: [],
    bodyBase64: '',
    inScope: true,
  }) as unknown as InterceptedRequestView;

// ---- emergency stop must not deliver the queue to the target ----
describe('emergency stop releases held traffic as DROP', () => {
  it('drops held requests instead of forwarding them', async () => {
    const interceptor = new Interceptor();
    interceptor.setState({ interceptRequests: true });
    const held = interceptor.holdRequest(requestView('r1'));
    interceptor.releaseAll('drop');
    // A `forward` decision here is what sends the request to the origin: the
    // proxy opens upstream on anything that is not a drop.
    expect((await held).action).toBe('drop');
  });

  it('defaults to drop, so a caller that forgets to choose fails safe', async () => {
    const interceptor = new Interceptor();
    interceptor.setState({ interceptRequests: true, interceptResponses: true });
    const req = interceptor.holdRequest(requestView('r2'));
    interceptor.releaseAll();
    expect((await req).action).toBe('drop');
  });

  it('still FORWARDS when interception is simply switched off', async () => {
    // The opposite intent: "stop holding my traffic" must not break the page.
    const interceptor = new Interceptor();
    interceptor.setState({ interceptRequests: true });
    const held = interceptor.holdRequest(requestView('r3'));
    interceptor.setState({ interceptRequests: false });
    expect((await held).action).toBe('forward');
  });

  it('a session emergency stop drops the queue', async () => {
    const session = new TacnocSession({ secretStoreFactory: () => new InMemorySecretStore() });
    await session.createProject(path.join(dir, 'estop.tacnocproj'), 'estop');
    session.setInterceptState({ interceptRequests: true });
    const held = session['interceptor'].holdRequest(requestView('r4'));
    session.emergencyStop();
    expect((await held).action).toBe('drop');
    await session.closeProject();
  });
});

// ---- "TLS interception is working" must mean the browser trusts the CA ----
describe('interception evidence counts proxy traffic only', () => {
  it('does not count Repeater or Variation HTTPS as decrypted interception', async () => {
    const store = await ProjectStore.create(path.join(dir, 'https.tacnocproj'), {
      name: 'https',
      secretStore: new InMemorySecretStore(),
    });
    // Engine-generated HTTPS: sent over Node's own TLS, never presents the
    // project's leaf certificate, and succeeds whether or not the CA is trusted.
    store.history.insert(exchange('repeater', 'https'));
    store.history.insert(exchange('variation', 'https'));
    expect(store.history.countByScheme('https')).toBe(2);
    expect(store.history.countInterceptedHttps()).toBe(0);

    // Proxy-decrypted HTTPS is the only thing that proves interception works.
    store.history.insert(exchange('proxy', 'https'));
    expect(store.history.countInterceptedHttps()).toBe(1);

    // Proxied plain HTTP proves nothing about the certificate either.
    store.history.insert(exchange('proxy', 'http'));
    expect(store.history.countInterceptedHttps()).toBe(1);
    store.close();
  });

  it('the CA status the preflight check reads uses the proxy-only count', async () => {
    const session = new TacnocSession({ secretStoreFactory: () => new InMemorySecretStore() });
    await session.createProject(path.join(dir, 'ca-evidence.tacnocproj'), 'ca-evidence');
    session['project']!.history.insert(exchange('repeater', 'https'));
    expect(session.getCaStatus().observedHttpsExchanges).toBe(0);
    expect(session.getCaInfo().interceptedHttpsExchanges).toBe(0);

    session['project']!.history.insert(exchange('proxy', 'https'));
    expect(session.getCaStatus().observedHttpsExchanges).toBe(1);
    await session.closeProject();
  });
});

// ---- a suppressed finding must not drive the badge ----
describe('suppressed findings are not announced', () => {
  it('upsert reports false for a finding stored as suppressed', async () => {
    const store = await ProjectStore.create(path.join(dir, 'find.tacnocproj'), {
      name: 'find',
      secretStore: new InMemorySecretStore(),
    });
    // findings.exchange_id is a foreign key — the exchanges have to exist.
    store.history.insert(exchange('proxy', 'https', 'e1'));
    store.history.insert(exchange('proxy', 'https', 'e2'));
    const base: Finding = {
      id: 'f1',
      exchangeId: 'e1',
      dedupeKey: 'missing-hsts:app.example.test',
      title: 'Missing HSTS',
      severity: 'low',
      confidence: 'firm',
      module: 'security-headers',
      moduleVersion: '1',
      description: 'no hsts',
      remediation: 'add hsts',
      evidence: [],
      createdAt: Date.now(),
      suppressed: false,
    };
    // Visible: announced.
    expect(store.findings.upsert(base)).toBe(true);

    store.findings.addSuppression({
      id: 's1',
      module: 'security-headers',
      reason: 'known and accepted for this engagement',
      createdAt: Date.now(),
    });
    const second: Finding = { ...base, id: 'f2', exchangeId: 'e2' };
    // Stored, but suppressed — the sidebar badge counts this event while the
    // Findings list counts unsuppressed rows, so announcing it made the badge
    // climb for findings the operator had explicitly hidden.
    expect(store.findings.upsert(second)).toBe(false);
    expect(store.findings.list({ includeSuppressed: true }).length).toBe(2);
    expect(store.findings.list().length).toBe(1);
    store.close();
  });
});

// ---- identity compliance must sample generated traffic, not the newest rows ----
describe('identity compliance sampling', () => {
  it('still finds generated traffic after proxy traffic floods the newest rows', async () => {
    const session = new TacnocSession({ secretStoreFactory: () => new InMemorySecretStore() });
    await session.createProject(path.join(dir, 'ident.tacnocproj'), 'ident');
    session.setEngagementProfile({
      ...session.getEngagementProfile(),
      userAgent: { required: 'greynoc-research', enforce: true },
    } as never);

    const project = session['project']!;
    // One non-compliant Repeater request, then enough proxy traffic to push it
    // out of any "newest 100 rows of any source" window.
    project.history.insert(exchange('repeater', 'https'));
    for (let i = 0; i < 150; i += 1) project.history.insert(exchange('proxy', 'https'));

    const compliance = session.getIdentityCompliance();
    // The bug reported "every generated request carries the required identity"
    // on the strength of a sample of zero.
    expect(compliance.sampled).toBe(1);
    expect(compliance.compliant).toBe(0);
    await session.closeProject();
  });
});

// ---- the CA setup guide ----
describe('CA install guide', () => {
  it('gives a runnable, per-platform install AND removal command', () => {
    for (const platform of ['win32', 'darwin', 'linux'] as NodeJS.Platform[]) {
      const guide = caInstallGuide('/tmp/tacnoc-ca.crt', platform);
      expect(guide.steps.length).toBeGreaterThan(0);
      // Removal is never a footnote: an interception CA left trusted after an
      // engagement is a standing risk.
      expect(guide.removal.command).toBeTruthy();
      expect(guide.steps.some((s) => !!s.command)).toBe(true);
      expect(guide.separateTrustStoreNote).toBeTruthy();
    }
  });

  it('narrows trust to the current user, never machine-wide', () => {
    expect(caInstallGuide('/tmp/ca.crt', 'win32').steps[0]!.command).toContain('-user');
    // No `-d`: that flag targets the admin/system domain and needs sudo.
    const mac = caInstallGuide('/tmp/ca.crt', 'darwin').steps[0]!.command!;
    expect(mac).toContain('login.keychain-db');
    expect(mac).not.toMatch(/\s-d\s/);
    // Linux installs into the browser's own NSS store, not the system bundle.
    expect(caInstallGuide('/tmp/ca.crt', 'linux').steps[0]!.command).toContain('.pki/nssdb');
  });

  it('quotes the certificate path so a space in it cannot split the command', () => {
    const win = caInstallGuide('C:\\Users\\a b\\ca.crt', 'win32').steps[0]!.command!;
    expect(win).toContain('"C:\\Users\\a b\\ca.crt"');
    const nix = caInstallGuide("/home/a b/o'brien/ca.pem", 'linux').steps[0]!.command!;
    expect(nix).toContain(`'/home/a b/o'\\''brien/ca.pem'`);
  });

  it('renders a placeholder before anything has been saved', () => {
    expect(caInstallGuide(undefined, 'win32').steps[0]!.command).toContain(CERT_PATH_TOKEN);
    expect(caInstallGuide('   ', 'win32').steps[0]!.command).toContain(CERT_PATH_TOKEN);
  });

  it('keeps the one-line summary in step with the guide', () => {
    // The main process used to carry its own verbatim copy of this text, so the
    // two could drift while both looked authoritative.
    expect(caInstallInstructions('win32')).toMatch(/current user/i);
    expect(caInstallInstructions('darwin')).toMatch(/keychain/i);
    expect(caInstallInstructions('linux')).toMatch(/browser/i);
  });
});
