import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import * as os from 'node:os';
import * as path from 'node:path';
import { promises as fs } from 'node:fs';
import * as crypto from 'node:crypto';
import { TacnocSession } from '../../src/engine/session.js';
import { InMemorySecretStore } from '../../src/engine/ca/secretStore.js';
import { startTestServer, type TestServerHandle } from '../server/testServer.js';
import { httpsThroughProxy } from '../support/proxyClient.js';

let server: TestServerHandle;
let session: TacnocSession;
let dir: string;

beforeAll(async () => {
  server = await startTestServer();
  dir = path.join(os.tmpdir(), `tacnoc-session-${crypto.randomBytes(6).toString('hex')}`);
  session = new TacnocSession({ secretStoreFactory: () => new InMemorySecretStore() });
  await session.createProject(path.join(dir, 'p.tacnocproj'), 'session-test');
});

afterAll(async () => {
  await session.closeProject();
  await server.close();
  await fs.rm(dir, { recursive: true, force: true });
});

async function waitFor(pred: () => boolean, ms = 3000): Promise<void> {
  const start = Date.now();
  while (!pred() && Date.now() - start < ms) await new Promise((r) => setTimeout(r, 20));
}

describe('TacnocSession end-to-end', () => {
  it('starts a loopback proxy, captures HTTPS, persists history, and scans', async () => {
    const status = await session.startProxy('127.0.0.1', 0);
    expect(status.running).toBe(true);
    expect(status.loopbackOnly).toBe(true);
    const port = status.port!;

    // add scope so this destination is in-scope (display + variation gating)
    session.setScope({
      include: [
        { id: 'r', enabled: true, hostMatch: 'exact', host: 'localhost', schemes: [], ports: [] },
      ],
      exclude: [],
    });

    const res = await httpsThroughProxy(
      '127.0.0.1',
      port,
      session.getCaInfo().certPem,
      'localhost',
      server.httpsPort,
      { path: '/missing-headers' },
    );
    expect(res.status).toBe(200);

    await waitFor(() => session.historyCount() >= 1);
    const page = session.queryHistory({ limit: 50 });
    expect(page.total).toBeGreaterThanOrEqual(1);
    const row = page.rows.find((r) => r.url.includes('/missing-headers'))!;
    expect(row.scheme).toBe('https');
    expect(row.inScope).toBe(true);

    // detail includes headers + body + sensitivity summary
    const detail = await session.getExchangeDetail(row.id);
    expect(detail?.response?.statusCode).toBe(200);
    expect(detail?.request.sensitive).toBeDefined();

    // passive scan produced security-header findings
    await waitFor(() => session.listFindings().some((f) => f.module === 'security-headers'));
    const findings = session.listFindings();
    expect(findings.some((f) => f.module === 'security-headers')).toBe(true);
  });

  it('exposes an emergency stop that does not throw with no active jobs', () => {
    expect(() => session.emergencyStop()).not.toThrow();
  });

  it('records audit entries for automated variation work only after scope + creation', () => {
    // Out-of-scope variation must be refused by the engine.
    session.setScope({ include: [], exclude: [] });
    expect(() =>
      session.createVariationJob({
        name: 't',
        base: {
          scheme: 'http',
          host: '127.0.0.1',
          port: server.httpPort,
          raw: `GET /json HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n`,
        },
        positions: [{ marker: '{{0}}', source: { kind: 'list', values: ['a'] } }],
        mode: 'batteringram',
        limits: { maxConcurrency: 1, requestsPerSecond: 5, timeoutMs: 5000, maxRequestsPerJob: 10 },
      }),
    ).toThrow(/not in scope/i);
  });
});
