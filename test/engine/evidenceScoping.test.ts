/**
 * What a "single target" bundle is allowed to know about the rest of the project.
 *
 * `evidenceBundle.test.ts` proves the assembler asks for one host's briefing.
 * This proves the session answers that question honestly — and it is the level
 * the defect actually lived at. A bundle exported for one host contained
 * exactly one exchange file and, three sections further down, `HANDOFF.md`
 * ranking a second target's endpoints under the engagement folder named after
 * the client. Two hosts, one project, one export: that is the whole repro.
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import * as os from 'node:os';
import * as path from 'node:path';
import * as crypto from 'node:crypto';
import { promises as fs } from 'node:fs';
import { TacnocSession } from '../../src/engine/session.js';
import { InMemorySecretStore } from '../../src/engine/ca/secretStore.js';
import { LogBuffer } from '../../src/engine/logging/logBuffer.js';
import { readZip } from '../../src/engine/evidence/zip.js';
import { startTestServer, type TestServerHandle } from '../server/testServer.js';
import { httpThroughProxy } from '../support/proxyClient.js';

const TARGET = 'localhost';
const OTHER = '127.0.0.1';

let server: TestServerHandle;
let session: TacnocSession;
let dir: string;
let projectDir: string;
let originPort: number;

async function waitFor(pred: () => boolean, ms = 4000): Promise<void> {
  const start = Date.now();
  while (!pred() && Date.now() - start < ms) await new Promise((r) => setTimeout(r, 20));
}

beforeAll(async () => {
  server = await startTestServer();
  originPort = server.httpPort;
  dir = path.join(os.tmpdir(), `tacnoc-scoping-${crypto.randomBytes(6).toString('hex')}`);
  // The folder name is the disclosure, not just the traffic: an engagement
  // folder is named after whoever it belongs to.
  projectDir = path.join(dir, 'TiffanyCo-Confidential.tacnocproj');
  session = new TacnocSession({ secretStoreFactory: () => new InMemorySecretStore() });
  await session.createProject(projectDir, 'scoping-test');

  const status = await session.startProxy('127.0.0.1', 0);
  const proxyPort = status.port as number;
  session.setScope({
    include: [
      { id: 'a', enabled: true, hostMatch: 'exact', host: TARGET, schemes: [], ports: [] },
      { id: 'b', enabled: true, hostMatch: 'exact', host: OTHER, schemes: [], ports: [] },
    ],
    exclude: [],
  });

  // Two in-scope hosts, each with an object identifier in the path so both
  // score as leads and the ranking has something to leak.
  await httpThroughProxy('127.0.0.1', proxyPort, TARGET, originPort, {
    path: '/account/42?user_id=7',
  });
  await httpThroughProxy('127.0.0.1', proxyPort, OTHER, originPort, {
    path: '/admin/99?user_id=9',
  });
  // A genuinely `Content-Encoding: gzip` response, captured and stored the way
  // the proxy stores one, so the bundle is read back off real bytes rather than
  // a fixture that decided in advance what the wire looked like.
  await httpThroughProxy('127.0.0.1', proxyPort, TARGET, originPort, { path: '/gzip' });
  await waitFor(() => session.historyCount() >= 3);
});

afterAll(async () => {
  await session.closeProject();
  await server.close();
  await fs.rm(dir, { recursive: true, force: true });
});

describe('engine briefing scoping', () => {
  it('ranks every captured site when nobody narrowed it', async () => {
    const briefing = await session.engineBriefing();
    expect(briefing).toContain(`http://${TARGET}:${originPort}`);
    expect(briefing).toContain(`http://${OTHER}:${originPort}`);
    expect(briefing).toContain('## Engagement folder:');
  });

  it('ranks only the named host, and stops naming the engagement folder', async () => {
    const briefing = await session.engineBriefing({ host: TARGET });
    expect(briefing).toContain(`http://${TARGET}:${originPort}`);
    expect(briefing).not.toContain(`http://${OTHER}:${originPort}`);
    expect(briefing).not.toContain('## Engagement folder:');
    expect(briefing).not.toContain('TiffanyCo-Confidential');
    // Still says what it is and what it left out, so a reader is not misled
    // into thinking this is everything the project holds.
    expect(briefing).toContain(`Narrowed to ${TARGET}`);
  });
});

describe('evidence bundle scoping, end to end', () => {
  it('exports one host without handing over the other, or the folder', async () => {
    const built = await session.buildTargetEvidenceBundle(TARGET);
    const files = readZip(built.zip);
    const handoff = (files.get('HANDOFF.md') as Buffer).toString('utf8');
    const everything = [...files.values()].map((b) => b.toString('utf8')).join('\n');

    expect(built.summary.exchangeCount).toBe(2);
    expect(handoff).toContain(TARGET);
    // The exchange filter was never the broken part — the briefing rendered
    // verbatim underneath it was.
    expect(handoff).not.toContain(`http://${OTHER}:${originPort}`);
    expect(everything).not.toContain('TiffanyCo-Confidential');
  });

  it('reads back a gzip response the proxy really captured', async () => {
    const files = readZip((await session.buildTargetEvidenceBundle(TARGET)).zip);
    const gzipped = [...files.entries()]
      .filter(([name]) => name.startsWith('exchanges/'))
      .map(([, body]) => body.toString('utf8'))
      .find((body) => body.includes('/gzip'));

    expect(gzipped).toBeDefined();
    expect(gzipped).toContain('gzipped-payload-gzipped-payload-');
    expect(gzipped).toContain('response body decompressed from gzip');
  });

  it('does not ship the session log tail unless it was asked for', async () => {
    const off = await session.buildTargetEvidenceBundle(TARGET);
    expect([...readZip(off.zip).keys()]).not.toContain('logs/tacnoc.log.jsonl');
    expect(off.summary.logCount).toBe(0);

    const on = await session.buildTargetEvidenceBundle(TARGET, { includeLogs: true });
    expect([...readZip(on.zip).keys()]).toContain('logs/tacnoc.log.jsonl');
  });
});

describe('log tail lifetime', () => {
  it('does not carry one project’s records into the next project’s export', async () => {
    const buffer = new LogBuffer();
    const other = new TacnocSession({
      secretStoreFactory: () => new InMemorySecretStore(),
      logBuffer: buffer,
    });
    const root = path.join(os.tmpdir(), `tacnoc-tail-${crypto.randomBytes(6).toString('hex')}`);
    try {
      await other.createProject(path.join(root, 'a.tacnocproj'), 'project-a');
      buffer.sink({
        ts: new Date().toISOString(),
        level: 'info',
        scope: 'proxy',
        msg: 'connect',
        meta: { host: 'client-a.example', port: 443 },
      });
      expect(other.exportLogTail().jsonl).toContain('client-a.example');

      // The buffer is built once per Session and the Session outlives every
      // project opened in it, so this used to be a straight carry-over: up to
      // 5000 of the last engagement's records, exported inside the next one's.
      await other.createProject(path.join(root, 'b.tacnocproj'), 'project-b');
      expect(other.exportLogTail().count).toBe(0);
      expect(other.exportLogTail().jsonl).not.toContain('client-a.example');
    } finally {
      await other.dispose();
      await fs.rm(root, { recursive: true, force: true });
    }
  });
});
