/**
 * End-to-end wiring of the scope gate.
 *
 * Scope can now arrive two ways — typed into the app, or read out of the
 * engagement folder and ticked — and the question that matters is not "does
 * each screen work" but "does a scope provided by EITHER route actually reach
 * the running agent and let it send". These tests drive a real project through
 * the real session, so a break anywhere in the chain (persistence, the live
 * read, the start guard, the per-request gate) shows up here rather than in a
 * hunt.
 */

import { describe, expect, it, beforeEach, afterEach } from 'vitest';
import { promises as fs } from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { TacnocSession } from '../../src/engine/session.js';
import { InMemorySecretStore } from '../../src/engine/ca/secretStore.js';
import { buildTools, meshRepeaterScopeDecision } from '../../src/engine/ai/tools.js';
import { scopeRulesFromProposal } from '../../src/engine/engagement/scopeProposal.js';
import type { ScopeRule } from '../../src/shared/scope.js';

let dir = '';
let session: TacnocSession;

const POLICY = `# Acme Bounty

## In scope
- api.acme-corp.test
- *.dev.acme-corp.test

## Out of scope
- internal.acme-corp.test
`;

beforeEach(async () => {
  dir = await fs.mkdtemp(path.join(os.tmpdir(), 'tacnoc-gate-'));
  session = new TacnocSession({
    secretStoreFactory: () => new InMemorySecretStore(),
    aiSecretStore: new InMemorySecretStore(),
  });
  await session.createProject(path.join(dir, 'p.tacnocproj'), 'gate-test', 'https://program.test');
});

afterEach(async () => {
  await session.dispose();
  await fs.rm(dir, { recursive: true, force: true }).catch(() => undefined);
});

/** The scope decision the mesh's own repeater tool would make for a host. */
const meshAllows = (host: string): boolean =>
  meshRepeaterScopeDecision(session, {
    scheme: 'https',
    host,
    port: 443,
    raw: 'GET / HTTP/1.1\r\nHost: x\r\n\r\n',
  }).inScope;

describe('scope set in the app reaches the agent', () => {
  it('starts fail-closed: nothing is allowed and the mesh refuses to run', async () => {
    expect(session.getScope().include).toHaveLength(0);
    expect(meshAllows('api.acme-corp.test')).toBe(false);
    await expect(session.startMeshRun({ objective: 'test' })).rejects.toThrow(/scope is empty/i);
  });

  it('a rule set through the app is visible to the mesh tool gate immediately', () => {
    session.setScope({
      include: [
        {
          id: 'i1',
          enabled: true,
          hostMatch: 'exact',
          host: 'api.acme-corp.test',
          schemes: [],
          ports: [],
        },
      ],
      exclude: [],
    });
    // Live read, not a snapshot taken at project open.
    expect(meshAllows('api.acme-corp.test')).toBe(true);
    expect(meshAllows('evil.test')).toBe(false);
  });

  it('survives a close and reopen of the project', async () => {
    const projectPath = path.join(dir, 'p.tacnocproj');
    session.setScope({
      include: [
        {
          id: 'i1',
          enabled: true,
          hostMatch: 'exact',
          host: 'api.acme-corp.test',
          schemes: [],
          ports: [],
        },
      ],
      exclude: [],
    });
    await session.closeProject();
    await session.openProject(projectPath);
    expect(session.getScope().include).toHaveLength(1);
    expect(meshAllows('api.acme-corp.test')).toBe(true);
  });

  it('a disabled include rule does not put anything in scope', () => {
    session.setScope({
      include: [
        {
          id: 'i1',
          enabled: false,
          hostMatch: 'exact',
          host: 'api.acme-corp.test',
          schemes: [],
          ports: [],
        },
      ],
      exclude: [],
    });
    expect(meshAllows('api.acme-corp.test')).toBe(false);
  });
});

describe('scope read from the engagement folder reaches the agent', () => {
  const writePolicy = async (): Promise<void> => {
    await fs.writeFile(path.join(dir, 'p.tacnocproj', 'program-policy.md'), POLICY, 'utf8');
  };

  it('finds the hosts in the folder and reports where each came from', async () => {
    await writePolicy();
    const proposal = await session.proposeScopeFromWorkspace();
    expect(proposal.include.map((c) => c.host).sort()).toEqual(
      ['*.dev.acme-corp.test', 'api.acme-corp.test'].sort(),
    );
    expect(proposal.exclude.map((c) => c.host)).toEqual(['internal.acme-corp.test']);
    expect(proposal.include[0]?.evidence[0]?.file).toBe('program-policy.md');
  });

  it('proposing alone changes NOTHING — scope stays fail-closed', async () => {
    await writePolicy();
    await session.proposeScopeFromWorkspace();
    expect(session.getScope().include).toHaveLength(0);
    expect(meshAllows('api.acme-corp.test')).toBe(false);
  });

  it('once the operator adds them, the agent may hit exactly those hosts', async () => {
    await writePolicy();
    const proposal = await session.proposeScopeFromWorkspace();
    const current = session.getScope();
    const { include, exclude } = scopeRulesFromProposal(
      proposal,
      proposal.include.map((c) => c.host),
      current,
    );
    session.setScope({
      include: [...current.include, ...(include as unknown as ScopeRule[])],
      exclude: [...current.exclude, ...(exclude as unknown as ScopeRule[])],
    });

    expect(meshAllows('api.acme-corp.test')).toBe(true);
    expect(meshAllows('anything.dev.acme-corp.test')).toBe(true);
    expect(meshAllows('deep.nested.dev.acme-corp.test')).toBe(true);
    // The exclusion from the policy is honoured without the operator ticking it.
    expect(meshAllows('internal.acme-corp.test')).toBe(false);
    // And nothing outside the policy leaked in.
    expect(meshAllows('acme-corp.test')).toBe(false);
    expect(meshAllows('evil.test')).toBe(false);
  });

  it('the empty-scope preflight blocker names what the folder contains', async () => {
    await writePolicy();
    const report = await session.getPreflight();
    const scopeCheck = report.checks.find((c) => c.id === 'scope');
    expect(scopeCheck?.severity).toBe('blocker');
    // The operator should not have to work out for themselves that the answer
    // is sitting in their own hunt folder.
    expect(scopeCheck?.detail).toContain('api.acme-corp.test');
    expect(scopeCheck?.remedy).toMatch(/proposed scope/i);
  });

  it('says plainly when the folder holds no scope information', async () => {
    const report = await session.getPreflight();
    const scopeCheck = report.checks.find((c) => c.id === 'scope');
    expect(scopeCheck?.severity).toBe('blocker');
    expect(scopeCheck?.detail).toMatch(/nothing is in scope by default/i);
  });
});

describe('the agent is told how to find scope', () => {
  it('exposes a read-only tool for reading scope out of the folder', () => {
    const tools = buildTools(session, { workspaceAccess: true, allowCertOps: false });
    const tool = tools.find((t) => t.name === 'propose_scope_from_workspace');
    expect(tool).toBeDefined();
    expect(tool?.effect).toBe('read');
    expect(tool?.mutates).toBe(false);
  });

  it('gives the mesh NO tool that can change scope', () => {
    const tools = buildTools(session, { workspaceAccess: true, allowCertOps: true });
    const names = tools.map((t) => t.name);
    // Nothing in the whole registry writes scope, whatever it might be called.
    expect(names.filter((n) => /scope/i.test(n) && !/evaluate|propose/i.test(n))).toHaveLength(0);
  });

  it('hides the folder tools entirely when workspace access is off', () => {
    const tools = buildTools(session, { workspaceAccess: false, allowCertOps: false });
    const names = tools.map((t) => t.name);
    expect(names).not.toContain('propose_scope_from_workspace');
    expect(names).not.toContain('read_workspace_file');
  });
});

describe('the operator is never left guessing', () => {
  it('reports folder hosts even when the policy is a bare list with no headings', async () => {
    // The common real shape: someone pastes the asset list into notes.txt with
    // no "In scope" heading above it. Everything lands in `unclear`, and
    // reporting only the confidently-classified hosts made preflight claim the
    // folder held nothing while it plainly named the targets.
    await fs.writeFile(
      path.join(dir, 'p.tacnocproj', 'targets.txt'),
      'api.acme-corp.test\nshop.acme-corp.test\n',
      'utf8',
    );
    const proposal = await session.proposeScopeFromWorkspace();
    expect(proposal.include).toHaveLength(0);
    expect(proposal.unclear.map((c) => c.host).sort()).toEqual([
      'api.acme-corp.test',
      'shop.acme-corp.test',
    ]);

    const report = await session.getPreflight();
    const scopeCheck = report.checks.find((c) => c.id === 'scope');
    expect(scopeCheck?.detail).toContain('api.acme-corp.test');
    expect(scopeCheck?.remedy).toMatch(/proposed scope/i);
  });

  it('refuses to start the mesh when every include rule is disabled', async () => {
    session.setScope({
      include: [
        {
          id: 'i1',
          enabled: false,
          hostMatch: 'exact',
          host: 'api.acme-corp.test',
          schemes: [],
          ports: [],
        },
      ],
      exclude: [],
    });
    // Counting rules without checking `enabled` let the run start and then have
    // every request refused — provider tokens spent rediscovering what the
    // guard already knew.
    await expect(session.startMeshRun({ objective: 'test' })).rejects.toThrow(/scope is empty/i);
  });

  it('points at the engagement folder in the mesh start refusal', async () => {
    await expect(session.startMeshRun({ objective: 'test' })).rejects.toThrow(/engagement folder/i);
  });

  it('names the folder hosts in the refusal, ahead of any other setup error', async () => {
    await fs.writeFile(
      path.join(dir, 'p.tacnocproj', 'targets.txt'),
      ['api.acme-corp.test', ''].join('\n'),
      'utf8',
    );
    // No API key is configured either, but scope is the safety gate and the
    // one-click fix, so it must be the error the operator is shown.
    await expect(session.startMeshRun({ objective: 'test' })).rejects.toThrow(
      /api\.acme-corp\.test/,
    );
  });
});
