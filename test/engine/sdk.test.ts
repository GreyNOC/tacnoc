import { describe, it, expect, beforeAll } from 'vitest';
import * as path from 'node:path';
import { promises as fs } from 'node:fs';
import * as crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { ExtensionHost } from '../../src/sdk/host.js';
import type { ExtensionManifest, Permission } from '../../src/sdk/api.js';
import type { HttpExchange } from '../../src/shared/model.js';

const REDACTION = { maskCookies: true, maskAuthorization: true, maskSecretPatterns: true };

const exampleDir = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '../../examples/extensions/header-hygiene',
);

let manifest: ExtensionManifest;
let source: string;

beforeAll(async () => {
  manifest = JSON.parse(await fs.readFile(path.join(exampleDir, 'manifest.json'), 'utf8'));
  source = await fs.readFile(path.join(exampleDir, 'extension.js'), 'utf8');
});

async function withHost<T>(fn: (host: ExtensionHost) => Promise<T>): Promise<T> {
  const host = new ExtensionHost(REDACTION);
  try {
    return await fn(host);
  } finally {
    await host.terminate();
  }
}

/** Poll `cond` until it is true, or throw after `timeoutMs`. */
async function waitFor(cond: () => boolean, timeoutMs = 4000): Promise<void> {
  const start = Date.now();
  while (!cond()) {
    if (Date.now() - start > timeoutMs) throw new Error('waitFor: condition not met in time');
    await new Promise((r) => setTimeout(r, 15));
  }
}

function exchangeWith(headers: { name: string; value: string }[]): HttpExchange {
  return {
    id: crypto.randomUUID(),
    createdAt: Date.now(),
    source: 'proxy',
    scheme: 'https',
    host: 'app.example.test',
    port: 443,
    inScope: true,
    automated: false,
    request: {
      method: 'GET',
      target: '/',
      url: 'https://app.example.test/',
      httpVersion: 'HTTP/1.1',
      headers: [{ name: 'Host', value: 'app.example.test' }],
      body: { size: 0, truncated: false },
    },
    response: {
      statusCode: 200,
      statusMessage: 'OK',
      httpVersion: 'HTTP/1.1',
      headers,
      body: { size: 0, truncated: false },
    },
    tags: [],
  };
}

describe('extension SDK host (isolated worker)', () => {
  it('loads the example and reports its registered capabilities', async () => {
    await withHost(async (host) => {
      await host.load(manifest, source, manifest.permissions);
      expect(host.listExtensions()).toHaveLength(1);
      expect(host.getTransforms().some((t) => t.id === 'ext.header-hygiene.rot13')).toBe(true);
      expect(host.getCheckModules().some((c) => c.module.includes('header-hygiene'))).toBe(true);
      expect(host.getEditorTabs().some((t) => t.id.endsWith('header-summary'))).toBe(true);
    });
  });

  it('does not register a transform when the transforms permission is withheld', async () => {
    await withHost(async (host) => {
      const granted: Permission[] = ['passive-checks']; // no 'transforms'
      await host.load(manifest, source, granted);
      expect(host.getTransforms()).toHaveLength(0);
      expect(host.getCheckModules().length).toBeGreaterThan(0);
    });
  });

  it('runs the registered ROT13 transform in the worker', async () => {
    await withHost(async (host) => {
      await host.load(manifest, source, manifest.permissions);
      expect(await host.applyTransform('ext.header-hygiene.rot13', 'Hello')).toBe('Uryyb');
    });
  });

  it('runs extension scanner checks in the worker and finds X-Debug', async () => {
    await withHost(async (host) => {
      await host.load(manifest, source, manifest.permissions);
      const findings = await host.runChecks(
        exchangeWith([
          { name: 'Content-Type', value: 'text/plain' },
          { name: 'X-Debug', value: 'trace=on' },
        ]),
        '',
        '',
      );
      expect(findings.some((f) => f.title.includes('X-Debug'))).toBe(true);
      expect(findings[0]?.module).toContain('header-hygiene');
    });
  });

  it('dispatches sanitized traffic without throwing', async () => {
    await withHost(async (host) => {
      await host.load(manifest, source, manifest.permissions);
      expect(() =>
        host.dispatchTraffic(
          exchangeWith([{ name: 'Set-Cookie', value: 'sid=TOPSECRET; Path=/' }]),
        ),
      ).not.toThrow();
    });
  });

  it('rejects source without an activate() export', async () => {
    await withHost(async (host) => {
      await expect(
        host.load(manifest, 'module.exports = {};', manifest.permissions),
      ).rejects.toThrow(/activate/);
    });
  });

  it('blocks require() from extension code (sandbox)', async () => {
    await withHost(async (host) => {
      const evil = 'module.exports = { activate: function(){ require("fs"); } };';
      await expect(host.load(manifest, evil, manifest.permissions)).rejects.toThrow();
    });
  });

  it('runs the extension in a SEPARATE OS process with no process/require in scope', async () => {
    await withHost(async (host) => {
      // The extension host is a different process from the test runner.
      const pid = host.pid();
      expect(typeof pid).toBe('number');
      expect(pid).toBeGreaterThan(0);
      expect(pid).not.toBe(process.pid);

      // A transform executes inside the child's vm, where process/require are
      // undefined — even a vm escape only reaches the isolated child, never here.
      const probeManifest: ExtensionManifest = {
        id: 'probe-ext',
        name: 'Probe',
        version: '1.0.0',
        description: '',
        sdkVersion: '1.0.0',
        permissions: ['transforms'],
      };
      const probeSource =
        'module.exports = { activate: function(b){' +
        '  b.registerTransform({ id: "probe", label: "Probe", category: "inspect",' +
        '    transform: function(){ return (typeof process) + "|" + (typeof require); } });' +
        '} };';
      await host.load(probeManifest, probeSource, ['transforms']);
      const out = await host.applyTransform('ext.probe-ext.probe', 'x');
      expect(out).toBe('undefined|undefined');
    });
  });

  it('rolls back registrations from an extension whose activate() throws', async () => {
    await withHost(async (host) => {
      // A valid extension registers a check (so the worker check path is active).
      await host.load(manifest, source, manifest.permissions);

      // A second extension registers a check, then throws during activate.
      const manifestB: ExtensionManifest = {
        id: 'evil-b',
        name: 'Evil B',
        version: '1.0.0',
        description: '',
        sdkVersion: '1.0.0',
        permissions: ['passive-checks'],
      };
      const sourceB =
        'module.exports = { activate: function(b){' +
        '  b.registerScannerCheck({ module: "orphan", version: "1", appliesTo: function(){ return true; },' +
        '    run: function(){ return [{ dedupeKey: "o", title: "B-ORPHAN-FINDING", severity: "low",' +
        '      confidence: "firm", description: "d", remediation: "r", evidence: [] }]; } });' +
        '  throw new Error("activate boom");' +
        '} };';
      await expect(host.load(manifestB, sourceB, ['passive-checks'])).rejects.toThrow();

      // The orphaned check from the failed extension must NOT run on later scans.
      const findings = await host.runChecks(
        exchangeWith([{ name: 'Content-Type', value: 'text/plain' }]),
        '',
        '',
      );
      expect(findings.some((f) => f.title.includes('B-ORPHAN'))).toBe(false);
    });
  });

  it('rejects a second extension that reuses an already-loaded id (keeps the first intact)', async () => {
    await withHost(async (host) => {
      await host.load(manifest, source, manifest.permissions);
      const checksBefore = host.getCheckModules().length;

      await expect(host.load(manifest, source, manifest.permissions)).rejects.toThrow(
        /already loaded/i,
      );

      // The first extension's registrations are untouched and still work.
      expect(host.listExtensions()).toHaveLength(1);
      expect(host.getCheckModules().length).toBe(checksBefore);
      expect(await host.applyTransform('ext.header-hygiene.rot13', 'Hello')).toBe('Uryyb');
    });
  });

  it('ignores a malformed createFinding payload without crashing the host', async () => {
    const collected: { title: string }[] = [];
    const host = new ExtensionHost(REDACTION, undefined, (f) => collected.push(f));
    try {
      const finderManifest: ExtensionManifest = {
        id: 'finder-ext',
        name: 'Finder',
        version: '1.0.0',
        description: '',
        sdkVersion: '1.0.0',
        permissions: ['read-traffic', 'findings'],
      };
      // The handler emits a garbage finding (must be ignored) then a valid one.
      const finderSource =
        'module.exports = { activate: function(b){' +
        '  b.onTraffic(function(){' +
        '    b.createFinding(42);' +
        '    b.createFinding(null);' +
        '    b.createFinding({ dedupeKey:"k", title:"REAL-FINDING", severity:"low",' +
        '      confidence:"firm", description:"d", remediation:"r", evidence:[] });' +
        '  });' +
        '} };';
      await host.load(finderManifest, finderSource, ['read-traffic', 'findings']);
      host.dispatchTraffic(exchangeWith([{ name: 'Content-Type', value: 'text/plain' }]));

      await waitFor(() => collected.some((f) => f.title === 'REAL-FINDING'));
      expect(collected.some((f) => f.title === 'REAL-FINDING')).toBe(true);
      // The host survived the malformed payloads and still answers RPCs.
      expect(host.pid()).toBeGreaterThan(0);
    } finally {
      await host.terminate();
    }
  });

  it('materializes an extension finding with out-of-range fields to safe defaults', async () => {
    const collected: { severity: string; confidence: string; title: string }[] = [];
    const host = new ExtensionHost(REDACTION, undefined, (f) =>
      collected.push({ severity: f.severity, confidence: f.confidence, title: f.title }),
    );
    try {
      const m: ExtensionManifest = {
        id: 'coerce-ext',
        name: 'Coerce',
        version: '1.0.0',
        description: '',
        sdkVersion: '1.0.0',
        permissions: ['read-traffic', 'findings'],
      };
      const src =
        'module.exports = { activate: function(b){' +
        '  b.onTraffic(function(){' +
        '    b.createFinding({ dedupeKey:"k", title:"COERCE", severity:"OMEGA",' +
        '      confidence:"absolute", description:"d", remediation:"r", evidence:"not-an-array" });' +
        '  });' +
        '} };';
      await host.load(m, src, ['read-traffic', 'findings']);
      host.dispatchTraffic(exchangeWith([{ name: 'Content-Type', value: 'text/plain' }]));

      await waitFor(() => collected.some((f) => f.title === 'COERCE'));
      const f = collected.find((x) => x.title === 'COERCE')!;
      expect(f.severity).toBe('info'); // invalid 'OMEGA' -> default
      expect(f.confidence).toBe('tentative'); // invalid 'absolute' -> default
    } finally {
      await host.terminate();
    }
  });

  it('fails closed — drops all extension capabilities when the child process dies', async () => {
    await withHost(async (host) => {
      await host.load(manifest, source, manifest.permissions);
      expect(host.hasExtensionChecks()).toBe(true);
      expect(host.getTransforms().length).toBeGreaterThan(0);

      // Simulate a crash: kill the isolated child out from under the host.
      const pid = host.pid();
      expect(typeof pid).toBe('number');
      process.kill(pid!, 'SIGKILL');

      await waitFor(() => !host.hasExtensionChecks());
      expect(host.hasExtensionChecks()).toBe(false);
      expect(host.getTransforms()).toHaveLength(0);
      expect(host.getCheckModules()).toHaveLength(0);

      // Calls now reject fast (fail-closed) instead of hanging.
      await expect(host.applyTransform('ext.header-hygiene.rot13', 'x')).rejects.toThrow();
      await expect(
        host.runChecks(exchangeWith([{ name: 'Content-Type', value: 'text/plain' }]), '', ''),
      ).resolves.toEqual([]);
    });
  });
});
