/**
 * Extension host CHILD-PROCESS runtime, embedded as a source string that the
 * host writes to a temp `.cjs` file and forks (see src/sdk/host.ts).
 *
 * Isolation model (see docs/extension-sdk.md, THREAT_MODEL.md):
 *  - Extensions run in a separate OS PROCESS (its own memory space, forked with a
 *    minimal environment and a bounded heap). The host and the extension exchange
 *    only structured-cloneable IPC messages — no shared object references — so a
 *    full escape here cannot read the engine, session, secrets, or DB in the
 *    host process.
 *  - Inside the child, each extension is additionally evaluated in a `vm` context
 *    with no `require`/`process`/`module` in scope and with in-context code
 *    generation (`eval`/`new Function`) disabled, plus a 2s top-level time box.
 *
 * NOTE: the `vm` context is DEFENSE IN DEPTH, not an escape-proof boundary — a
 * determined extension can still reach the child realm's globals (e.g. via a
 * host-realm function's `.constructor`) and thus the child process's own
 * filesystem/network. The load-bearing controls are (1) the separate OS PROCESS
 * — the host's memory, session, CA key and DB are unreachable regardless of any
 * in-child escape — and (2) redaction of every exchange/body/header handed to an
 * extension (see host.ts). This is materially stronger than a worker thread but
 * is NOT a full OS sandbox (no seccomp/AppContainer/sandbox-exec). Only load
 * extensions you trust.
 */

export const EXTENSION_HOST_SOURCE = String.raw`
'use strict';
const vm = require('node:vm');
const SDK_VERSION = '1.0.0';

const extensions = [];      // { id, grants:Set, trafficHandlers:[] }
const checks = [];          // { extId, module, version, appliesTo, run }
const transforms = {};      // fullId -> { extId, label, category, fn }
const tabs = {};            // fullId -> { extId, label, render }
const actions = {};         // fullId -> { extId, label, onInvoke }

const redactorShim = {
  redactText: (s) => s,
  redactUrl: (s) => s,
  redactHeaderValue: (_n, v) => v,
  redactHeaders: (h) => h,
  redactBodyText: () => '',
};

function post(msg) { if (process.send) process.send(msg); }

function buildApi(ext) {
  const has = (p) => ext.grants.has(p);
  const api = {
    version: SDK_VERSION,
    manifest: ext.manifest,
    log: (m) => post({ type: 'log', level: 'info', msg: '[' + ext.id + '] ' + m }),
  };
  if (has('read-traffic')) api.onTraffic = (h) => ext.trafficHandlers.push(h);
  if (has('passive-checks'))
    api.registerScannerCheck = (c) =>
      checks.push({ extId: ext.id, module: c.module, version: c.version, appliesTo: c.appliesTo, run: c.run });
  if (has('transforms'))
    api.registerTransform = (t) => {
      transforms['ext.' + ext.id + '.' + t.id] = { extId: ext.id, label: t.label, category: t.category, fn: t.transform };
    };
  // Deliver created findings immediately (works whether called from a scanner
  // check or from an onTraffic handler — never buffered/dropped).
  if (has('findings')) api.createFinding = (f) => post({ type: 'finding', extId: ext.id, finding: f });
  if (has('ui-tabs'))
    api.registerEditorTab = (tab) => { tabs[ext.id + ':' + tab.id] = { extId: ext.id, label: tab.label, render: tab.render }; };
  if (has('context-menu'))
    api.registerContextMenuAction = (a) => { actions[ext.id + ':' + a.id] = { extId: ext.id, label: a.label, onInvoke: a.onInvoke }; };
  return api;
}

function load(manifest, source, granted) {
  const grants = new Set((granted || []).filter((p) => (manifest.permissions || []).includes(p)));
  const ext = { id: manifest.id, manifest: manifest, grants: grants, trafficHandlers: [] };
  const api = buildApi(ext);
  const sandbox = {
    module: { exports: {} },
    exports: {},
    tacnoc: api,
    console: {
      log: (...a) => post({ type: 'log', level: 'info', msg: '[' + manifest.id + '] ' + a.join(' ') }),
      warn: (...a) => post({ type: 'log', level: 'warn', msg: '[' + manifest.id + '] ' + a.join(' ') }),
      error: (...a) => post({ type: 'log', level: 'error', msg: '[' + manifest.id + '] ' + a.join(' ') }),
    },
  };
  sandbox.module.exports = sandbox.exports;
  // Disable in-context eval/new Function so a naive 'eval(...)' path is blocked
  // (defense in depth; the host-realm .constructor path is documented as out of
  // scope for the vm and mitigated by the process boundary + redaction).
  const context = vm.createContext(sandbox, { codeGeneration: { strings: false, wasm: false } });
  new vm.Script(source, { filename: 'tacnoc-ext:' + manifest.id }).runInContext(context, { timeout: 2000 });
  const mod = sandbox.module.exports;
  const activate = (mod && mod.activate) || sandbox.exports.activate;
  if (typeof activate !== 'function') throw new Error('extension ' + manifest.id + ' does not export an activate(tacnoc) function');
  // Snapshot the registries so a failed activate rolls back ONLY the delta it
  // added (not another extension's live registrations that share an id).
  const checksLen = checks.length;
  const tKeys = new Set(Object.keys(transforms));
  const tabKeys = new Set(Object.keys(tabs));
  const actKeys = new Set(Object.keys(actions));
  try {
    activate(api);
  } catch (e) {
    checks.length = checksLen;
    for (const k of Object.keys(transforms)) if (!tKeys.has(k)) delete transforms[k];
    for (const k of Object.keys(tabs)) if (!tabKeys.has(k)) delete tabs[k];
    for (const k of Object.keys(actions)) if (!actKeys.has(k)) delete actions[k];
    throw e;
  }
  extensions.push(ext);

  const own = (obj) => Object.keys(obj).filter((k) => obj[k].extId === ext.id);
  return {
    checks: checks.filter((c) => c.extId === ext.id).map((c) => ({ module: 'ext:' + ext.id + ':' + c.module, version: c.version })),
    transforms: own(transforms).map((id) => ({ id: id, label: transforms[id].label, category: transforms[id].category })),
    tabs: own(tabs).map((id) => ({ id: id, label: tabs[id].label })),
    actions: own(actions).map((id) => ({ id: id, label: actions[id].label })),
    hasTraffic: ext.trafficHandlers.length > 0,
  };
}

function runChecks(exchange, requestBodyText, responseBodyText) {
  const raw = [];
  for (const c of checks) {
    try {
      // Give each check its OWN copy of the exchange so one check cannot mutate
      // state observed by later checks (even in appliesTo).
      let view = exchange;
      try { view = structuredClone(exchange); } catch (_e) { view = exchange; }
      const ctx = { exchange: view, requestBodyText: requestBodyText, responseBodyText: responseBodyText, redactor: redactorShim };
      if (c.appliesTo && !c.appliesTo(view)) continue;
      const results = c.run(ctx) || [];
      for (const r of results) raw.push({ extId: c.extId, module: 'ext:' + c.extId + ':' + c.module, version: c.version, finding: r });
    } catch (e) {
      post({ type: 'log', level: 'warn', msg: 'check failed: ' + String(e) });
    }
  }
  return { raw: raw };
}

process.on('message', (m) => {
  try {
    if (m.type === 'load') {
      try { post({ type: 'loaded', reqId: m.reqId, ok: true, registrations: load(m.manifest, m.source, m.granted) }); }
      catch (e) { post({ type: 'loaded', reqId: m.reqId, ok: false, error: String((e && e.message) || e) }); }
    } else if (m.type === 'traffic') {
      for (const ext of extensions) for (const h of ext.trafficHandlers) {
        try { h(m.event); } catch (e) { post({ type: 'log', level: 'warn', msg: 'traffic handler: ' + String(e) }); }
      }
    } else if (m.type === 'runChecks') {
      const r = runChecks(m.exchange, m.requestBodyText, m.responseBodyText);
      post({ type: 'checksResult', reqId: m.reqId, raw: r.raw });
    } else if (m.type === 'applyTransform') {
      const t = transforms[m.id];
      if (!t) post({ type: 'transformResult', reqId: m.reqId, ok: false, error: 'unknown transform' });
      else { try { post({ type: 'transformResult', reqId: m.reqId, ok: true, value: String(t.fn(m.input)) }); }
             catch (e) { post({ type: 'transformResult', reqId: m.reqId, ok: false, error: String((e && e.message) || e) }); } }
    } else if (m.type === 'renderTab') {
      const tab = tabs[m.id];
      if (!tab) post({ type: 'renderResult', reqId: m.reqId, ok: false, error: 'unknown tab' });
      else { try { post({ type: 'renderResult', reqId: m.reqId, ok: true, value: String(tab.render(m.event)) }); }
             catch (e) { post({ type: 'renderResult', reqId: m.reqId, ok: false, error: String(e) }); } }
    } else if (m.type === 'invokeAction') {
      const a = actions[m.id];
      if (a) { try { Promise.resolve(a.onInvoke(m.exchangeId)).catch(() => {}); } catch (e) { /* ignore */ } }
      post({ type: 'actionDone', reqId: m.reqId });
    } else if (m.type === 'shutdown') {
      process.exit(0);
    }
  } catch (e) {
    post({ type: 'log', level: 'error', msg: 'host error: ' + String(e) });
  }
});

// Exit if the parent goes away (IPC channel disconnected) so we never orphan.
process.on('disconnect', () => process.exit(0));

post({ type: 'ready' });
`;
