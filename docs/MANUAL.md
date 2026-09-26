# TACNOC Operator Manual

**TACNOC v0.6.1** (`greynoc-tacnoc`, Apache-2.0) · documented **2026-09-15**

Internal alias: **Belcher**. The on-disk database filename (`belcher.db`) and the project export
format tag (`greynoc-belcher-project`) are deliberately frozen under that older name so existing
projects keep opening after the rename (`CHANGELOG.md:587-591`).

---

### How to read this document

Every command, flag, file path, config key, function name, default value, panel name, environment
variable and limit in this manual was read out of the v0.6.1 source tree and is cited as
`file:line`. **Those citations will drift.** They are accurate against the tree as it stood on
2026-09-15 at version 0.6.1; treat a mismatched line number as a signal to re-read, not as proof
the behaviour changed.

Three conventions used throughout:

- **"Not found in tree"** means exactly that — searched for, absent. It is a result, not an
  omission. Section [16](#16-unverified-absent-and-contradictory) collects every one of them.
- A **> blockquote** marks a trap: a place where the tool does less than its label, its own
  documentation, or your intuition suggests.
- Where this manual and another file in the repo disagree, the disagreement is named and the
  code citation wins. Several in-tree documents are stale in ways that would cost you real time;
  they are listed in [16.3](#163-in-tree-statements-that-are-wrong).

This manual does not replace the focused documents under `docs/`. It links to them rather than
restating them. See [Appendix A](#appendix-a-documentation-map).

---

## Table of contents

- [1. Orientation](#1-orientation)
  - [1.1 What TACNOC is](#11-what-tacnoc-is)
  - [1.2 The authorized-use boundary](#12-the-authorized-use-boundary)
  - [1.3 What TACNOC deliberately does not contain](#13-what-tacnoc-deliberately-does-not-contain)
  - [1.4 Read this first: the six things that surprise people](#14-read-this-first-the-six-things-that-surprise-people)
  - [1.5 Architecture in one page](#15-architecture-in-one-page)
- [2. Installation, build, and running](#2-installation-build-and-running)
  - [2.1 Requirements](#21-requirements)
  - [2.2 First-time setup](#22-first-time-setup)
  - [2.3 Running in development](#23-running-in-development)
  - [2.4 Building the MCP server](#24-building-the-mcp-server)
  - [2.5 Which scripts mutate your working tree](#25-which-scripts-mutate-your-working-tree)
  - [2.6 Production build and packaged artifacts](#26-production-build-and-packaged-artifacts)
  - [2.7 SBOM and checksums](#27-sbom-and-checksums)
  - [2.8 The release pipeline and its gates](#28-the-release-pipeline-and-its-gates)
  - [2.9 What the quality gate does not cover](#29-what-the-quality-gate-does-not-cover)
  - [2.10 Tests](#210-tests)
- [3. First run](#3-first-run)
  - [3.1 Create or adopt a project](#31-create-or-adopt-a-project)
  - [3.2 Install the CA and prove interception works](#32-install-the-ca-and-prove-interception-works)
  - [3.3 Arm the engagement](#33-arm-the-engagement)
- [4. Projects and storage](#4-projects-and-storage)
  - [4.1 What a project is](#41-what-a-project-is)
  - [4.2 On-disk layout](#42-on-disk-layout)
  - [4.3 The SQLite WASM layer](#43-the-sqlite-wasm-layer)
  - [4.4 Schema and migrations](#44-schema-and-migrations)
  - [4.5 The blob store](#45-the-blob-store)
  - [4.6 What is encrypted at rest and what is not](#46-what-is-encrypted-at-rest-and-what-is-not)
  - [4.7 The secret store and the cross-context trap](#47-the-secret-store-and-the-cross-context-trap)
  - [4.8 Concurrency: the two-writers risk](#48-concurrency-the-two-writers-risk)
  - [4.9 Deletion behaviour](#49-deletion-behaviour)
  - [4.10 Import and export](#410-import-and-export)
  - [4.11 Backup and handling](#411-backup-and-handling)
  - [4.12 The workspace reader](#412-the-workspace-reader)
- [5. Scope and authorization](#5-scope-and-authorization)
  - [5.1 The four mechanisms](#51-the-four-mechanisms)
  - [5.2 Authorization](#52-authorization)
  - [5.3 The scope data model and decision procedure](#53-the-scope-data-model-and-decision-procedure)
  - [5.4 Host, scheme, port and path matching](#54-host-scheme-port-and-path-matching)
  - [5.5 Normalization and the enabled divergence](#55-normalization-and-the-enabled-divergence)
  - [5.6 Where scope is enforced and where it is not](#56-where-scope-is-enforced-and-where-it-is-not)
  - [5.7 Engagement identity](#57-engagement-identity)
  - [5.8 Preflight](#58-preflight)
- [6. The proxy and TLS interception](#6-the-proxy-and-tls-interception)
  - [6.1 Reference card](#61-reference-card)
  - [6.2 The listener](#62-the-listener)
  - [6.3 Plain HTTP](#63-plain-http)
  - [6.4 CONNECT and TLS interception](#64-connect-and-tls-interception)
  - [6.5 The project CA](#65-the-project-ca)
  - [6.6 No CA, or an untrusted CA](#66-no-ca-or-an-untrusted-ca)
  - [6.7 Guided CA setup](#67-guided-ca-setup)
  - [6.8 How interception is verified](#68-how-interception-is-verified)
  - [6.9 HTTP/2 and HTTP/3](#69-http2-and-http3)
  - [6.10 WebSockets](#610-websockets)
  - [6.11 Interception: edit, forward, drop](#611-interception-edit-forward-drop)
  - [6.12 Timeouts and connection handling](#612-timeouts-and-connection-handling)
  - [6.13 What the proxy does not do](#613-what-the-proxy-does-not-do)
  - [6.14 Recovery: this project cannot be opened](#614-recovery-this-project-cannot-be-opened)
- [7. The workbench tools](#7-the-workbench-tools)
  - [7.1 Which tools touch the network](#71-which-tools-touch-the-network)
  - [7.2 Repeater](#72-repeater)
  - [7.3 Passive scanner](#73-passive-scanner)
  - [7.4 Sequencer](#74-sequencer)
  - [7.5 Encoder and Decoder](#75-encoder-and-decoder)
  - [7.6 Compare](#76-compare)
  - [7.7 Target map](#77-target-map)
  - [7.8 Analysis: surface ranking, proof, hunt memory](#78-analysis-surface-ranking-proof-hunt-memory)
- [8. Automation: the Variation engine and its limits](#8-automation-the-variation-engine-and-its-limits)
  - [8.1 Modes and counts](#81-modes-and-counts)
  - [8.2 Payload sources](#82-payload-sources)
  - [8.3 Rate limiting, precisely](#83-rate-limiting-precisely)
  - [8.4 The per-job cap and the absolute ceiling](#84-the-per-job-cap-and-the-absolute-ceiling)
  - [8.5 Every other validated limit](#85-every-other-validated-limit)
  - [8.6 Scope enforcement at two points](#86-scope-enforcement-at-two-points)
  - [8.7 Result rows](#87-result-rows)
  - [8.8 Control, audit, and emergency stop](#88-control-audit-and-emergency-stop)
  - [8.9 The dead automation settings](#89-the-dead-automation-settings)
- [9. The user interface](#9-the-user-interface)
  - [9.1 Window anatomy](#91-window-anatomy)
  - [9.2 Traffic views](#92-traffic-views)
  - [9.3 Intercept](#93-intercept)
  - [9.4 Findings](#94-findings)
  - [9.5 Engagement](#95-engagement)
  - [9.6 Supporting views](#96-supporting-views)
  - [9.7 Settings](#97-settings)
  - [9.8 Exporting, and what redacted covers](#98-exporting-and-what-redacted-covers)
- [10. The MCP server](#10-the-mcp-server)
  - [10.1 What it is](#101-what-it-is)
  - [10.2 The hand-rolled transport](#102-the-hand-rolled-transport)
  - [10.3 Building it](#103-building-it)
  - [10.4 Registering it with a client](#104-registering-it-with-a-client)
  - [10.5 Tool reference](#105-tool-reference)
  - [10.6 The registry test that fails on purpose](#106-the-registry-test-that-fails-on-purpose)
  - [10.7 Adding a tool](#107-adding-a-tool)
- [11. The AI mesh](#11-the-ai-mesh)
  - [11.1 Default state](#111-default-state)
  - [11.2 Exactly what data leaves the machine](#112-exactly-what-data-leaves-the-machine)
  - [11.3 The egress acknowledgement](#113-the-egress-acknowledgement)
  - [11.4 Redaction before send](#114-redaction-before-send)
  - [11.5 Provider configuration](#115-provider-configuration)
  - [11.6 The tool registry](#116-the-tool-registry)
  - [11.7 Budget, audit, abort](#117-budget-audit-abort)
  - [11.8 Run bounds and role permissions](#118-run-bounds-and-role-permissions)
  - [11.9 Limitations](#119-limitations)
- [12. The Extension SDK](#12-the-extension-sdk)
  - [12.1 The extension model](#121-the-extension-model)
  - [12.2 Loading](#122-loading)
  - [12.3 Manifest reference](#123-manifest-reference)
  - [12.4 Permissions and the API surface](#124-permissions-and-the-api-surface)
  - [12.5 Lifecycle](#125-lifecycle)
  - [12.6 What an extension can and cannot reach](#126-what-an-extension-can-and-cannot-reach)
  - [12.7 The data an extension sees](#127-the-data-an-extension-sees)
  - [12.8 Identifiers and namespacing](#128-identifiers-and-namespacing)
  - [12.9 A minimal worked example](#129-a-minimal-worked-example)
  - [12.10 Security considerations](#1210-security-considerations)
  - [12.11 Maturity](#1211-maturity)
- [13. Safety and limits](#13-safety-and-limits)
- [14. Reference](#14-reference)
  - [14.1 npm scripts](#141-npm-scripts)
  - [14.2 Configuration keys and defaults](#142-configuration-keys-and-defaults)
  - [14.3 Constants and caps](#143-constants-and-caps)
  - [14.4 The 19 transforms](#144-the-19-transforms)
  - [14.5 The 8 MCP tools](#145-the-8-mcp-tools)
  - [14.6 The 30 AI mesh tools](#146-the-30-ai-mesh-tools)
  - [14.7 The 11 passive checks](#147-the-11-passive-checks)
  - [14.8 IPC and event surface](#148-ipc-and-event-surface)
  - [14.9 Environment variables](#149-environment-variables)
  - [14.10 File and directory map](#1410-file-and-directory-map)
- [15. Troubleshooting](#15-troubleshooting)
- [16. Unverified, absent, and contradictory](#16-unverified-absent-and-contradictory)
- [Appendix A: Documentation map](#appendix-a-documentation-map)
- [Appendix B: Audit action catalogue](#appendix-b-audit-action-catalogue)
- [Appendix C: Verification method](#appendix-c-verification-method)

---

## 1. Orientation

### 1.1 What TACNOC is

TACNOC is a local-first intercepting-proxy workbench for web application security testing. It is
an Electron desktop application over a UI-independent, Electron-free TypeScript engine. The engine
captures HTTP/1.1, HTTP/2 and WebSocket traffic through a loopback proxy with a per-project TLS
interception CA, stores it in a per-project encrypted SQLite database, and exposes a set of
analysis tools — Repeater, Variation, Sequencer, Encoder/Decoder, Compare, Target Map, a passive
scanner — over that captured traffic.

Size and shape of the codebase, as of v0.6.1:

| Area | Lines | Files |
|---|---|---|
| `src/engine` | ~14,600 | 50 |
| `src/renderer` | ~5,505 | 23 |
| `test` | ~8,179 | 38 |
| `src/mcp` | 637 | 3 |
| `src/main` | 584 | 3 |

Three runtime dependencies, exactly: `@anthropic-ai/sdk`, `node-forge`, `node-sqlite3-wasm`.
SQLite is WebAssembly, the CA is pure JavaScript, so there is no native build toolchain and no
`node-gyp` step. Node ≥ 22.12 is required; the project is developed against Node 24.

There are four ways to drive it, and they have materially different safety properties:

| Surface | Can emit packets to a target? | Scope-gated? |
|---|---|---|
| The desktop UI (proxy, Repeater, Variation) | Yes | Variation only |
| The engine API, embedded in your own Node code | Yes | Variation only |
| The **MCP server** (`src/mcp`) | **No — architecturally incapable** | n/a |
| The **AI mesh** (`src/engine/ai`) | Yes, via Repeater and Variation | Yes, at the tool boundary |

### 1.2 The authorized-use boundary

TACNOC intercepts TLS by minting certificates from a CA you install into a trust store. That is
the capability the entire tool is built around, and it is the capability that makes unauthorized
use of it a serious act. Three statements the product makes about itself, each backed by code:

1. **It never modifies an OS trust store for you.** `src/engine/ca/installInstructions.ts` renders
   a command string with your saved certificate path quoted for the target shell
   (`installInstructions.ts:55-59`) and hands it to you. The module is explicit that it returns a
   command rather than running one (`:10-14`). You run it; you own the consequence.
2. **Every install guide ships its removal command in the same step.** The guide struct requires
   one (`installInstructions.ts:37-38`, rationale at `:16-18`) and the UI renders it beside the
   install command (`CertificateView.tsx:274-282`). Run it when the engagement ends.
3. **Scope is fail-closed and starts empty.** A new project is in scope for nothing
   (`emptyScope()`, `src/shared/scope.ts:64-66`). Automated generation refuses to run against a
   destination that is not explicitly included.

What the product does *not* claim, and you should not either:

- Scope does not gate the proxy or the human-driven Repeater. See [5.6](#56-where-scope-is-enforced-and-where-it-is-not).
- Preflight `ready` gates nothing mechanically. See [5.8](#58-preflight).
- An authorization reference is free text stored in two places and enforced nowhere. See
  [5.2](#52-authorization).

The tool records; it does not authorize. Authorization lives in your engagement paperwork.

### 1.3 What TACNOC deliberately does not contain

Each row is an absence verified by search, with the citation that documents the gap.

| Absent | Evidence |
|---|---|
| Upstream proxy / SOCKS / proxy chaining | `grep -rniE "upstreamproxy\|socks\|HTTPS?_PROXY" src/` returns nothing; `docs/capability-matrix.md:12` |
| Transparent / invisible proxy mode | `docs/capability-matrix.md:12` |
| HTTP/3 / QUIC interception | `docs/certificate-management.md:88`; `README.md:188-191` |
| Active vulnerability scanner, active crawling, content discovery | `README.md:183`; `docs/capability-matrix.md:11`, `:19` |
| Proxy-level match-and-replace rule engine | `docs/capability-matrix.md:13`; `README.md:183-186` |
| Editable WebSocket message repeater / interceptor | `README.md:183-185`; `docs/capability-matrix.md:14` |
| Automated live token harvesting / generation loop | `docs/capability-matrix.md:18` |
| Report generator, sanitized findings export, issue-tracker sync | `docs/capability-matrix.md:22`, `:44-45`; `grep exportReport\|generateReport\|reportExport\|sanitizedReport src/` returns nothing |
| Bundled wordlists, injection payloads, credential lists | `payloads.ts:4-6`; `src/shared/variation.ts:1-8` — the one built-in set is 17 benign structural values |
| A "none-alg" or signature-bypass JWT helper | `src/engine/transforms/codec.ts:8-10`, stated as a deliberate omission |
| Telemetry, analytics, update check, network log sink | `SECURITY.md:12-13`; `src/engine/logging/logger.ts:6-7` |
| A command-line interface | `package.json` declares no `bin` key |
| A UI path to load any extension other than the bundled example | no `loadExtension` IPC channel; `src/shared/ipc.ts:155-156` |
| A permission-approval dialog for extensions | no `approve`/`grant` dialog anywhere in `src/renderer/src/` |
| Code signing configuration | `electron-builder.yml:4-7`; `RELEASE.md:88-116` — intentional, see [2.8](#28-the-release-pipeline-and-its-gates) |

### 1.4 Read this first: the six things that surprise people

1. **The proxy captures everything, in scope or not, and forwards it.** `evaluateScope` runs on
   every proxied request but only to stamp an `inScope` flag (`proxyServer.ts:396`, `:409`). There
   is no refusal branch. The proxy is an observation instrument, not a containment boundary.
2. **The Repeater is not scope-gated and is not audited.** `repeater.ts:7-8` says so in its own
   header. A hand-typed request to any host on the internet will be sent, recorded as
   `inScope: false`, and produce no audit row.
3. **EMERGENCY STOP does not stop the proxy.** It halts Variation jobs, drops the intercept queue,
   and aborts AI runs (`session.ts:736-745`). The listener stays bound and keeps proxying. To stop
   traffic, toggle the Proxy chip.
4. **"HTTPS interception working" is a lifetime count, not live state.** It is
   `COUNT(*) WHERE scheme='https' AND source='proxy'` over the whole project
   (`historyRepo.ts:219-224`). One decrypted exchange from last week keeps it green forever —
   including after you uninstall the CA.
5. **The project export is raw.** Full captured headers and bodies, base64, in plain JSON
   (`projectStore.ts:187-244`). Redaction covers logs and findings evidence, not the export. Two
   in-tree documents claim otherwise; both are wrong ([16.3](#163-in-tree-statements-that-are-wrong)).
6. **The AI mesh is the only third-party egress path, and redaction is off by default.**
   `redactBeforeSend` defaults to `false` (`ai.ts:207`), and even when on it wraps tool *results*
   only — the prompts, which carry your authorization reference and CA fingerprint, are never
   redacted.

### 1.5 Architecture in one page

```
  ┌──────────────── Electron main (src/main, 584 ln) ────────────────┐
  │  app.setName('TACNOC')  ·  90 IPC methods  ·  17 pushed events   │
  │  ElectronSecretStore (safeStorage)  ·  native dialogs            │
  └───────────────┬──────────────────────────────┬───────────────────┘
      contextBridge│ invoke/onEvent only          │
  ┌───────────────▼──────────────┐   ┌────────────▼───────────────────┐
  │ Renderer (React, sandboxed)  │   │ Engine (src/engine, Electron-  │
  │ 16 views, no Node, CSP-locked│   │ free TypeScript)               │
  └──────────────────────────────┘   │  proxy/   ca/    scope/        │
                                     │  repeater/ variation/ scanner/ │
  ┌──────────────────────────────┐   │  storage/ crypto/ analysis/    │
  │ MCP server (src/mcp, 637 ln) │   │  ai/ (the only egress path)    │
  │ stdio JSON-RPC, 8 pure tools │   └──────────┬─────────────────────┘
  │ NO project, NO packets       │              │
  └──────────────────────────────┘   ┌──────────▼─────────────────────┐
                                     │ Extension host (src/sdk)        │
  ┌──────────────────────────────┐   │ forked child, vm context,       │
  │ <name>.tacnocproj/           │◄──┤ scrubbed env, IPC-only bridge   │
  │  belcher.db  blobs/  ca.pem  │   └─────────────────────────────────┘
  │  secrets.enc.json            │
  └──────────────────────────────┘
```

`ARCHITECTURE.md` is the longer version and is accurate except on one point — see
[16.3](#163-in-tree-statements-that-are-wrong).

---

## 2. Installation, build, and running

Everything in this section was read out of `package.json`, `electron-builder.yml`,
`electron.vite.config.ts`, `.npmrc`, `tsconfig*.json`, the two `.github/workflows/` files, and
`scripts/`.

### 2.1 Requirements

| Requirement | Source |
|---|---|
| Node.js ≥ 22.12.0 | `package.json:10-12` (`"engines": { "node": ">=22.12.0" }`) |
| npm (for `npm ci` / `npm install`) | `.npmrc`; `.github/workflows/ci.yml:36,58,80` |
| Windows, macOS, or Linux | `README.md:66` |
| **No** native build toolchain | `README.md:67`, `RELEASE.md:427` — SQLite is WASM, the CA is pure JS |
| A display (for `npm run test:e2e` only) | `playwright.config.ts:6`; `test/e2e/smoke.spec.ts:5` |

> **`engines` is advisory, not enforced.** `.npmrc` is five lines and sets only
> `save-exact=false`, `audit=true`, `fund=false`. There is no `engine-strict=true` anywhere in the
> tree, so an older Node prints a warning and installs anyway. CI pins `node-version: '22'`
> (`ci.yml:34`, `release.yml:32` — line 33 is `cache: npm`).

Installed tool versions in the reference working copy: `electron` 43.2.0, `electron-builder`
26.15.3, satisfying the `^43.1.1` / `^26.15.3` ranges at `package.json:52-53`. The workstation ran
Node v24.14.1 / npm 11.11.0.

### 2.2 First-time setup

```bash
npm install            # developer setup (CONTRIBUTING.md:24)
npm ci                 # reproducible install from the lockfile — what CI uses
```

`SECURITY.md:55-56` and `RELEASE.md:424` state the rule: `package-lock.json` pins the tree and CI
uses `npm ci`. Both CI jobs and every release matrix leg run `npm ci` (`ci.yml:36,58,80`;
`release.yml:34`).

There are **no** `preinstall` / `postinstall` / `prepare` lifecycle scripts. The scripts block at
`package.json:13-36` contains exactly the 22 named scripts in [14.1](#141-npm-scripts) and nothing
else, so install runs none of the project's own code.

### 2.3 Running in development

```bash
npm run dev            # electron-vite dev — launches the desktop app   (package.json:14)
```

`electron.vite.config.ts` defines the three bundles it drives: main from `src/main/index.ts`
(line 17); preload from `src/preload/index.ts` emitted as **CommonJS `.cjs`** — the comment at
line 27 reads "Sandboxed preloads must be CommonJS; emit .cjs so it loads correctly" (lines 25-29);
and the renderer rooted at `src/renderer` with `index.html` as input (lines 32-45). Path aliases
`@shared` / `@engine` / `@sdk` (lines 5-9) are duplicated in `tsconfig.json:22-26` and
`vitest.config.ts:5-11`, so the same import specifiers resolve under the bundler, `tsc`, and
Vitest.

**How dev and production differ at runtime.** `src/main/index.ts:99-104` branches on
`process.env['ELECTRON_RENDERER_URL']`: if set, the main window does `loadURL(rendererUrl)`;
otherwise `loadFile(path.join(__dirname, '../renderer/index.html'))`. The same variable gates the
`will-navigate` allowlist at `:94-96`. It is read twice in this tree and **set nowhere in it** —
electron-vite supplies it in `dev`.

To preview a production bundle instead:

```bash
npm run build          # npm run typecheck && electron-vite build   (package.json:15)
npm run start          # electron-vite preview                      (package.json:17)
```

`npm run build` writes `out/main/index.js`, `out/preload/index.cjs`, and `out/renderer/`
(`index.html` + `assets/`), entry names from `electron.vite.config.ts:17,28,43`. `package.json:9`
points `main` at `out/main/index.js`, which is why packaging requires a prior build
(`electron-builder.yml:17-18`).

### 2.4 Building the MCP server

```bash
npm run build:mcp      # tsc -p tsconfig.mcp.json  →  out/mcpsrv/    (package.json:16)
```

This is a **second, independent** compile. The root `tsconfig.json` is `"noEmit": true` (line 28)
because electron-vite bundles the app; the MCP server is spawned by an external client as a plain
Node process and needs real emitted ESM (`tsconfig.mcp.json` `$comment`, lines 3-6;
`docs/mcp-server.md:36-37`). `tsconfig.mcp.json` sets `module`/`moduleResolution: NodeNext`
(lines 19-20), `rootDir: src` (34), `outDir: out/mcpsrv` (35), and includes only
`src/mcp/**/*.ts` (41). With `rootDir: src`, `src/mcp/index.ts` emits to
`out/mcpsrv/mcp/index.js` — exactly the path `.mcp.json:19` registers.

`out/` is gitignored (`.gitignore:8`), so this must be run once after cloning and again after
touching `src/mcp` or the engine modules it imports (`.mcp.json:11-13`; `docs/mcp-server.md:43-44`).

> **`build:mcp` is in no build, no gate, and no workflow.** `npm run build` and `npm run ci` omit
> it, and `grep -rn "build:mcp" .github/` returns nothing — so `out/mcpsrv/` is never produced in
> CI and a break there ships silently. `npm run typecheck` does type-check the same sources
> (`tsconfig.json:31` includes `src/**/*.ts`) but under `"moduleResolution": "Bundler"`
> (`tsconfig.json:5`) rather than `NodeNext` (`tsconfig.mcp.json:20`). **Whether typecheck catches
> a NodeNext-only resolution break is not stated anywhere in the tree** — run `build:mcp` to be
> sure. `tsconfig.mcp.json:12-15` notes the extensions are already explicit today, which is why it
> currently works.

The unit suite does not need it either: `test/mcp/mcpServer.test.ts` imports
`../../src/mcp/protocol.js` and `../../src/mcp/tools.js` directly (lines 15-16).

### 2.5 Which scripts mutate your working tree

Read this before running anything on a tree that holds work in progress.

| Script | Effect on the working tree |
|---|---|
| `typecheck`, `lint`, `format:check`, `audit`, `ci`, `test`, `test:watch` | **Read-only** |
| `test:coverage` | Writes `coverage/` (gitignored, `.gitignore:18`) |
| `test:e2e` | Writes `playwright-report/`, `test-results/` (`.gitignore:19-20`); specs create and `fs.rm` temp dirs under `os.tmpdir()` (`packaged.spec.ts:51,98`) |
| `build`, `build:mcp`, `start` | Write `out/` (gitignored, `.gitignore:8`) |
| `format`, `lint:fix` | **Rewrite tracked source files in place.** The only two that modify committed code |
| `sbom` | **Overwrites `sbom.json` at the repo root** (`scripts/generate-sbom.mjs:88-89`) |
| `dist`, `dist:dir`, `dist:linux` | Write into `dist/`; **do not clean it first** |
| `dist:win` | **Deletes the entire `dist/` directory** (`rmSync(dist, {recursive:true, force:true})`, `scripts/package-windows.mjs:78`) before building |
| `checksums` | Writes `dist/SHA256SUMS-<os>.txt`; exits 1 if `dist/` is missing (`checksums.mjs:20-23`) or holds no distributable (44-47) |
| `release:prepare` | Mutates only `sbom.json` (it is `ci` + `audit` + `sbom`) |
| `dev` | Full on-disk side effects **not determined** — establishing them requires running the app. What the code says: `src/main/index.ts:40` pins `app.setName('TACNOC')` before any userData path resolves, and `:50` resolves an AI secret store at `path.join(app.getPath('userData'), 'ai-secrets')` |

> **`npm run dist` and `npm run dist:dir` have no `package.json` guard.** Only the two per-OS
> scripts snapshot `package.json` before packaging and restore it afterwards, on success or
> failure, because electron-builder "has been observed writing that over the source file, deleting
> `scripts` and `devDependencies` outright" (`scripts/package-windows.mjs:40-66`,
> `scripts/package-linux.mjs:39-65`). `package.json:30,33` call `electron-builder` directly, and
> `release.yml:76` uses bare `npm run dist` — so the guard never runs in CI either.

### 2.6 Production build and packaged artifacts

```bash
npm run dist        # build + electron-builder → dist/ (host platform's targets)
npm run checksums   # dist/SHA256SUMS-<os>.txt
```

Packaging config is `electron-builder.yml`: `appId: com.greynoc.tacnoc` (9),
`productName: TACNOC` (10), `copyright: GreyNOC (authorized security research)` (11), output `dist`
(14), build resources dir `build` (15 — **no `build/` directory exists in this tree**; it is also
gitignored at `.gitignore:11`). Packaged `files` is `out/**/*` plus `package.json`, excluding
`**/*.map` (19-22).

Two packaging details are load-bearing, both documented in the file itself:

- **`asarUnpack: node_modules/node-sqlite3-wasm/**`** (31-32, comment 29-30) — the `.wasm` asset is
  read from the filesystem at runtime and cannot live inside the asar archive.
- **`extraResources: examples/extensions → examples/extensions`** (25-27, comment 24) — resolved
  via `process.resourcesPath` when packaged. The branch is `src/main/ipc.ts:33-41`:
  `return app.isPackaged ? packaged : devPath;` (line 40).

#### Targets per platform

| Platform | Targets | Artifact name pattern | Source |
|---|---|---|---|
| Windows | `nsis`, `portable`, both x64 | `TACNOC-<version>-Setup-x64.exe`, `TACNOC-<version>-Portable-x64.exe` | `electron-builder.yml:34-53` |
| macOS | `dmg`, `zip` | no `artifactName` configured — electron-builder's default applies; **the default pattern is not stated anywhere in this tree** | `electron-builder.yml:55-59` |
| Linux | `AppImage`, `tar.gz` | `TACNOC-<version>-linux-<arch>.<ext>` | `electron-builder.yml:62-66` |

There are three Windows-relevant `artifactName` keys: a `win:`-level default
`${productName}-${version}-${arch}.${ext}` (40), overridden by `nsis.artifactName` (48) and
`portable.artifactName` (53). Both emit `.exe`, so without the overrides "they collide on one
filename in dist/" (comment, 42-43). Portable extracts to a stable per-version directory under
`%TEMP%` via `unpackDirName: TACNOC-${version}` (51-52). NSIS is `oneClick: false`,
`perMachine: false`, `allowToChangeInstallationDirectory: true` (45-47).

Packaged executable paths, as `test/e2e/packaged.spec.ts:29-34` looks for them:

```
dist/win-unpacked/TACNOC.exe
dist/linux-unpacked/greynoc-tacnoc
dist/mac/TACNOC.app/Contents/MacOS/TACNOC
dist/mac-arm64/TACNOC.app/Contents/MacOS/TACNOC
```

> **The Linux executable is `greynoc-tacnoc`, not `tacnoc`** — it is named from the package `name`,
> not `productName`. `scripts/package-linux.mjs:94-103` reads it out of the built payload rather
> than hardcoding it (`EXE_FALLBACK = 'greynoc-tacnoc'`, line 99), with a comment recording that
> the message "used to print `./tacnoc`, which names a file that is not in the archive" (95-98).
> **`electron-builder.yml:71` still tells you to extract and run `./tacnoc`** — the exact wrong
> name that `package-linux.mjs` exists to correct. Follow `RELEASE.md:43-46` and the script.

#### AppImage cannot be built on Windows

`electron-builder.yml:68-72`, `scripts/package-linux.mjs:11-20` and `RELEASE.md:50-57` all agree:
AppImage packaging creates symlinks inside the image, Windows refuses those without Developer Mode
or elevation, and the build dies with `EPERM`. `tar.gz` cross-builds from any host. A bare
`npm run dist` on Windows does not attempt AppImage — AppImage is a `linux:` target, reached only
with `--linux`, which is why `release.yml` can run a plain `npm run dist` on every matrix leg
(`RELEASE.md:59-66`).

#### Per-OS one-shot scripts

```bash
npm run dist:win     # clean dist/ → build → nsis + portable → checksums
npm run dist:linux   # build → linux tar.gz x64
```

`scripts/package-windows.mjs` **refuses to run on a non-Windows host** (`process.platform !== 'win32'`
→ exit 1, 26-32), pins the target list as `npx --no-install electron-builder --win nsis portable`
(89) so its intent survives edits to the YAML (comment 86-87), runs `checksums.mjs` itself (93),
and exits 1 if fewer than two `.exe` files were produced (104-107).

`scripts/package-linux.mjs` runs `npx electron-builder --linux tar.gz --x64` (78), prints a note
when run from Windows explaining the AppImage omission (69-74), and exits 1 if no `.tar.gz`
appeared (85-88). It does **not** run `checksums` — run `npm run checksums` afterwards.

> **Ordering hazard.** `dist:win` deletes everything in `dist/` before it starts, so running it
> *after* `dist:linux` destroys the Linux archive you just built — and the checksum manifest is
> then rewritten without it, so nothing complains. **Build Windows first, Linux second**
> (`RELEASE.md:36-40`).

> **`packaged.spec.ts` will silently exercise a stale binary.** It searches
> `$TACNOC_PACKAGE_DIR`, then `dist`, then `release` (line 35) and auto-skips only when it finds
> nothing (48). `RELEASE.md:188-190` records this happening on a real cut: for v0.5.4
> "`packaged.spec.ts` ran here against the `dist/` already on disk — the v0.5.2 local build;
> nothing was packaged for 0.5.4 on this host". In the reference working copy `dist/` holds
> **v0.5.1** and `release/` holds **v0.4.x**, against source at **0.6.1**. Either run `dist:win`
> (which wipes `dist/` first) or set `TACNOC_PACKAGE_DIR`.

### 2.7 SBOM and checksums

**SBOM** — `npm run sbom` runs `scripts/generate-sbom.mjs`, a self-contained CycloneDX **1.5**
generator that reads `package-lock.json` (v2/v3 with a `packages` map required, else exit 1 —
24-27) and writes `sbom.json` at the repo root (88-89).

- `electron` is a `devDependency` but is the **shipped runtime**, so it is force-included via
  `packagedRuntimeDevDependencies = new Set(['electron'])` (19, applied 43-44) and scoped
  `required` rather than `optional` (55).
- `--dev` includes the rest of devDependencies; the default is production plus that packaged
  runtime (7, 16, 91).
- **No wall-clock timestamp** is emitted — line 76: "no wall-clock timestamp — keeps the SBOM
  reproducible for a given lockfile". The `serialNumber` is a SHA-256 over the component list (68).

> **The SBOM in the tree is stale in two independent ways**, and because there is deliberately no
> timestamp there is nothing in the file to tell you how old it is. It records
> `metadata.component.version: "0.5.1"` against `package.json`'s 0.6.1, and `electron@43.1.1`
> against the 43.2.0 actually installed. Check the version field; regenerate at cut time. Its 10
> components: `@anthropic-ai/sdk`, `@babel/runtime`, `@stablelib/base64`, `electron`,
> `fast-sha256`, `json-schema-to-ts`, `node-forge`, `node-sqlite3-wasm`, `standardwebhooks`,
> `ts-algebra`.

**Checksums** — `npm run checksums` runs `scripts/checksums.mjs`: SHA-256 over every file in
`dist/` matching `/\.(exe|dmg|zip|AppImage|tar\.gz|deb|rpm)$/i` (32), skipping
`/^(builder-debug|builder-effective-config)/i` (33), writing `dist/SHA256SUMS-<os>.txt` where
`<os>` is `windows` / `macos` / `linux` from `process.platform` (25-26). Lines are
`` `${hash}  ${name}` `` — hash, **two spaces**, name (41).

- `latest*.yml` and `.blockmap` are **excluded** — electron-builder emits them for its
  auto-updater, this app ships no updater, so they are not distributed and "must not appear in a
  checksum manifest for files no one can download" (28-31).
- The per-OS filename exists because the release job downloads all three matrix legs' artifacts
  into one flat set, and three files named `SHA256SUMS.txt` would collide (6-9).

> **The `<os>` names the build host, not the target.** The reference tree's
> `dist/SHA256SUMS-windows.txt` contains three lines covering both `.exe` files **and** the
> cross-built `TACNOC-0.5.1-linux-x64.tar.gz`. There is no `SHA256SUMS-linux.txt` and there should
> not be (`RELEASE.md:295-301`).

Note on the old `release/` folder: `release/SHA256SUMS.txt` is flat-named (pre-dating the per-OS
change) and uses the `hash *filename` binary-marker form, not the two-space form `checksums.mjs:41`
emits. It was not written by the current script. Treat it as history.

### 2.8 The release pipeline and its gates

#### Pre-release checklist (`RELEASE.md:7-21`)

1. **Security review** of the diff since the last tag — scope gate, redaction, CA/secret handling,
   at-rest encryption, extension isolation still intact.
2. **Quality gate:** `npm run ci` green, plus `npm run test:e2e` on a machine with a display.
3. **Dependency audit:** `npm run audit` — full tree, high+.
4. **SBOM:** `npm run sbom`.
5. **Version + changelog:** bump `version` in `package.json`; move items from *Unreleased* into the
   new version in `CHANGELOG.md`.
6. **Tag:** commit, `git tag vX.Y.Z`, push the tag.

> **`npm run release:prepare` is not the full gate.** It is `ci` + `audit` + `sbom`
> (`package.json:35`); it does **not** run `test:e2e`, and `RELEASE.md:73-86` declares the
> packaged-artifact E2E run mandatory — "Do not cut a release without this passing" (86).

#### The mandatory packaged-artifact gate

After `npm run dist`, run `npm run test:e2e`. `test/e2e/packaged.spec.ts` drives the **packaged
binary** and is the only thing that exercises:

- SQLite WASM loaded from `app.asar.unpacked` rather than `node_modules`,
- the example extension resolved via `process.resourcesPath` (the `app.isPackaged` branch),
- forking the extension host child out of a packaged Electron binary,
- the loopback-only proxy default surviving packaging.

Its assertions include `expect(result.status.loopbackOnly).toBe(true)` (91),
`expect(result.extCount).toBe(1)` (92), and a rot13 round-trip through the forked extension child —
`ext.header-hygiene.rot13` on `'Hello'` returning `'Uryyb'` (94-95). Skip message when nothing is
found: "no packaged app in dist/ or release/ — run `npm run dist:win` first" (48).

The other nine E2E tests launch the **dev bundle** at `out/main/index.js` (`smoke.spec.ts:18,40`;
`full.spec.ts:35`; `ca-setup.spec.ts:22,29`; `ai-mesh.spec.ts:16,21`; `hunt-folder.spec.ts:47,131`;
`qaqc-wiring.spec.ts:16,34,104`), so **`npm run build` is a hard prerequisite for
`npm run test:e2e`** — without it those nine fail on a missing file rather than on anything
meaningful, while the tenth skips, so a run can look mostly-green for the wrong reason.

Playwright config (`playwright.config.ts:9-16`): `testDir: './test/e2e'`, `timeout: 60000`,
`fullyParallel: false`, `workers: 1`, `reporter: [['list'], ['html', {open:'never'}]]`,
`trace: 'retain-on-failure'`.

#### `ci.yml` — on push and PR to `master` or `main`

- **`quality`** — matrix over `ubuntu-latest`, `windows-latest`, `macos-latest`, `fail-fast: false`
  (21-29). `npm ci` (36), then `format:check` (38), `lint` (40), `typecheck` (42), `npm test` (44).
  The header comment records why the matrix exists: it used to run only on ubuntu while
  `release.yml` builds on all three, so "the first time the gate ever saw Windows or macOS was on a
  pushed tag" — which cost v0.5.3 (macOS-only path assertion) and v0.5.5 (Windows-only test
  timeout) (14-20).
- **`e2e`** — `ubuntu-latest` only (49-69). `npm ci`, `npm run build`,
  `npx playwright install-deps`, then `xvfb-run -a npm run test:e2e`. `dist/` is never built here,
  so `packaged.spec.ts` skips (66-67).
- **`audit`** — `ubuntu-latest` (71-90). `npm audit --audit-level=high` invoked **directly, not via
  the npm script** (84), then `npm run sbom` (86), uploading `sbom.json` (87-90).

The workflow's own header records that the trigger said `main` while the default branch is
`master`, so "the gate this workflow exists to enforce had never run on a single push or PR"; both
branch names are now listed (3-11).

#### `release.yml` — on a `v*` tag push

`on: push: tags: ['v*']` (8-10), `permissions: contents: write` (12-13).

**`build`** — matrix `windows-latest`, `macos-latest`, `ubuntu-latest`, `fail-fast: false` (17-27):
`npm ci` (34) → `npm run ci` (36) → `npm run audit` (38) → build installers (39-76) → (Linux)
`npx playwright install-deps` (77-81) → **verify the packaged artifact** via `npm run test:e2e`,
under `xvfb-run -a` on Linux (82-93) → `npm run checksums` (94-95) → (Linux) `npm run sbom`
(96-101) → report signing status (102-109) → upload artifacts (110-122).

The packaging step is `npm run dist -- --publish never` (76). `--publish never` is explicit
because, left implicit, "electron-builder publishes on a `v*` tag by itself (it warns about
exactly this) and would race that job for the same release" (73-75).

Uploaded per leg: `dist/*.exe`, `dist/*.dmg`, `dist/*.zip`, `dist/*.AppImage`, `dist/*.tar.gz`,
`dist/SHA256SUMS-*.txt`, `sbom.json` (115-122). The SBOM is generated only on Linux because it "is
derived only from package-lock.json (identical on every OS)" and three copies would collide (96-100).

**`draft-release`** — `needs: build`, so **every** leg must pass (125). Downloads all artifacts into
`release/` (128-130) and calls `softprops/action-gh-release@v2` with `draft: true`,
`generate_release_notes: true`, `files: release/**/*` (131-136). Drafted, never auto-published.

#### Signing is an explicit operator decision

**Code signing is intentionally not configured** (`electron-builder.yml:4-7`, `RELEASE.md:88-116`).
Signing activates automatically and only when the matching repository secrets are set; with none
set, artifacts are UNSIGNED, the build does **not** fail, and the workflow emits
`::warning::No signing secrets configured — artifacts are UNSIGNED. The release is left as a
draft.` (`release.yml:102-109`).

| Purpose | Repository secrets |
|---|---|
| Windows Authenticode | `WINDOWS_CSC_LINK` (base64 .pfx), `WINDOWS_CSC_KEY_PASSWORD` |
| macOS Developer ID + notarization | `APPLE_ID`, `APPLE_APP_SPECIFIC_PASSWORD`, `APPLE_TEAM_ID` |

> **An unset GitHub secret is the empty string, not unset.** `release.yml:53-60` declares them in
> `env:` but the shell block at 61-72 exports them **per-OS**, guarded by
> `[ -n "$WINDOWS_CSC_LINK" ]` and `RUNNER_OS`. electron-builder reads `CSC_LINK` as a path to a
> certificate, and `""` resolves against the working directory and "fails with `<projectDir> not a
> file`" (44-51) — that killed the v0.5.4 macOS leg; the failure text is quoted at
> `RELEASE.md:205-207`. Moving these back into a plain `env:` block reintroduces the bug. When no
> `APPLE_ID` is set on macOS the workflow also exports `CSC_IDENTITY_AUTO_DISCOVERY=false` so
> auto-discovery does not "search the keychain and leave the build unsigned as a side effect"
> (67-72).

macOS notarization additionally needs `mac.hardenedRuntime` and `mac.notarize` enabled in
`electron-builder.yml` — both left off by default so unsigned/dev builds do not fail
(`RELEASE.md:110-111`).

What unsigned means downstream (`RELEASE.md:389-396`): Windows SmartScreen shows "Windows protected
your PC" / unknown publisher and needs an explicit *More info → Run anyway*; macOS Gatekeeper
blocks the app outright; and there is **no cryptographic proof of origin or integrity in the binary
itself** — the SHA-256 manifest is the only integrity check, "and it is only meaningful if obtained
over a channel independent of the artifact."

#### Reproducibility

`RELEASE.md:416-427`: **the builds are not bit-reproducible.** Packaging the same commit twice
produces artifacts of identical size but different SHA-256 because electron-builder embeds
build-time metadata. A recorded hash identifies *one specific build*, not "the build of this
commit" — re-cutting a release invalidates already-published hashes.

### 2.9 What the quality gate does not cover

Verified by reading the tool configurations:

- **`scripts/*.mjs` are outside every gate.** `lint` runs `eslint . --ext .ts,.tsx` — `.mjs` is not
  in the list. `format`/`format:check` glob only `src/**/*.{ts,tsx,css}` and `test/**/*.ts`
  (`package.json:21-22`). `tsconfig.json:30-37` includes `src/**`, `test/**` and three root `*.ts`
  configs. So **all five** `.mjs` files — `checksums.mjs`, `generate-sbom.mjs`, `package-linux.mjs`,
  `package-windows.mjs`, `reseal-project-secrets.mjs` — plus `scripts/secret-helper.cjs` are linted
  by nothing, formatted by nothing, and typechecked by nothing. The code that cuts releases is the
  code nothing checks.
- **`*.cjs` is in `.eslintrc.cjs`'s `ignorePatterns`** (line 44 of the list at 37-45), so
  `secret-helper.cjs` is doubly excluded.
- **Markdown, YAML and JSON are not format-checked** — no `.md`, `.yml` or `.json` in the prettier
  globs; `package-lock.json` is in `.prettierignore` (7).
- **`npm run ci` excludes E2E, audit, SBOM and `build:mcp`.** It is exactly
  `format:check && lint && typecheck && test` (`package.json:28`).
- **ESLint policy:** `--max-warnings 0` (`package.json:19`) while
  `@typescript-eslint/no-explicit-any` is `'warn'` (`.eslintrc.cjs:32`) — **one `any` fails the
  build.** The rule reads permissive in the config and behaves as an error in the gate.
- **`.gitattributes` sets `* text=auto eol=lf`** (11). Not cosmetic: Git for Windows defaults to
  CRLF checkout, prettier is pinned to `endOfLine: "lf"` (`.prettierrc.json:8`), and without the
  attribute `format:check` failed on *every* file on a Windows checkout — "Code style issues found
  in 130 files", which is how the v0.4.0 and v0.4.1 release builds died (`.gitattributes:1-10`,
  `RELEASE.md:343-351`).
- **`electron-builder.yml:74-75`** carries the comment "Emit a per-build metadata file listing
  produced artifacts." immediately above `artifactBuildCompleted: null`. The value disables the
  hook; the comment describes the opposite. Nothing in the tree resolves which was intended — do
  not rely on that hook firing.

### 2.10 Tests

`vitest.config.ts:12-20`: `globals: true`, `environment: 'node'`, `include: ['test/**/*.test.ts']`,
`pool: 'forks'`, `testTimeout: 20000`, `hookTimeout: 20000`. The fork pool and timeouts exist
because "Engine + integration tests bind loopback sockets" (16-17). Coverage (21-26) uses the `v8`
provider over `src/engine/**/*.ts`, `src/shared/**/*.ts`, `src/sdk/**/*.ts`, excluding `**/*.d.ts`,
with `text` and `html` reporters.

The Vitest suite runs **fully offline** — every fixture is a `127.0.0.1` server started in-process
(`docs/testing.md:17-19`: "if the machine had no network at all, these tests would still pass").
That guarantee is for the headless suite; `test:e2e` launches a real Electron app and is documented
separately as opt-in (`docs/testing.md:5-6,14`).

Counts: **28** `*.test.ts` files under `test/` (27 in `test/engine/`, 1 in `test/mcp/`) and **10**
declared Playwright tests across **7** spec files — both verified by enumerating the tree, matching
"28 test files / 368 tests" at `RELEASE.md:180` and "all 10 specs green" at `:186`. The 368 figure
is documented, **not measured** by this pass; `README.md:123` says to run `npm test` for the
current number.

That 20 s `testTimeout` is not academic. `CHANGELOG.md [0.5.6]` records `storage.test.ts` building
2050 exchanges one `insert` at a time — each its own durable commit, because "WAL is unsupported by
the WASM VFS" — and because the inserts are *synchronous* "the 20-second test timeout could not
even fire until the block finished: the runner reported **86,034 ms against a 20,000 ms limit**."
The fix was `HistoryRepo.insertMany` wrapping a batch in one transaction: **86,034 ms → 249 ms**
(`CHANGELOG.md:19-27`; `RELEASE.md:242-244,258`).

---

## 3. First run

Three procedures, in order. Do not skip §3.3 — an un-armed project will happily send traffic.

### 3.1 Create or adopt a project

The `Welcome` screen (`src/renderer/src/views/Welcome.tsx`) renders instead of the sidebar+main
layout whenever no project is open (`App.tsx:321-329`). It offers four entry points.

**Create a new project**

1. Fill **Project name** (defaults to `Engagement`, `Welcome.tsx:7`) and, optionally,
   **Authorization reference (optional)** — placeholder `e.g. signed SOW / engagement ID`
   (`Welcome.tsx:118-126`).
2. **`Browse…`** → native folder picker titled *"Choose a project location"* (`src/main/ipc.ts:44-51`).
3. **`Create project`**. The directory is `<location>/<sanitised-name>.tacnocproj` — name sanitised
   to `[a-zA-Z0-9._-]`, leading/trailing `-` stripped, empty names falling back to `project`; a
   path already ending in `.tacnocproj` is used as-is (`src/main/ipc.ts:300-303`).

You should then see the top bar + sidebar + `HTTP History`, with the project-name chip in the top
bar. Errors render in a red `danger-box` above the buttons (`Welcome.tsx:140`).

**`Open existing…`** — picks a directory and calls `openProject`. You may point it at the *parent*
folder: `resolveProjectDir` accepts a folder containing exactly one project, names the candidates
when it contains several, and otherwise says the folder is not a project and does not contain one
(`src/engine/project/projectStore.ts:393-421`).

**`Import export…`** — pick a target directory, then a `*.json` export; rebuilds the project there
(`src/main/ipc.ts:106-117`). Read [4.10](#410-import-and-export) first — the CA, engagement
profile, AI settings and CA history do not come back.

**`Open hunt folder…`** — adopts a folder that already holds the engagement material via its own
picker, titled *"Choose the folder your engagement material is in"* (`src/main/ipc.ts:77-83`). It
creates the project *inside* that folder, classifies the documents, and reports e.g. *"Created a
project in …. Read 14 of 20 document(s) — 2 scope, 1 engagement, 3 report, 6 recon. Check
Engagement → Proposed scope before testing anything."* (`Welcome.tsx:37-42`).

> **Choosing the hunt folder is the egress decision.** The screen says so in bold: everything
> readable in that folder becomes available to the AI and is sent to the model provider during a
> run (`Welcome.tsx:164-168`; same rationale in `session.ts:1193-1195`). Leave the mesh off and
> nothing leaves the machine.

> **`adoptHuntFolder` re-points the workspace only conditionally** — when the project directory
> differs from the folder you picked **and** the existing profile's `workspaceDir` is still blank
> (`session.ts:1222-1224`). Adopting a folder over a project that already has a workspace set
> leaves the old one in place. Check `Engagement → Engagement folder` afterwards.

### 3.2 Install the CA and prove interception works

**Screen:** `CA Certificate` (`src/renderer/src/views/CertificateView.tsx`). Four numbered steps
plus a collapsible **Certificate details** card (`:388-418`). Full mechanics in
[6.7](#67-guided-ca-setup) and [6.8](#68-how-interception-is-verified); procedure here.

This step is **optional**. Plain `http://` is captured with no certificate at all — the header
card, heading *"Read HTTPS traffic (optional)"*, says exactly that (`CertificateView.tsx:153-159`).

The status chip top-right reads `HTTPS interception working` or `HTTPS not set up`, driven by
`interceptedHttpsExchanges > 0` (`CertificateView.tsx:75`, `:161-165`).

**Step 1 — Save the certificate to a file.** Read the red `danger-box` (*"Trusting this CA is
powerful… TACNOC never modifies your operating system trust store for you."*, `:231-237`). Tick
**"I understand the risk and am authorized to intercept traffic in this environment."** — the
**`Save CA certificate to file…`** button is disabled until you do (`:238-249`). The save dialog is
titled *"Save project CA certificate"*, default filename **`greynoc-tacnoc-ca.crt`**
(`src/main/ipc.ts:158-162`). Only the public certificate is written (`ipc.ts:164`); the private key
never leaves the secret store. Saving a **revoked** project's CA is refused — *"This project has no
CA certificate — it was revoked. Issue a new one first."* — rather than writing a 0-byte file
(`ipc.ts:149-157`), and the refusal is toasted rather than swallowed (`CertificateView.tsx:117-124`).

**Step 2 — Trust it.** Greyed with *"Save the certificate first; the command below needs its
path."* until step 1 completes (`:261-264`). The commands are in
[6.7](#67-guided-ca-setup); each is rendered against your real saved path, quoted for the target
shell, with a **`Copy`** button that toasts on success *and on failure* (`:463-489`) — a silent
copy button is worse than none, because you would paste whatever was already on the clipboard into
a shell.

**Step 3 — Point your browser at the proxy.** Set **both** HTTP *and* HTTPS proxy to the address
shown — `proxyTarget`, the live listener when running and otherwise the literal `127.0.0.1:8080`
(`CertificateView.tsx:141`, rendered `:297-302`). A browser that proxies only HTTP never sends the
`CONNECT` that HTTPS interception depends on. If the proxy is stopped, this step offers a
**`Start the proxy`** button inline (`:307-327`).

**Step 4 — Check that it worked.** Browse any `https://` page in that browser. The step polls every
**3000 ms** while unverified (`VERIFY_POLL_MS`, `:31`, `:90-94`) and offers **`Check again`**
(`:360-362`). On failure the warn box names the three usual causes: browser not restarted after
install, browser keeps its own certificate store (Firefox), or only the HTTP proxy was set
(`:351-357`). On success the chip flips, a green `ok-box` appears (`:167-173`), and the guide
collapses itself; **`Show the steps anyway`** reopens it (`:80`, `:196-216`) and **`Skip for now`**
(`:373-381`) collapses it to *"Setup skipped. HTTP is still captured; HTTPS is not."*

### 3.3 Arm the engagement

1. **Create the project inside the engagement folder**, so the paperwork sits next to it — the
   engine's own example is `TiffanyCo/Tiffany.tacnocproj` next to `ENGAGEMENT.md`
   (`session.ts:228`). Record the authorization reference at creation (`createProject`'s third
   argument, `session.ts:212`).
2. **Engagement → profile:** set program, platform, handle, authorization reference, the required
   `User-Agent` and any identity headers. Turn **enforce** on — without it nothing is rewritten
   ([5.7](#57-engagement-identity)).
3. **Engagement → Proposed scope:** read candidates out of the folder, each with file, line and the
   matching line's text. Check each against the program page. Ticking an include adds it;
   **exclusions are added regardless of the ticks**, because "an exclusion the operator declines to
   add is an exclusion that silently stops applying" (`scopeProposal.ts:354-362`). An applied
   `*.host` candidate becomes `**.host` ([5.4](#54-host-scheme-port-and-path-matching)).
4. **Scope:** add or correct rules by hand. The Add form defaults `hostMatch` to `exact`
   deliberately (`ScopeView.tsx:10-14`) and never auto-detects a `*` — while its own placeholder
   reads `host e.g. example.test or *.example.test` (`:171`). Add **exclude** rules for anything
   sensitive inside the include set — logout, payment, admin.
5. **Preflight:** clear every blocker. `project`, `authorization`, `scope`, `ca-expired` and
   `proxy-bind` are the five that mean "do not start" ([5.8](#58-preflight)).
6. **Verify on the wire, not in config:** browse the target through the proxy and confirm HTTP
   History shows your target in-scope and everything else out, and that the `ca-trust` check reports
   decrypted HTTPS exchanges. Configuration saying interception is on proves nothing — that is
   exactly what the `ca-trust` check exists to catch (`preflight.ts:160-178`).
7. Only then create a Variation job or start a mesh run. Keep **EMERGENCY STOP** in reach, and know
   from [8.8](#88-control-audit-and-emergency-stop) what it does and does not halt.

---

## 4. Projects and storage

Builds on [`project-format.md`](project-format.md) — read that for the short version — and corrects
it where the code disagrees. Source of record: `src/engine/project/projectStore.ts`,
`src/engine/storage/*.ts`, `src/engine/crypto/contentCipher.ts`, `src/engine/ca/secretStore.ts`,
`src/engine/ca/certificateAuthority.ts`, `src/main/electronSecretStore.ts`,
`src/engine/workspace/workspace.ts`.

### 4.1 What a project is

A project is **a directory on disk**, conventionally suffixed `.tacnocproj`. Everything a hunt
accumulates — captured exchanges, WebSocket frames, findings, suppressions, saved Repeater
requests, the audit log, scope, engine config, the engagement profile, and the project's own TLS
interception CA — lives inside it.

`ProjectStore` ties the directory together: database, blob store, CA, and five repositories
(`history`, `meta`, `findings`, `audit`, `wsMessages`) (`projectStore.ts:66-91`, repos at `:85-90`).

A `TacnocSession` holds **at most one open project**. `createProject`, `openProject` and
`importProject` all call `closeProject()` first (`session.ts:213`, `:236`, `:1568`), and
`closeProject()` stops the proxy, emergency-stops every variation job, stops all mesh runs, and
closes the database handle (`session.ts:285-294`).

**The `.tacnocproj` suffix is a convention, not a requirement.** Nothing checks it when opening: a
directory *is* a project if it contains `belcher.db` (`ProjectStore.open` does
`fs.access(<dir>/belcher.db)` and nothing else, `projectStore.ts:116-117`; `hasProjectDb`,
`:423-430`). Two code sites *produce* the suffix, with different sanitizers:

| Site | Sanitizer | Fallback |
|---|---|---|
| `ensureProjectPath`, desktop shell (`src/main/ipc.ts:300-303`) | `/[^a-zA-Z0-9._-]+/g` → `-`; returns `dir` unchanged if it already ends in `.tacnocproj` (`:302`) | `project` |
| `adoptHuntFolder`, **engine** (`session.ts:1209`) | `sanitizeProjectName` (`session.ts:100-115`): strips control chars, maps `< > : " / ? * \| \` → `-`, strips trailing dot/space, caps at 64 chars | `Engagement` |

### 4.2 On-disk layout

```
NAME.tacnocproj/
  belcher.db            SQLite database (WASM SQLite)
  blobs/                content-addressed body store, <aa>/<bb>/<id>
  ca.pem                public project CA certificate (mode 0644)
  ca.pem.revoked.json   present only after a CA revoke (mode 0600)
  secrets.enc.json      safeStorage-sealed secrets — Electron app only (mode 0600)
  secrets.json          file-fallback secret store — headless/library use only (mode 0600)
  secrets.key           32-byte master key for secrets.json, SAME DIRECTORY (mode 0600)
```

- `belcher.db` — `DB_FILE`, `projectStore.ts:36`.
- `blobs/` — `BLOBS_DIR`, `:37`; layout `<root>/<id[0:2]>/<id[2:4]>/<id>`, `blobStore.ts:31-33`.
- `ca.pem` — `CA_FILE`, `:38`; mode `0o644` by `persist()` (`certificateAuthority.ts:208`, and the
  standalone `persistCaMaterial` helper, `:102`).
- `ca.pem.revoked.json` — path built `certificateAuthority.ts:110`, written mode `0o600` `:113`.
  Its presence is what stops a reopen from silently regenerating a revoked CA (`:188-195`).
- `secrets.enc.json` — `electronSecretStore.ts:19`, mode `0o600` `:46`.
- `secrets.json` / `secrets.key` — `secretStore.ts:66-67`; modes `0o600` at `:106` and `:88`.

There is **no lock file** — see [4.8](#48-concurrency-the-two-writers-risk).

> Node's `{ mode: 0o600 }` has no effect on Windows, where access is governed by NTFS ACLs. Treat
> the mode bits as POSIX-only hardening. *(Property of the Node API, not a statement in the tree.)*

### 4.3 The SQLite WASM layer

All persistence goes through `src/engine/storage/database.ts`, a thin wrapper over
`node-sqlite3-wasm` — a pure-WebAssembly SQLite build with a **synchronous** API (`:1-30`). The
module is pulled in via `createRequire` so bundlers do not statically process the `.wasm` asset
(`:28-30`).

Why WASM rather than `node:sqlite` or a native module: ADR 0003. `node:sqlite` was chosen first
(ADR 0002) then found absent from the Electron-bundled Node of the day, so the shipped app would
have crashed the moment a project opened while the tests passed (`adr/0003:9-14`). The WASM build
runs identically under Vitest's Node and Electron's, with no native rebuild (`adr/0003:44-45`).
Packaging consequence: `node_modules/node-sqlite3-wasm` including its `.wasm` must ship **unpacked**
(`adr/0003:50-52`).

| Property | Value | Source |
|---|---|---|
| Journal mode | **WAL unsupported by the WASM VFS**; falls back to rollback journaling | `database.ts:37-38`; `adr/0003:46-47` |
| Foreign keys | `PRAGMA foreign_keys = ON` on every open — file (`:39`) and in-memory (`:47`) | `database.ts:39`, `:47` |
| Migrations | `applyMigrations` runs on every open, both paths | `database.ts:41`, `:49` |
| Transactions | `BEGIN IMMEDIATE` … `COMMIT`, `ROLLBACK` on any throw | `database.ts:70-85` |
| API shape | synchronous `exec` / `run` / `get` / `all` | `database.ts:53-68` |
| `busy_timeout` | **not set anywhere in the tree** | no match under `src/`, `test/`, `scripts/`, `docs/` |

The synchronous API is why bulk work must be batched: `HistoryRepo.insert` is its own durable
commit and with no WAL each row pays a full journal round-trip. Use `insertMany()`, which wraps the
loop in one transaction (rationale `historyRepo.ts:115-128`; method `:129-133`; regression test
`test/engine/storage.test.ts:278-300`). See [2.10](#210-tests) for the 86 s → 249 ms case.

### 4.4 Schema and migrations

Two version numbers exist and are unrelated.

| Number | Value | Meaning | Source |
|---|---|---|---|
| `PRAGMA user_version` | **2** | on-disk SQL schema version | `migrations.ts:170-172` |
| `PROJECT_FORMAT_VERSION` | **1** | portable export document version | `projectStore.ts:35` |

`CURRENT_SCHEMA_VERSION` is derived from the migration list, not typed literally
(`migrations.ts:172`). Migrations are an append-only ordered array (`:170`) applied on **every**
`Database.open` and `openInMemory`. Each runs inside a transaction that also bumps `user_version`,
so the schema change and version bump commit atomically — otherwise a crash in the gap would leave
tables created but the version unbumped and the next open would re-run `CREATE TABLE` and fail
(`migrations.ts:174-189`, reasoning `:178-182`).

#### Tables (schema v2)

| Table | Added | Purpose |
|---|---|---|
| `project_meta` | v1 (`migrations.ts:23-26`) | key/value JSON: project info, scope, engine config, engagement profile, AI config, CA history |
| `exchanges` | v1 (`:28-68`) | flattened HTTP request/response, one row per exchange |
| `findings` | v1 (`:78-94`) | scanner/extension findings; FK to `exchanges` **ON DELETE CASCADE** (`:93`) |
| `suppressions` | v1 (`:100-107`) | suppression rules |
| `audit_log` | v1 (`:109-117`) | append-only automation audit; autoincrement id, **no FK** |
| `saved_requests` | v1 (`:122-131`) | saved Repeater requests, raw text |
| `variation_jobs` | v1 (`:133-142`) | **declared but never read or written anywhere in `src/`** |
| `ws_messages` | v2 (`:152-163`) | captured WebSocket frames; FK to `exchanges` **ON DELETE CASCADE** (`:162`) |

> The `variation_jobs` claim is a grep result: the only occurrence of the identifier under `src/`
> is the `CREATE TABLE` at `migrations.ts:133`. It is nevertheless *listed* in
> `docs/project-format.md:40` as if live — that doc line is stale by implication.

Indexes — `exchanges`: `created_at`, `host`, `status_code`, `method`, `in_scope`, `source`, `mime`
(`:70-76`); `findings`: `exchange_id`, `dedupe_key`, `severity` (`:96-98`); `audit_log`: `ts`,
`job_id` (`:119-120`); `ws_messages`: `(exchange_id, seq)` (`:164`).

`project_meta` keys in use: `project.info` (`metaRepo.ts:9`, `:42-44`), `project.scope` (`:10`,
`:49-51`), `project.config` (`:11`, `:56-58`), `project.engagement` (`session.ts:118`, written
`:770`), `project.ca.history` (`session.ts:119`, written `:523`, capped at `MAX_CA_HISTORY = 50`,
`:120`), `project.ai` (literal key, read `session.ts:1362`/`:1367`, written `:1368`).

> **Migration policy has one gap.** Migrations are forward-only and additive; "Never edit a shipped
> migration — add a new one" (`migrations.ts:1-8`). There are **no down-migrations**, and
> `applyMigrations` has **no guard for a database whose `user_version` is higher than the running
> build knows about** — the loop applies only `version > current` and silently skips everything
> else (`:176-187`). The export path *does* refuse a document from the future
> (`projectStore.ts:255-259`); the database path does not. An older build will open a newer
> project's database without complaint.

### 4.5 The blob store

Bodies do not live in the database if they are large. `BlobStore` (`src/engine/storage/blobStore.ts`)
is content-addressed on the body's **plaintext**, so identical bodies deduplicate even though each
sealed copy uses a fresh IV (`contentCipher.ts:9-11`; dedup short-circuit `blobStore.ts:52`).

**The id is not a SHA-256 when the project is encrypted.** It is `HMAC-SHA256(idKey, plaintext)`
where `idKey = HMAC-SHA256(DEK, "belcher-blob-id")` (`contentCipher.ts:27`, `:36-38`; selected at
`blobStore.ts:48-50`). The point is to remove the known-plaintext oracle: someone who copies the
folder without the key cannot confirm a candidate body is present by hashing it
(`contentCipher.ts:30-35`). Plain SHA-256 is used only on the unencrypted low-level path, which in
practice means tests. The test asserts both halves — the id differs from the plaintext SHA-256, and
the plaintext hash appears nowhere on disk (`test/engine/storage.test.ts:263-267`).

> **Doc defect.** The header comment of `blobStore.ts` still says bodies are "stored by SHA-256 of
> their PLAINTEXT bytes" with layout `<root>/<aa>/<bb>/<sha256-of-plaintext>` (`:4`, `:10`), and
> `docs/project-format.md:12` repeats the stale layout. The inline comment at `blobStore.ts:46-47`
> and the prose at `docs/project-format.md:20-24` are correct. Trust those.

On-disk blob layout is `[iv(12) | ciphertext | tag(16)]` when a cipher is configured, raw bytes
otherwise (`blobStore.ts:7-8`; wire format `contentCipher.ts:4`, lengths `:15-16`).

#### How a body decides where it lives

| Path | Threshold | Source |
|---|---|---|
| Live capture (proxy tee) | inline until `spillToDiskAfterBytes`, then streamed to a blob | `bodyCollector.ts:56-65` |
| Live capture hard cap | stops storing at `maxCapturedBytes`, marks `truncated`; **the proxy still forwards every byte to the peer** | `bodyCollector.ts:1-10`, `:37-47` |
| Fully-known body (edited/forwarded, Repeater, Variation) | `> spillToDiskAfterBytes` → blob, else inline | `bodyCollector.ts:112-133`, threshold `:127` |
| **Import from an export** | **hardcoded 64 KiB, ignores config** | `projectStore.ts:316-322`, threshold `:317` |

Defaults: `spillToDiskAfterBytes` 5 MiB, `maxCapturedBytes` 100 MiB (`config.ts:16`, `:17`). Note
the asymmetry in the last row: round-tripping a project through export/import re-lays-out every
body against 64 KiB rather than the configured 5 MiB, so a re-imported project has far more blob
files and a smaller `belcher.db`. Content preserved; layout not.

> **Blobs are never deleted.** There is **no blob garbage collector, prune, vacuum, or delete
> path** anywhere in the tree — `BlobStore` exposes `has`, `putBytes`, `readBytes`,
> `createReadStream`, `beginWrite`, `finalizeStaged` (`@internal`) and two private helpers, and
> nothing else (`blobStore.ts:25-103`). Every cleared exchange leaves its body on disk, encrypted
> and unreferenced, forever.

Staging: `putBytes` stages in the OS temp directory (`:55-56`) and renames into place, falling back
to copy+unlink across devices (`:57`, `:94-101`). The staged bytes are **already sealed** before the
write (`:54`), so a ciphertext fragment — never plaintext — is what can linger in `os.tmpdir()`
after a crash. `beginWrite` stages as `<blobs>/.staging-<hex>.tmp` (`:75`) and removes it on
`abort()` (`:152-157`); a hard crash leaves it.

### 4.6 What is encrypted at rest and what is not

At-rest encryption is **AES-256-GCM** under a single per-project 32-byte data-encryption key (DEK),
wire format `[iv(12) | ciphertext | tag(16)]` (`contentCipher.ts:4`, `:15-17`, `seal` `:50-55`,
`open` `:58-67`). A wrong key or any tampering is detected by the GCM auth tag — `open()` throws
(`:64-66`).

The DEK lives in the project's `SecretStore` under `project-data-key` (`projectStore.ts:39`). It is
created on `create()` and **never on `open()`**: `create()` passes `allowCreate = true` (`:99`),
`open()` passes `false` (`:121`), and with no existing secret `loadOrCreateDek` returns `undefined`
(`:41-51`, specifically `:48`) — so **a project whose key is missing opens unencrypted**.
`store.encryptedAtRest` is simply `!!cipher` (`:84`).

**Encrypted**

| What | Where | Source |
|---|---|---|
| Request headers (JSON) | `exchanges.req_headers` (sealed, base64 into TEXT) | `historyRepo.ts:152`, helper `:108-110` |
| Response headers (JSON) | `exchanges.res_headers` | `:161` |
| Inline request body | `exchanges.req_body_inline` (BLOB) | `:157`, helper `:111-113` |
| Inline response body | `exchanges.res_body_inline` | `:166` |
| Per-exchange operator notes | `exchanges.notes` | `:171` |
| WebSocket frame payloads | `ws_messages.payload` | `wsRepo.ts:36` |
| Every blob file | `blobs/**` | `blobStore.ts:54`, `:142-145` |

**Not encrypted — plaintext inside `belcher.db`**

| What | Why it matters |
|---|---|
| `exchanges`: `host`, `url`, `target`, `method`, `scheme`, `port`, `status_code`, `status_message`, `mime`, `source`, `in_scope`, `automated`, `job_id`, all `timing_*`, `tags`, `error`, all `*_body_size`/`_trunc`/`_enc`/`_blob` | Kept plaintext so history stays searchable — and **URLs routinely carry secrets** (`THREAT_MODEL.md:71-77`). Columns `migrations.ts:28-68`; only the fields above pass through `encText`/`encBytes` (`historyRepo.ts:138-174`) |
| `project_meta` — info, scope, engine config, engagement profile, AI config, CA history | `MetaRepo` takes no cipher (`metaRepo.ts:13-14`; constructed without one, `projectStore.ts:87`) |
| `findings`, including the `evidence` JSON | `FindingsRepo` takes no cipher (`findingsRepo.ts:30-31`, `projectStore.ts:88`). Evidence *is* redacted before storage on the passive-scan path (`passiveScanner.ts:90-94`) — a different control, and one that does **not** apply to findings replayed by `import()` (`projectStore.ts:276`) |
| `suppressions` | same repo, no cipher |
| `audit_log` | `AuditRepo` takes no cipher (`auditRepo.ts:17-18`); detail and target are run through a `Redactor` first (`:11-15`, `:20-33`) |
| **`saved_requests.raw` — the full raw HTTP request text** | Written verbatim with no cipher and no redaction (`projectStore.ts:142-157`, `raw` at `:153`; column `TEXT NOT NULL`, `migrations.ts:129`). A saved Repeater request carries whatever `Cookie`, `Authorization` or token was in it, in cleartext, in the database |
| `ca.pem` | public certificate, safe to share (`docs/project-format.md:13`) |

> That `saved_requests.raw` row is the one most likely to surprise someone who read "headers are
> encrypted at rest" and stopped there.

**Verified negatives.** The encryption is tested against raw disk bytes, not the API: the test
writes a marker into a header and a blob, closes the project, reads **every file under the project
directory** (`readAllUnder`, `test/engine/storage.test.ts:216-227`), asserts the plaintext markers
are absent, then reopens with the key and asserts both come back (`:230-276`, assertions
`:258-268`). A second test reopens with a fresh empty secret store and asserts
`encryptedAtRest === false` and that `history.get()` **throws** (`:302-317`) — that throw is the
normal failure mode for a keyless read, because `rowToExchange` calls `JSON.parse` on base64
ciphertext (`historyRepo.ts:349-351`).

### 4.7 The secret store and the cross-context trap

Both the **CA private key** (`tls-ca-private-key`, `certificateAuthority.ts:34`) and the **project
DEK** (`project-data-key`, `projectStore.ts:39`) live behind one interface:

```ts
interface SecretStore {
  get(key: string): Promise<string | null>;
  set(key: string, value: string): Promise<void>;
  delete(key: string): Promise<void>;
  isSecure(): boolean;
  backendName(): string;
}
```
(`src/engine/ca/secretStore.ts:19-27`)

| Implementation | File | On-disk artefact | `isSecure()` | `backendName()` | Works in |
|---|---|---|---|---|---|
| `ElectronSecretStore` | `src/main/electronSecretStore.ts:15` | `<project>/secrets.enc.json` (`:19`), `0o600` (`:46`) | `safeStorage.isEncryptionAvailable()` (`:22-28`) | `"OS secure storage (safeStorage)"`, or `"safeStorage (unencrypted fallback)"` (`:30-34`) | **Electron main process only** — imports `electron` (`:10`) |
| `FileSecretStore` | `secretStore.ts:60` | `<project>/secrets.json` + `secrets.key` (`:66-67`), both `0o600` (`:106`, `:88`) | **always `false`** (`:70-72`) | `"file (AES-GCM, obfuscation-grade)"` (`:73-75`) | any Node context; **the default** |
| `InMemorySecretStore` | `secretStore.ts:29` | none | `false` (`:40-42`) | `"in-memory (ephemeral)"` (`:43-45`) | any Node context; tests |

`ElectronSecretStore` is wired in by the desktop shell for every project (`src/main/index.ts:46`)
and separately, under `userData`, for the AI provider key so that key never travels with a shared
project folder (`:47-50`).

> **`FileSecretStore` is the default and is obfuscation-grade only.** `ProjectStore.create`/`open`
> fall back to `new FileSecretStore(directory)` when the caller injects nothing
> (`projectStore.ts:96`, `:118`). Values are AES-256-GCM sealed under
> `scryptSync(masterKey, 'belcher-secret-store', 32)` (`secretStore.ts:114`, `:123`), where the
> 32-byte master key is a random file **in the same directory** (`:77-92`). Copying the folder
> copies the key; at-rest encryption buys nothing against whoever holds the folder. The file says so
> itself — "OBFUSCATION-GRADE ONLY … explicitly NOT equivalent to OS secure storage" (`:9-12`).
> Preflight only *warns* about this (`preflight.ts:150-158`); nothing blocks interception with the
> CA key effectively in the clear.

#### The trap: a desktop project opened elsewhere

Two halves that fail in opposite directions.

**Half one — Electron to Electron, fails LOUD.** `safeStorage` keeps its master key under the app's
`userData`, and Electron derives `userData` from the app name — which used to depend on how the
process was launched (package name under `npm run dev`, `"Electron"` under a bare
`electron out/main/index.js`, the electron-builder productName when packaged). A project sealed
under one identity could not be opened by another (`CHANGELOG.md:345-355`). The fix is a pin,
`app.setName('TACNOC')` before anything reads `userData` (`src/main/index.ts:40`, rationale
`:21-39`). For projects already in that state, `ElectronSecretStore.get` **throws rather than
returning `null`** — deliberately, because `null` would make `CertificateAuthority.loadOrCreate`
regenerate over a still-present CA key and make `loadOrCreateDek` silently drop encryption
(`electronSecretStore.ts:56-76`, reasoning `:57-63`). The error names the running identity and its
`userData` path (`:69`).

**Half two — an Electron project opened by a headless/library caller, fails SILENT.** This is the
dangerous one, and it follows from three individually correct pieces of code:

1. The directory has `secrets.enc.json`, no `secrets.json`. A headless caller that injects no store
   gets `FileSecretStore` (`projectStore.ts:118`). Its `readAll()` catches the missing file and
   returns `{}` (`secretStore.ts:95-102`), so `get()` returns **`null`** — absent, not
   undecryptable (`:109-112`).
2. `loadOrCreateDek(store, /* allowCreate */ false)` therefore returns `undefined`
   (`projectStore.ts:46-48`). The project opens with `encryptedAtRest === false` (`:84`, `:121`).
   **No error.** Every subsequent header or inline-body read then tries to `JSON.parse` ciphertext
   and throws, far from the cause (`historyRepo.ts:349-351`).
3. Worse, `CertificateAuthority.loadOrCreate` sees `keyPem === null` with `certPem` present and no
   revocation marker, so it falls to the final `else`: `generateCa()` then `persist()`, which
   **overwrites `ca.pem`** (`certificateAuthority.ts:196-199`; `persist` writes `certPath` at
   `:206-210`) and writes a fresh private key into the new `secrets.json` (`:209`).

Step 3 costs you something irreversible. Reopening in Electron afterwards finds the **old** CA key
in `secrets.enc.json` and the **new** certificate in `ca.pem`, and pairs them: there is **no check
anywhere that the loaded key matches the loaded certificate** — `loadOrCreate` assigns both
unconditionally in the `keyPem && certPem` branch (`certificateAuthority.ts:183-187`). Every browser
that trusted the original CA now sees a chain signed by a key it cannot verify.

The same failure reaches you from the other direction: **deleting `secrets.enc.json` while keeping
`ca.pem`** takes the generate-and-persist branch and overwrites `ca.pem` with a brand-new CA. Back
the project directory up as a unit, not file by file.

**Rules that follow.** Never open an Electron-created project from a script, a test, or any library
caller without injecting the right `SecretStore`. `ProjectStore.open` and `create` both accept
`{ secretStore }` (`projectStore.ts:54-57`), and `TacnocSession` takes a `secretStoreFactory`
(`session.ts:125`, applied `:208-210`). If you cannot supply one, copy the project directory first
and work on the copy.

The MCP server takes the strict version of this rule: **no tool opens a project, touches the SQLite
store, reads a secret, or emits a packet** — including, explicitly, "Nothing here writes, so it
cannot race the desktop app for the project database" (`src/mcp/tools.ts:1-21`, bullets `:4-14`).

#### Recovery: `scripts/reseal-project-secrets.mjs`

```
node scripts/reseal-project-secrets.mjs <projectDir> <oldUserDataDir>
```
(`scripts/reseal-project-secrets.mjs:15`, usage error `:36-40`)

There is **no npm script** for this — `package.json:13-36` does not wrap it — and it resolves the
Electron binary through `require('electron')` (`:81`), so run it from the repo with `node_modules`
installed. `<oldUserDataDir>` is under `%APPDATA%` (Windows), `~/Library/Application Support`
(macOS), or `~/.config` (Linux), named for whichever build created the project (`:17-19`). What it
does, in order:

1. Copies `secrets.enc.json` aside as `secrets.enc.json.bak-<epoch>` (`:98-100`).
2. Launches Electron with `--user-data-dir=<old>` to **decrypt** (`:102`, flag `:78`; helper
   decrypt branch `scripts/secret-helper.cjs:65-72`).
3. Launches Electron again under the pinned `TACNOC` identity to **re-encrypt** (`:111`), writing
   `secrets.enc.json.new` and renaming it into place so an interrupted run cannot leave a
   half-written store (`secret-helper.cjs:84-85`, rationale `:82-83`).
4. Re-reads under the new identity and compares **every** secret value; on any mismatch it restores
   the backup and exits non-zero (`:122-134`).

Plaintext never touches disk: it crosses a one-shot loopback socket with a random 24-byte token
compared using `crypto.timingSafeEqual`, because the payload is a CA private key and neither a temp
file nor an environment variable is an acceptable place for one (`:44-72`, compare `:61-63`; helper
side `secret-helper.cjs:39-58`). The helper pins `app.setName('TACNOC')` itself — without it, it
would re-seal into a *fourth* identity the app never reads (`secret-helper.cjs:21-26`).

> **Second stale doc comment, same family as the blobStore one.** `secret-helper.cjs:10` and its
> usage lines `:14-15` describe the transfer as "stdout -> parent -> stdin". That is the mechanism
> the same file says does **not** work: "Not stdin: Electron's Windows binary is a GUI-subsystem
> process and never receives one, so a piped payload silently arrived empty" (`:42-43`). The
> loopback socket at `:39-58` is what actually runs.

### 4.8 Concurrency: the two-writers risk

**There is no lock.** Searched and not found anywhere in `src/`: a lock file, an advisory lock, a
`PRAGMA busy_timeout`, an open-project registry, or `app.requestSingleInstanceLock()` in
`src/main/index.ts` (134 lines; no match for `requestSingleInstanceLock` or `singleInstance`
anywhere under `src/`).

What *is* enforced: one project per `TacnocSession` (`session.ts:213`, `:236`, `:1568`); rollback
journaling, a whole-file locking model (`database.ts:37-38`); synchronous writes, each `insert` its
own commit (`historyRepo.ts:115-133`); and the MCP server architecturally forbidden from writing
(`src/mcp/tools.ts:13-14`).

What is **not** prevented: two instances of the desktop app opening the same project directory; a
script or test opening a project the app has open; two `TacnocSession` objects in one process. In
that state both processes hold an open WASM SQLite handle on `belcher.db` with no busy timeout,
both write blobs into the same tree, and both may write `secrets.*`. The blob store is relatively
tolerant — ids are content-derived, staging names random (`blobStore.ts:55`, `:75`), and
`finalizeStaged` drops the temp file if the destination already exists (`:84-92`) — so the exposure
is concentrated on the database and the secret store.

> **Operating rule: one writer per project directory, enforced by you.** Close the project in the
> app before running any script against it. For concurrent reads, copy the directory. *(This rule
> is a consequence of the verified absences above; no such rule is written anywhere in the tree.)*

### 4.9 Deletion behaviour

`TacnocSession.clearHistory()` calls `HistoryRepo.clear()` (`session.ts:644-646`), which runs
`DELETE FROM exchanges` and nothing else (`historyRepo.ts:226-228`). Because
`PRAGMA foreign_keys = ON` (`database.ts:39`) and both `findings` and `ws_messages` declare
`ON DELETE CASCADE` on `exchange_id` (`migrations.ts:93`, `:162`), that single statement also
deletes:

- **every finding in the project**, suppressed or not, and
- **every captured WebSocket frame**.

`audit_log`, `suppressions`, `saved_requests` and `project_meta` survive — none has a foreign key to
`exchanges` (`migrations.ts:100-131`). The blobs those rows referenced are **not** deleted and
cannot be ([4.5](#45-the-blob-store)).

> In the UI this is a `ghost`-styled button labelled **"Clear"** in the History toolbar, with **no
> confirmation dialog** (`HistoryView.tsx:164-166`). There is no `confirm` anywhere on the path:
> renderer `api.clearHistory()` (`api.ts:133`) → IPC handler (`ipc.ts:210`) → session → repo.

### 4.10 Import and export

`export()` produces one versioned JSON document, conventionally `*.gnbexport.json`
(`projectStore.ts:187-230`; default filename `${data.info.name}.gnbexport.json` at
`src/main/ipc.ts:98`).

| Field | Contents | Source |
|---|---|---|
| `format` | `"greynoc-belcher-project"` (frozen across the rename) | `:217` |
| `formatVersion` | `1` | `:35`, `:218` |
| `exportedAt`, `info`, `scope`, `config` | metadata | `:219-222` |
| `exchanges` | **all**, paged 2000 at a time | `:189-203`, page size `:192` |
| `findings` | including suppressed | `:224` |
| `suppressions`, `savedRequests` | all | `:225-226` |
| `audit` | **most recent 5000 only** (`AuditRepo.list` orders `id DESC`) | `:227`; `auditRepo.ts:43` |
| `websockets` | all frames, decrypted here and re-sealed on import | `:204-212`, `:280-297` |

Bodies are base64-inlined with a per-body cap defaulting to **25 MiB**; anything larger is carried
as metadata with `"omitted": true` (`:188`, `exportBody` `:232-244`, omission `:234-236`). The
desktop `exportProjectToFile` handler passes no override (`ipc.ts:94-104`, call `:95`).

`import()` validates `format` (`:252-254`) and **refuses a `formatVersion` newer than the running
build** (`:255-259`) — the one place a version-too-new check exists — then creates a project and
replays everything. WebSocket frames are inserted *after* exchanges so the FK is satisfied
(`:280-283`).

**What export does NOT carry** — read `ProjectExportV1` (`:348-364`) as an exclusion list:

- **The CA.** Neither `ca.pem` nor the CA private key. `import()` calls `ProjectStore.create`
  (`:260`), whose `CertificateAuthority.loadOrCreate` finds nothing and generates and persists a
  brand-new CA (`certificateAuthority.ts:196-199`). **Every browser must re-trust the imported
  project's CA.**
- **The engagement profile** (`project.engagement`), **AI settings** (`project.ai`), and **CA
  history** (`project.ca.history`).
- Audit entries beyond the most recent 5000.
- Bodies over the 25 MiB cap.

> **The engine config *is* carried and restored** — exported at `:222`, passed into
> `ProjectStore.create` as `config: exported.config` (`:266`), persisted via `meta.setConfig`
> (`:110`). Only engagement, AI and CA history are lost. `create` also writes an empty fail-closed
> scope first (`:111`), which `import()` then overwrites with the exported scope (`:269`).

> **Exports are plaintext and unredacted.** The document contains captured headers and body bytes in
> base64, in a plain JSON file written with `JSON.stringify(data, null, 2)` (`ipc.ts:102`).
> Redaction applies to logs and findings evidence, **not** to the raw export
> (`docs/project-format.md:77-79`, `SECURITY.md:40-43`, `THREAT_MODEL.md:76-77`). An export of an
> encrypted project is an unencrypted copy of everything the encryption was protecting. Treat a
> `.gnbexport.json` as the most sensitive artefact the tool produces. Note also that the format tag
> is still `greynoc-belcher-project` — tooling matching on the product name will miss it.

### 4.11 Backup and handling

The tree contains essentially no backup documentation — `docs/project-format.md:4` calls the
portable export a mechanism "for sharing/backup" and that is the extent of it. **The following is
derived from the verified mechanics above, not quoted from the repo.**

**Back up by copying the directory, with the app closed.**

- A `.tacnocproj` directory is self-contained *except* for the safeStorage master key, which lives
  under `<userData>/Local State` and is **not** in the folder
  (`scripts/reseal-project-secrets.mjs:4-5`; `CHANGELOG.md:351`). A folder copy of an
  Electron-created project is restorable only on the same machine, same OS user, same app identity.
  That is a confidentiality feature and a restore hazard at the same time.
- Copy with the project closed. No lock, no WAL; copying a rollback-journal database mid-write can
  capture a torn state.
- Take the whole directory. `belcher.db` alone is useless: bodies over the spill threshold are in
  `blobs/`, and without `secrets.*` nothing decrypts.
- `secrets.key` and `secrets.json` must travel together or neither works; `secrets.enc.json` is
  useless without the originating machine's `userData`.

**For a portable, machine-independent backup, use the export** — then handle it as raw captured
traffic, because that is what it is. Accept that the CA, engagement profile, AI settings, CA
history, oversized bodies, and audit entries past 5000 will not come back.

**Before archiving or handing off:** `.gitignore` already excludes `*.tacnocproj`, `projects/`,
`*.pem`, `*.key`, `*.crt` and `ca-store/` from version control (`:23-29`; note the
`!test/**/fixtures/**` re-inclusion at `:30`), and `SECURITY.md:38-39` says not to commit project
folders, CA material, or exports. Nothing enforces this outside git.

**Data that lives outside the project directory:**

| Artefact | Location | Notes |
|---|---|---|
| AI provider API key | `<userData>/ai-secrets` via `ElectronSecretStore` | app-level so it never travels with a shared project and never crosses the contextBridge (`src/main/index.ts:47-50`) |
| Hunt memory | `<userData>/hunt-memory/hunt-outcomes.jsonl` | plaintext JSONL (`huntMemory.ts:38`), redacted on write (`:20-22`), capped at 5000 records (`:39`) / 8 MiB (`:41`); **cross-engagement by design** (`src/main/index.ts:51-54`) |
| safeStorage master key | `<userData>/Local State` | not TACNOC's file; the reason folder copies do not decrypt elsewhere |

### 4.12 The workspace reader

The engagement workspace defaults to the project directory itself, which points a model-facing read
API at the folder holding the database, the blobs, and the secret store (`workspace.ts:17-19`). The
containment rules are therefore part of this area.

- **Read-only.** No write, move, or delete exists in the API surface (`:12-13`).
- **Denied by name at any depth:** `blobs`, `ca.pem`, `node_modules`, `.git`, `.svn`, `.hg`, `.ssh`,
  `.gnupg`, `.aws`, `.env` (`:46-62`).
- **Denied by pattern:** `^secrets(\.|$)` (catches `secrets.json`, `secrets.key`,
  `secrets.enc.json`), `\.(db|db-wal|db-shm|sqlite|sqlite3)$`, `^\.env(\..+)?$`,
  `\.(key|p12|pfx|jks|keystore)$`, `^id_(rsa|dsa|ecdsa|ed25519)$`, `^\.npmrc$`, `^\.netrc$`
  (`:64-72`) — all case-insensitive.
- **The denylist is applied twice** — to the caller's string (`:192`) and again to the *resolved*
  path (`:225`) — because on Windows an 8.3 short name (`SECRET~1.JSO`) sails past a check on
  `secrets.enc.json` and lands on exactly that file (`:220-224`).
- **Hard links are caught by identity, not spelling:** a file with `nlink > 1` is compared by
  inode/device against every denied name in its own directory (`:237-261`, called `:404`).
- **Alternate data streams** (`policy.md:hidden.txt`) are refused outright (`:186-191`).
- **Symlinks are skipped** during listing (`:342-344`) and never followed out of the root — the path
  is resolved with `fs.realpath` and re-checked for containment (`:201-219`).
- **Private key material is refused by content**, not extension: any returned text matching
  `-----BEGIN [A-Z ]*PRIVATE KEY-----` is rejected before it can be egressed (`:418-427`). Binary
  content (a NUL byte) is refused first (`:415-417`).

Bounds (`:33-38`): `MAX_ENTRIES` 2000, `MAX_DEPTH` 8, `DEFAULT_READ_BYTES` 256 KiB,
`MAX_READ_BYTES` 2 MiB, `MAX_SEARCH_FILES` 500, `MAX_SEARCH_MATCHES` 200.

> **200 is the search ceiling, not the default.** `searchWorkspace` clamps `maxMatches` to a
> **default of 50** capped at 200 (`:453`), and `maxFiles` to a default of `MAX_SEARCH_FILES` capped
> at 500 (`:454`). A search that looks exhaustive may have stopped at 50. Search is substring and
> case-insensitive (`:485`), deliberately not a regex — "a model-authored pattern is a
> denial-of-service lever on this process" (`:440-444`).

This is a read gate for the AI/workspace path **only**. It places no restriction on the operator, on
other processes, or on anything reading the project directory directly.

---

## 5. Scope and authorization

TACNOC's safety story is four separable mechanisms, not one. Confusing them is the main way
operators get surprised.

### 5.1 The four mechanisms

| # | Mechanism | Kind of control | Blocks traffic? |
|---|---|---|---|
| 1 | Authorization reference | Record-keeping + preflight report | No |
| 2 | Scope (`evaluateScope`) | Fail-closed gate | Yes — on *automated* generation only |
| 3 | Limits (count, rate, concurrency, timeout, budget) | Bounded automation | Yes — caps volume |
| 4 | Emergency stop | Abort switch | Yes — for jobs and mesh runs |

Audit logging and secret redaction sit alongside these as *recording* and *containment* controls;
neither prevents a request. Read this together with
[`authorization-and-scope.md`](authorization-and-scope.md) and [`../THREAT_MODEL.md`](../THREAT_MODEL.md).

### 5.2 Authorization

An authorization reference is free text, stored in two places and enforced nowhere.

- Set at project creation — `createProject(dir, name, authorizationRef?)` (`session.ts:212`) — into
  `ProjectInfo.authorizationRef` (`src/shared/project.ts:11`, "Free-form engagement/authorization
  reference recorded by the researcher").
- Set again, separately, on the engagement profile (`EngagementProfile.authorizationRef`,
  `src/shared/engagement.ts:60`, default `''` at `:80`), edited in **Engagement**
  (`EngagementView.tsx:384-385`).
- Preflight reads the profile value first, then the project value (`preflight.ts:58-59`), raises a
  **blocker** when both are empty (`:68-77`), and when one is present makes the reference itself the
  `detail` of an `ok` check (`:83`) — which matters, because preflight detail is quoted verbatim
  into the AI briefing ([11.2](#112-exactly-what-data-leaves-the-machine)).

> **What it does not cover.** Nothing in the engine refuses to act because the reference is missing.
> `startMeshRun` checks scope and the API key only (`session.ts:1477-1494`); it never consults
> `PreflightReport.ready`. The one indirect halt is soft and model-mediated: the recon role prompt
> orders it to stop on a blocker (`prompts.ts:49` — "If it returns any BLOCKER, stop and report
> exactly what is blocking; do not paper over it"), and the per-run recon prompt adds the
> machine-readable form — "say so in your FIRST line, beginning with \"BLOCKED:\""
> (`orchestrator.ts:678`). The orchestrator stops the run if the recon text matches
> `/^\s*BLOCKED\s*:/i` (`isBlocked`, `:681-684`; checked `:286-296`). If the model *declines* the
> recon turn, the engine substitutes its own briefing, which prepends `BLOCKED:` itself when
> preflight has blockers (`session.ts:916-923`) — that path *is* deterministic. Nothing at all gates
> the Variation engine, the Repeater, or the proxy on authorization.

### 5.3 The scope data model and decision procedure

`ScopeConfig = { include: ScopeRule[]; exclude: ScopeRule[] }` (`src/shared/scope.ts:43-46`).

| Field | Type | Empty/absent means |
|---|---|---|
| `id` | string | — (required) |
| `label` | string? | rule reported by `id` instead (`scope.ts:100`, `:109`) |
| `enabled` | boolean | see [5.5](#55-normalization-and-the-enabled-divergence) — `ruleMatches` requires it truthy |
| `hostMatch` | `'exact' \| 'subdomain' \| 'wildcard'` | unknown value → no match (`default: return false`, `scope.ts:58-59`) |
| `host` | string | pattern; interpretation depends on `hostMatch` |
| `schemes` | `Scheme[]` | **empty = any scheme** (`scope.ts:64`) |
| `ports` | `number[]` | **empty = any port** (`scope.ts:68`) |
| `path` | `{kind:'prefix'\|'regex', value}?` | **absent = any path** (`scope.ts:72`) |

`evaluateScope(config, target)` — `src/engine/scope/scope.ts:92-120`:

1. Normalize the target host (`:93`).
2. Find the **first matching enabled `exclude` rule** (`:95`). If one matches → `inScope: false`,
   `matchedExclude` set. **Excludes are evaluated first and always win.**
3. Else find the **first matching enabled `include` rule** (`:104`) → `inScope: true`.
4. Else `inScope: false` (`:113-119`), with the reason distinguishing *no include rules at all*
   (`'No include rules defined — scope is empty (fail-closed).'`) from `'No include rule matched
   this destination.'`

So: **in scope ⇔ (at least one enabled include matches) AND (no enabled exclude matches)**. With
zero include rules nothing is in scope — the fail-closed default, and the state of every new
project (`emptyScope()`, `src/shared/scope.ts:64-66`). A rule matches only when **all** of
`enabled`, host, scheme, port and path match (`ruleMatches`, `scope.ts:82-90`).

### 5.4 Host, scheme, port and path matching

| `hostMatch` | Semantics (`scope.ts:45-61`) | `*` in `host` |
|---|---|---|
| `exact` | `host === ruleHost` (`:48-49`) | **treated literally** |
| `subdomain` | `host === ruleHost \|\| host.endsWith('.' + ruleHost)` (`:50-51`) | **treated literally** |
| `wildcard` | anchored regex from a glob (`:52-57`): `*` → `[^.]+` (exactly one label), `**` → `.+` (one or more characters, dots included); each of `\ ^ $ . \| ? + ( ) [ ] { }` backslash-escaped; a compilation exception returns `false` | globbed |

Globbing happens **only** in the `wildcard` branch — `globToRegExp` is called from nowhere else
(`scope.ts:54`).

| Pattern (`wildcard`) | Compiled regex | `a.test` | `x.a.test` | `x.y.a.test` |
|---|---|---|---|---|
| `*.a.test` | `^[^.]+\.a\.test$` | no | **yes** | no |
| `**.a.test` | `^.+\.a\.test$` | no | **yes** | **yes** |

> **A `*` in the host with `hostMatch: 'exact'` or `'subdomain'` is a literal asterisk** — the rule
> is dead, and nothing warns. The Scope Add form defaults to `exact` and its own placeholder
> suggests `*.example.test` (`ScopeView.tsx:14`, `:171`). The MCP tool does the opposite and infers
> `wildcard` from a `*` (`mcp/tools.ts:79-85`), so the same rule text behaves differently depending
> on which surface created it.

> **Neither `*` nor `**` matches the apex.** Both require at least one label before the base. To
> cover apex plus subdomains use two rules, or `hostMatch: 'subdomain'` — which matches the apex
> *and* every depth below it, anchored on a literal dot, so `evilexample.test` does not match
> `example.test` (`docs/authorization-and-scope.md:40-41`; test *"matches subdomains but not the
> wrong parent"*, `test/engine/scope.test.ts:35-45`, which asserts both `notexample.test` and
> `evilexample.test` are out).

- **Scheme** — only `http` and `https` exist (`src/shared/model.ts:17`); `targetFromUrl` returns
  `null` for anything else (`scope.ts:135`).
- **Port** — `targetFromUrl` defaults to 443/https and 80/http when the URL carries no explicit port
  (`scope.ts:136`). On the proxy path the port comes from the CONNECT authority, then the
  absolute-form URL, then the `Host` / `:authority` header (`proxyServer.ts:351-392`).
- **Path** — matched against `target.path`, which on every proxy/repeater/variation path is the
  **origin form: path *plus* query string** (`originForm`, `proxyUtil.ts:90-94`; `deriveContext`,
  `proxyServer.ts:394-396`; `targetFromUrl` returns `parsed.pathname + parsed.search`,
  `scope.ts:137`). So a `prefix` of `/api` matches `/api/x?y=1`, and a `regex` can be written
  against the query. `kind:'prefix'` is `String.startsWith` (`:74`); `kind:'regex'` is an
  **unanchored** `new RegExp(value).test(value)` (`:76`) — write your own `^` if you mean a prefix.

> **An invalid path regex returns `false`** (`:78`, commented "an invalid regex must not silently
> match everything") — i.e. it matches nothing. On an *include* rule that fails safe; on an
> *exclude* rule the exclusion silently stops protecting the thing you excluded, with no error.

### 5.5 Normalization and the enabled divergence

`normalizeHost` (`scope.ts:12-16`) trims, lowercases, and strips **all** trailing dots. It is
applied to the target host (`:93`) and to the rule host on every comparison (`:46`, and inside
`globToRegExp` at `:20`). That is the whole of it. It does **not** do:

- punycode/IDN folding — `xn--` and the Unicode form are different hosts;
- IP canonicalization — the *URL parser* normalizes `0x7f.0.0.1` to `127.0.0.1` before scope ever
  sees it, but nothing normalizes an IP against a hostname rule;
- IPv6 bracket normalization.

> **IPv6 rules do not port between surfaces.** `targetFromUrl` returns `parsed.hostname`, which is
> **bracketed** — `https://[::1]:8443/p` yields host `"[::1]"` — while the proxy's CONNECT/`Host`
> path uses `parseAuthority`, which strips brackets (`proxyUtil.ts:61-67`,
> `host = authority.slice(1, close)`). A rule written for one form silently never matches the other.

> **The `enabled` divergence.** `ruleMatches` requires `rule.enabled` to be **truthy**
> (`scope.ts:84`). Eight other sites instead count rules where `enabled !== false` — the two that
> gate readiness are `MeshOrchestrator.start` (`orchestrator.ts:170`) and `buildPreflight`
> (`preflight.ts:53`, and `:288` for the exclude count); the rest are reporting surfaces
> (`orchestrator.ts:440`, `session.ts:847`, `:854`, `:1325`, `:1483`). The MCP rule normalizer makes
> the same choice (`mcp/tools.ts:96`). For a rule authored in the UI this never differs —
> `ScopeView.newRule()` always writes `enabled: true` (`:9`). For a **hand-edited or imported
> project file** carrying a rule with `enabled` absent, the mesh would be allowed to start and
> preflight would report scope as populated, while `evaluateScope` refused every request. `setScope`
> performs no validation at all — it writes the object verbatim to project metadata
> (`session.ts:531-533` → `metaRepo.ts:49-51`).

### 5.6 Where scope is enforced and where it is not

`evaluateScope` is the only evaluator. Nine call sites across six modules; none reimplements the
logic.

| Call site | File:line | Effect |
|---|---|---|
| `VariationEngine.createJob` | `variationEngine.ts:144-154` | **Refuses** to create the job |
| `VariationEngine.runOne` (per generated request) | `:338-362` | **Skips** the request, increments `skipped`, audits `request.skipped-out-of-scope` (`:357`) |
| `meshRepeaterScopeDecision` → `send_repeater` | `ai/tools.ts:92-106`, used `:643-648` | **Refuses** the call, returns an `error` string to the model |
| `MeshOrchestrator.start` | `orchestrator.ts:170-176` | **Refuses to start a run** with no enabled include rule |
| `TacnocSession.startMeshRun` | `session.ts:1483-1485` | Same check, ahead of the API-key check |
| `ProxyServer.deriveContext` | `proxyServer.ts:396` | **Labels only** — stamps `ctx.inScope` (`:409`), used at `:467`, `:775`, `:968` |
| `Repeater.send` | `repeater.ts:168` | **Labels only** |
| `buildTargetMap` | `siteMap.ts:106-111` | Labels each endpoint, live, per call |
| `evaluate_scope` AI tool | `ai/tools.ts:604-607` | Read-only advice to the model |
| `evaluate_scope` MCP tool | `mcp/tools.ts:301-313` | Offline; evaluates a **caller-supplied** scope object |

`rankAttackSurface` (`surface.ts:328-331`) does not call the evaluator itself — it reads
`endpoint.inScope` off the `TargetMap` just produced, counting out-of-scope endpoints into
`outOfScopeSkipped` and never ranking them.

**Gated (refused or skipped):** Variation job creation; every Variation request; the AI mesh's
`send_repeater`; starting an AI mesh run at all.

**Not gated:**

- **The proxy.** All traffic routed through it is forwarded and captured regardless of scope. There
  is no refusal branch — `inScope` appears in `proxyServer.ts` only at `:93` (the type), `:409`
  (stamp), and `:467`, `:775`, `:968` (readers). This is deliberate — passive observation is how you
  discover what is in scope — but the proxy is not a containment boundary.
- **The Repeater**, when driven by a human from the UI. `repeater.ts:7-8`: "This is a MANUAL,
  single-shot workflow (not automated generation), so it is not scope-gated; the resulting exchange
  still records its in-scope status." `session.sendRepeater` adds no gate either (`:680-692`).
- **Interception.** `holdRequest`/`holdResponse` are called for every proxied message when the
  toggle is on (`proxyServer.ts:475`, `:688`; `interceptor.ts:52`, `:71`); the scope badge in the
  queue is informational.
- **The passive scanner.** Grep of `inScope` / `evaluateScope` across `src/engine/scanner/` returns
  **no matches**; it scans and produces findings for out-of-scope exchanges too.
- **Scope changes are not retroactive.** `exchanges.in_scope INTEGER NOT NULL` is written once at
  ingest (`migrations.ts:35`) and read back verbatim (`historyRepo.ts:394`). The **Target** map and
  the attack-surface ranking *do* re-evaluate live, so the two surfaces can legitimately disagree.
- **Proposals are not scope.** `proposeScope` reads the engagement folder and produces candidates
  with file/line evidence; it never writes scope (`scopeProposal.ts:13-16`: "It never writes scope.
  `setScope` stays an operator action"; test *"proposing alone changes NOTHING — scope stays
  fail-closed"*, `test/engine/scopeGateWiring.test.ts:140-145`). The mesh has **no tool that can
  change scope** (test `scopeGateWiring.test.ts:199-204`).
- Applying a proposed wildcard candidate `*.host` produces a rule with host `**.host` and
  `hostMatch: 'wildcard'` (`scopeProposal.ts:341-347`) — the proposal path widens `*` to `**`
  deliberately, unlike the hand-entry path.

#### Anti-bypass details worth knowing

- `send_repeater` forces `followRedirects: false, maxRedirects: 0` (`ai/tools.ts:666-667`) — a
  redirect is a cross-host hop the gate never saw.
- `send_repeater` forwards the **canonicalized** destination the gate approved
  (`decision.scheme/host/port`, `:658-671`), not the model's raw object, because `Repeater.send`
  reads scheme/port verbatim and TLS selection is an exact `'https'` match. The in-code comment
  spells out the two failure cases: `'HTTPS'` checked as TLS but sent cleartext, and an omitted port
  checked as 443 but sent to Node's default 80.
- Both the mesh gate and `VariationEngine` derive the path with the **same parser the sender uses** —
  `originForm(parseRawRequest(raw).target)` (`requestPath`, `ai/tools.ts:83-89`; `safePath`,
  `variationEngine.ts:488-493`) — so an absolute-form request line cannot smuggle a path past a
  path-scoped rule. Both fall back to `'/'` on a malformed raw.
- The operator-driven Repeater *does* strip `Cookie` and `Authorization` on a cross-host redirect
  (`repeater.ts:137-139`), and the engagement profile is forbidden from setting those two headers
  for the same reason (`src/shared/engagement.ts:124-136`).

### 5.7 Engagement identity

Applied in the engine on the two generating paths, not left to whoever typed the request.

- `applyIdentity(headers, profile)` (`identity.ts:70-98`) rewrites headers **only when
  `profile.userAgent.enforce` is true and at least one valid required header exists**
  (`identityEnforced`, `:61-63`). An existing header is replaced **in place** (position preserved,
  `:89-92`), later duplicates dropped, missing ones appended (`:94-96`).
- Call sites: `Repeater.send` per hop (`repeater.ts:102`) and `VariationEngine.runOne` per request
  (`variationEngine.ts:366`). Both read the profile **per request** via `getEngagement?.()`, so an
  edit mid-run takes effect (comment `variationEngine.ts:364-365`).
- Validation runs twice — at `setEngagementProfile` (`session.ts:762-770`, rejects outright with
  *"engagement profile rejected: …"*) and again in `requiredIdentityHeaders`, which silently
  **drops** invalid entries (`identity.ts:46`). CR/LF/NUL are refused (`CTL_RE`,
  `shared/engagement.ts:106`, checked `:153-155`), as are non-transportable values
  (`TRANSPORTABLE_VALUE_RE`, `:109`, checked `:159-162`); reserved header names — the framing headers
  plus `cookie`, `authorization`, `proxy-authorization` — are refused (`RESERVED_HEADERS`,
  `:124-136`); values capped at `MAX_HEADER_VALUE_LENGTH = 1024` (`:139`); at most
  `MAX_IDENTITY_HEADERS = 16` (`:138`), enforced in the setter *and* again on the enforcement path
  (`identity.ts:51-55`, whose comment explains that "the setter's validation is not the only way a
  profile arrives").

> **What it does not cover.** Proxy traffic is never rewritten — the browser sends its own
> `User-Agent`. `checkIdentity` (`identity.ts:114-130`) reports compliance for already-sent traffic
> but changes nothing, and preflight reports historical non-compliance as a *warning*, with the
> honest remedy that "Traffic sent before enforcement was enabled stays as it was; new requests will
> comply" (`preflight.ts:206-207`). **If a programme requires a marker header on every request,
> routing a browser through TACNOC does not satisfy it.**

### 5.8 Preflight

`buildPreflight(inputs)` (`preflight.ts:50`) is a pure function over a snapshot; it returns graded
checks and `ready = !checks.some((c) => c.severity === 'blocker')` (`:298`).

| Check id | Severity | Condition | Line |
|---|---|---|---|
| `project` | blocker | no project open | `:60-67` |
| `authorization` | blocker | no authorization reference in profile or project | `:68-77` |
| `authorization` | ok | reference recorded — **detail is the reference itself** | `:78-85` |
| `scope` | blocker | zero enabled include rules; lists hosts found in the engagement folder | `:88-103` |
| `scope` | ok | rule and host counts; detail lists up to 10 hosts | `:104-112` |
| `ca-revoked` | warning | interception disabled | `:116-124` |
| `ca-expired` | blocker | CA `notAfter` in the past | `:125-132` |
| `ca-expiring` | warning | expiry approaching | `:133-140` |
| `ca` | ok | **detail is subject + truncated SHA-256 fingerprint + days remaining** | `:141-148` |
| `ca-key-storage` | warning | CA key not in OS secure storage | `:150-158` |
| `ca-trust` | warning / ok | zero decrypted HTTPS exchanges captured despite interception being on | `:161-178` |
| `user-agent` | warning / ok | not configured / configured-but-not-enforced / historical non-compliance / enforced | `:182-217` |
| `proxy-bind` | blocker | listener is not loopback | `:220-228` |
| `proxy` | warning | proxy not running | `:229-237` |
| `workspace` | warning / ok | folder unreadable or empty (points one level up when the project sits inside the hunt folder) | `:240-270` |
| `history` | warning | zero exchanges captured | `:272-281` |

Every check is grounded in something observable — certificate validity windows, the count of
decrypted HTTPS exchanges actually captured, the `User-Agent` on requests already sent — not in
configuration alone (`preflight.ts:11-13`).

> **Preflight is advisory. `ready` gates nothing mechanically.** Grep of `.ready` shows use only in
> the AI briefing text (`session.ts:865`) and the Engagement view (`EngagementView.tsx:209-210`). A
> `BLOCKER` row does not stop the proxy, the Repeater, or a variation job. In particular
> `proxy-bind` is a blocker raised *after* the proxy has already bound to the non-loopback address.

---

## 6. The proxy and TLS interception

This is the core of TACNOC. Everything else consumes what this subsystem captures. Source of
record: `src/engine/proxy/proxyServer.ts` (1,073 lines), `proxyUtil.ts` (94), `interceptor.ts`
(130), `wsFrame.ts` (228), `src/engine/ca/*`, `src/engine/net/httpClient.ts`. Builds on
[`certificate-management.md`](certificate-management.md).

### 6.1 Reference card

| Property | Value | Source |
|---|---|---|
| Default bind host | `127.0.0.1` | `src/shared/model.ts:173` |
| Default bind port | `8080` | `model.ts:174` |
| Hosts that bind without a warning | `127.0.0.1`, `::1`, `localhost` | `config.ts:34` |
| CONNECT response line | `HTTP/1.1 200 Connection Established` + `Proxy-agent: TACNOC` | `proxyServer.ts:306`, `:339` |
| MITM ALPN offered | `['h2','http/1.1']`; `['http/1.1']` when `enableHttp2 === false` | `:116-118` |
| Upstream ALPN requested | `['http/1.1']` always | `:571`, `:821` |
| Origin cert validation | `rejectUnauthorized: false` (never hard-fails) | `:570`, `:820` |
| CA key algorithm | RSA-3072, self-signed, SHA-256, now−1d → now+5×365d | `certificateAuthority.ts:69-87`, `:318-336` |
| Leaf key algorithm | RSA-2048, one pair shared by every host | `:201-202` |
| Leaf validity | 397 days (`notBefore` = now − 1 day) | `:381-382` |
| Leaf cache | LRU, max 1024 entries | `:161`, `:404-408` |
| CA subject | `CN=TACNOC Project CA, O=TACNOC (authorized testing)` | `:35-36` |
| Public CA cert on disk | `<project>.tacnocproj/ca.pem`, mode `0644` | `projectStore.ts:38`, `certificateAuthority.ts:208` |
| CA private key secret name | `tls-ca-private-key` | `:34` |
| Upstream socket timeout | `limits.upstreamTimeoutMs`, default 30 000 ms | `config.ts:26`, `proxyServer.ts:561` |
| Max concurrent proxy connections | `limits.maxProxyConnections`, default 512 | `config.ts:25`, `proxyServer.ts:282` |
| Body capture caps | spill to disk > 5 MiB, hard cap 100 MiB | `config.ts:15-18` |
| WebSocket caps | 5 000 messages/conn, 64 KiB/message, 64 KiB handshake | `proxyServer.ts:62-65` |
| Upstream/SOCKS proxy chaining | **Not implemented** | no match in `src/`; `capability-matrix.md:12` |
| Transparent / invisible proxy mode | **Not implemented** | `capability-matrix.md:12` |
| HTTP/3 / QUIC | **Not implemented** | `certificate-management.md:88`; `README.md:188-191` |

### 6.2 The listener

`ProxyServer.start(host, port)` creates one `http.Server` and binds it (`proxyServer.ts:232-258`).
Four events are wired:

| Event | Handler | Covers |
|---|---|---|
| `request` | `onRequest(req, res, 'http')` (`:234`) | plain-HTTP proxy requests, absolute-form |
| `connect` | `onConnect(req, sock, head)` (`:235`) | `CONNECT host:port` → TLS interception |
| `upgrade` | `onUpgrade(req, sock, head, 'http')` (`:236-238`) | `ws://` WebSocket handshakes |
| `connection` | `trackConnection(sock)` (`:239`) | connection accounting / cap |

`clientError` responds `HTTP/1.1 400 Bad Request\r\n\r\n` on a writable socket, else destroys it, so
a malformed request line cannot take the proxy down (`:241-244`).

**Binding.** `TacnocSession.startProxy(host?, port?)` takes the per-project persisted
`config.listener` unless overridden (`session.ts:374-379`). The listener is edited in
**Settings → Proxy listener** and, as the UI states, "Applies the next time you start the proxy"
(`SettingsView.tsx:103`).

> **The engine does not refuse a non-loopback bind — it only classifies it.** `isLoopbackBind()`
> (`config.ts:36-38`) drives a `loopbackOnly` flag in `ProxyStatus` (`session.ts:418`), which renders
> a `non-loopback bind` chip in the top bar (`App.tsx:195-199`); Settings shows its own warning box
> computed by a renderer-local mirror of the same host set (`SettingsView.tsx:6-8`, `:95`,
> `:128-134`). Nothing blocks it. **If you bind `0.0.0.0`, anyone who can reach that port gets an
> open forward proxy with your CA behind it.**

> **The connection cap destroys sockets with no response at all** (`:281-285`) — from the client's
> side it looks like a connection reset, not a proxy error. A "flaky target" at high concurrency may
> be `maxProxyConnections` (default 512).

`start()` resolves with the port actually bound, read back from `server.address()` (`:248-257`), and
`ProxyServer.address` reports it (`:120-122`) — so a configured port of `0` yields whatever
ephemeral port Node chose.

**Stopping.** `stop()` (`:260-279`) does, in order: release every held intercept queue entry as
**drop** (`:266` — stopping is not consent to send queued requests), `closeAllConnections()` on the
plain server and, through an optional cast, on the MITM server (`:268-269`), destroy every
intercepted socket (`:270`), destroy every tracked socket (`:271-272`), then await both `close()`
(`:273`).

### 6.3 Plain HTTP

`deriveContext` (`:351-411`) resolves host/port from, in order: the absolute-form request line
(`http://host:port/path`), falling back to the `Host` header when `new URL()` throws, falling back to
an empty host — which produces a clean upstream failure rather than an `uncaughtException`
(`:372-392`, rationale `:373-378`).

Forwarding is `openUpstream` (`:546-575`) → `http.request` / `https.request`. Headers are rebuilt by
`buildOutboundHeaders` (`proxyUtil.ts:32-53`), which:

- drops the RFC 9110 §7.6.1 hop-by-hop set: `connection`, `proxy-connection`, `keep-alive`,
  `proxy-authenticate`, `proxy-authorization`, `te`, `trailer`, `transfer-encoding`, `upgrade`
  (`:11-21`);
- drops `content-length` and lets the runtime recompute framing from the bytes actually written
  (`:40`);
- drops any `:`-prefixed HTTP/2 pseudo-header (`:38`);
- preserves duplicate headers as arrays and preserves the original casing of the **first**
  occurrence of each name (`:41-50`).

> **You cannot forward a deliberately desynchronised `Content-Length`.** Both `content-length` and
> `transfer-encoding` are stripped and Node recomputes framing (`proxyUtil.ts:19`, `:40`, `:26-28`).
> CL.TE / TE.CL request-smuggling primitives cannot be expressed through the interceptor, the
> Repeater (`repeater.ts:211`), or the Variation engine (`net/httpClient.ts:47`).

Two body paths:

- **Interception off** — `streamTee` writes each chunk to the peer and to a `BodyCollector`
  simultaneously (`:520-527`, `:998-1008`). Capture caps never affect what is forwarded: the
  collector clamps storage and sets `truncated`, the tee still writes the full buffer
  (`bodyCollector.ts:33-47`).
- **Interception on** — the whole body is buffered first so it can be shown and edited (`:431-439`).

### 6.4 CONNECT and TLS interception

`onConnect` (`:293-319`):

1. Parse the authority (`parseAuthority(req.url, 443)`), IPv6-bracket aware (`proxyUtil.ts:56-73`).
2. `ensureMitm()` — if it returns `undefined`, fall through to **passthrough** ([6.6](#66-no-ca-or-an-untrusted-ca)).
3. Write `HTTP/1.1 200 Connection Established\r\nProxy-agent: TACNOC\r\n\r\n` (`:306`).
4. `unshift` any bytes the client already sent with the CONNECT (`:307`).
5. Stash `{host, port}` on the raw socket under a module-private `Symbol('tacnocAuthority')`
   (`:96`, `:311`).
6. Add the socket to the `intercepted` set, then `mitm.emit('connection', clientSocket)` (`:312-314`).

The TLS terminator is **not** a plain `tls.Server`. `buildMitm()` (`:136-169`) creates an
`http2.createSecureServer({ allowHTTP1: true, ALPNProtocols, SNICallback })` — the only TLS server
anywhere in `src/engine/` (`grep -rn "tls.createServer\|createSecureServer" src/engine/` returns
`proxyServer.ts:138` alone). Both h2 and http/1.1 requests arrive on the http1-compatible `request`
event (`:151-159`), so a single `onRequest` path serves plain HTTP, decrypted HTTP/1.1, and
decrypted HTTP/2.

> **`ARCHITECTURE.md:80-83` is out of date** — it says the client socket is "wrapped in a
> `tls.TLSSocket`" and the decrypted stream "handed to an inner `http.Server`". The code uses
> `http2.Http2SecureServer` with `allowHTTP1` (`:100`, `:138`, `:141`). The difference matters: the
> comment at `:185-190` records that `closeAllConnections()` is an `http.Server` method
> `Http2SecureServer` does not have, and that sockets handed in via `emit('connection')` are not
> counted by `close()` either, which is why intercepted sockets are tracked and destroyed by hand
> (`:191`, `:210-213`, `:270`). *(That Node API claim is the code comment's; no runtime check was
> performed.)*

Per-connection certificates come from `SNICallback` → `ca.secureContextFor(servername || 'localhost')`
(`:143-149`). The server's default context is built from `ca.leafPemFor('localhost')` (`:137`), so a
connection that presents **no SNI** is served a certificate for the name `localhost`, which fails
hostname verification for any other target. *(How often real clients omit SNI is not a question the
tree answers — not found in tree.)*

The authority for a decrypted request is recovered from the socket's TLS `_parent`, because the
secure server wrapped the raw CONNECT socket (`readAuthority`, `:1049-1057`; used `:360`). Only if
that fails does it fall back to `Host` / `:authority` (`:364-371`).

**Origin leg.** The proxy always opens a *new*, ordinary connection to the true origin —
`servername: host`, `ALPNProtocols: ['http/1.1']`, and **`rejectUnauthorized: false`** (`:567-572`,
rationale `:564-566`).

> **The proxy is not a TLS validity oracle.** Expired, self-signed and wrong-name origin
> certificates are accepted silently on the proxy path and nothing is recorded about them. This is
> deliberate (lab and self-signed origins must be testable) — but if you need to know whether an
> origin's certificate is valid, use the Repeater, whose `sendRaw` records `socket.authorized` as
> `tlsAuthorized` (`net/httpClient.ts:62-68`, `:128`). The only `authorized` tokens in
> `proxyServer.ts` are the two `rejectUnauthorized: false` options. TACNOC will happily proxy you
> into a MITM'd origin and report it as a passive finding rather than failing the connection.

### 6.5 The project CA

#### Generation and location

A CA is generated on **first project open** if none exists (`certificateAuthority.ts:170-204`).
There are **two near-identical generators**: the private `generateCa()` (`:317-341`) used by
`loadOrCreate` at `:197`, and module-level `generateCaMaterial()` (`:68-94`) used by `rotate()`.
Both produce RSA-3072, self-signed, `SHA-256` (`:69`/`:318`, `:87`/`:336`); a 16-byte random serial
with the leading byte forced to `00` (`randomSerialHex`, `:53-58`); `notBefore` = now − 1 day,
`notAfter` = now + 5 × 365 days (`:74-75`, `:323-324`); extensions
`basicConstraints{cA:true, critical}`, `keyUsage{keyCertSign, cRLSign, critical}`,
`subjectKeyIdentifier` (`:82-86`, `:331-335`).

| Artifact | Where it lives |
|---|---|
| Public CA certificate | `<project>.tacnocproj/ca.pem`, mode `0644` |
| CA **private key** (desktop app) | `safeStorage`-sealed inside `secrets.enc.json`, mode `0600`; master key in the OS credential store under the app's `userData` |
| CA private key (headless / CI) | `secrets.json` + `secrets.key`, AES-256-GCM under a scrypt-derived key, both mode `0600` |
| Revocation marker | `ca.pem.revoked.json`, mode `0600` (`:110-113`) |

See [4.7](#47-the-secret-store-and-the-cross-context-trap) for the full store comparison and the
"project cannot be opened" recovery.

#### Leaf certificates

`leafFor(host)` (`:361-411`): 397-day validity, `CN=<host>`, issuer = CA subject,
`basicConstraints{cA:false}`, `keyUsage{digitalSignature, keyEncipherment}`,
`extKeyUsage{serverAuth}`, and a single SAN — `type 7` (iPAddress) when `net.isIP(host)` is non-zero,
`type 2` (dNSName) otherwise (`:386-387`). With no CA material it throws rather than minting
anything (`:364-368`).

> **One RSA-2048 key pair is shared by every leaf** and is generated fresh on each `loadOrCreate` —
> i.e. on every project open (`:201-202`). It is never persisted. Only the certificate differs per
> host. **A CA rotate does not rotate the leaf key pair.**

The cache is an LRU capped at 1024 entries (`:158-161`, `:404-408`), because SNI is
attacker-controlled and each miss synchronously mints and signs a certificate.

#### Lifecycle: rotate, revoke, generations

`generation` increments on every rotate/revoke (`:239`, `:267`). `ProxyServer.ensureMitm()` rebuilds
the TLS server whenever `mitmGeneration !== ca.generation` (`proxyServer.ts:182-194`), and
`refreshCa()` applies the change to **already-open tunnels** rather than waiting for the next
CONNECT (`:219-230`, called from `session.ts:486`, `:508`). `dropInterceptedSockets()` destroys every
socket currently being intercepted (`:210-213`); the comment at `:202-209` explains why this is
load-bearing — a browser holds an HTTPS tunnel open for minutes, so without it revoking affected
only new tunnels while plaintext kept flowing into history under a status that said interception was
off.

- **`rotate(reason)`** (`:222-241`) — builds fresh material off to the side, persists it (`:229-230`),
  clears the revocation marker (`:231`), then swaps in one step (`:232-237`); clears the leaf cache;
  bumps generation. Every client that trusted the old certificate now rejects interception until you
  install the new one — that break is the point (`:212-221`).
- **`revoke(reason)`** (`:249-269`) — deletes the stored key **first**, then `ca.pem`, then writes the
  revocation marker (`:257-259`), and only then drops in-memory state. The ordering is deliberate
  (`:252-256`): the reverse can leave the app believing the CA is gone while the trusted certificate
  and its key both remain on disk.
- Both are audited as `ca.rotated` / `ca.revoked` with reason and fingerprint (`session.ts:487-492`,
  `:509-514`) and appended to a project history bounded at 50 entries (`:119-120`, `:520-524`).
- **Revocation survives reopening.** If the marker exists and no key/cert pair is present,
  `loadOrCreate` restores the revoked state rather than silently generating a new CA (`:188-195`).

> **The AI mesh can rotate and revoke the CA** when `allowCertOps` is granted — tools `issue_ca` and
> `revoke_ca`, recorded with actor `ai-mesh` (`ai/tools.ts:261`, `:265`, `:271`, `:274`, `:280`). A
> rotate breaks every client that trusted the old certificate.

> **No CRL, no OCSP.** "Revoked" means "this app will no longer sign leaves with this CA" — nothing
> external honours it (`certificateAuthority.ts:20-22`). Removing trust from the client is the
> removal command in [6.7](#67-guided-ca-setup), and it is a separate action you must take.

### 6.6 No CA, or an untrusted CA

Two different states — do not confuse them.

**CA revoked (no CA material at all).** `ensureMitm()` returns `undefined` (`:177-181`) and
`onConnect` calls `passthrough()` (`:321-347`): a blind TCP relay to `host:port`, still answering
`200 Connection Established` with `Proxy-agent: TACNOC` (`:339`), piping bytes both ways (`:341-342`).
An empty host is destroyed instead of dialled (`:323-326`). **Nothing is captured** — the function is
documented as "Captures nothing" (`:321`) and emits no exchange.

> A counter is incremented and an info line logged (`:327-328`), and `ProxyServer.passthroughTunnels`
> exposes it (`:124-127`) — but **nothing in the app reads that getter**:
> `grep -rn "passthroughTunnels" src/ test/` matches only its own declaration. It is not surfaced in
> the UI or any status DTO. The Certificate view instead renders a "This project has no CA" box
> driven by an empty `certPem` (`CertificateView.tsx:140`, `:176-193`).

**CA present but the client does not trust it.** The CONNECT is answered `200`, TLS termination is
attempted, and the client aborts the handshake. `mitm.on('tlsClientError')` is an explicit no-op —
"client TLS errors (e.g. untrusted CA) are expected; ignore" (`:164-166`). No exchange is recorded,
no error is surfaced in the app.

> **This is the silent failure the guided setup exists to catch.** You see a browser certificate
> error and an empty history, and nothing anywhere in TACNOC says why.

### 6.7 Guided CA setup

Optional — plain `http://` is captured with no certificate at all. The procedure is in
[3.2](#32-install-the-ca-and-prove-interception-works); the commands and their reasoning are here.

The engine renders the command with your saved path already quoted for the target shell
(`installInstructions.ts:55-59`; regression-tested for spaces and apostrophes at
`test/engine/qaqc-v053.test.ts:258-263`). **TACNOC hands you a string; you run it** (`:10-14`). The
app never modifies an OS trust store.

| Platform | Install | Remove |
|---|---|---|
| Windows (PowerShell or Command Prompt, **no admin**) | `certutil -addstore -user Root "<path>"` | `certutil -delstore -user Root "TACNOC Project CA"` |
| macOS (Terminal, **no sudo**) | `security add-trusted-cert -r trustRoot -k ~/Library/Keychains/login.keychain-db '<path>'` | `security delete-certificate -c "TACNOC Project CA"` |
| Linux — Chrome/Chromium/Edge NSS store | `certutil -d sql:$HOME/.pki/nssdb -A -t "C,," -n "TACNOC Project CA" -i '<path>'` | `certutil -d sql:$HOME/.pki/nssdb -D -n "TACNOC Project CA"` |

Source: `installInstructions.ts:84`, `:98`, `:115`, `:129`, `:145`, `:159`; shells named at `:78`,
`:109`, `:139`. Each takes the narrowest trust that works — current user not machine, login keychain
not System (the macOS command deliberately omits `-d`, verified at `qaqc-v053.test.ts:250-253`), the
browser's own NSS store not the system CA bundle. Install `libnss3-tools` if `certutil` is missing
(`:144`). Each platform also gets a click-by-click alternative — `certmgr.msc` on Windows (`:89-92`),
Keychain Access on macOS (`:120-123`).

Expected output: Windows prints `Certificate added to store.` plus a Windows security prompt
confirming the root (`:85-86`); macOS prompts for your login password (`:116-117`); Linux prints
nothing and needs a browser restart (`:146-147`).

> **The separate-trust-store note differs by platform — read yours, not a summary.**
> - Windows (`:100-101`): *Firefox and Tor Browser keep their own certificate stores and ignore the
>   Windows one* — import at Settings → Privacy & Security → Certificates → View Certificates →
>   Authorities → Import, ticking "Trust this CA to identify websites".
> - macOS (`:131-132`): the same warning for **Firefox only** (Tor Browser is not named).
> - Linux (`:161-162`): the note is **not about Firefox at all** — it warns *against* installing into
>   `/usr/local/share/ca-certificates`, because that makes every process on the machine trust the
>   interception CA. Firefox on Linux is covered by a normal guide step at `:150-153`.
>
> `docs/certificate-management.md:60-64` calls the separate-store problem the single most common
> reason a correct-looking install captures nothing.

**Removal is part of the procedure, not a footnote.** Run it the moment the engagement ends.

### 6.8 How interception is verified

The README claim — verification "from decrypted traffic rather than from configuration" — is
accurate. The implementation is one SQL query:

```
SELECT COUNT(*) AS n FROM exchanges WHERE scheme = 'https' AND source = 'proxy'
```

`src/engine/storage/historyRepo.ts:219-224` (query text at `:221`).

Both filters matter, and `source = 'proxy'` is the whole point (`:206-218`). Repeater and Variation
send HTTPS over the engine's own Node TLS stack: they never present the project's leaf certificate to
anything and never consult any trust store, so they succeed whether or not the CA was ever installed.
Counting them let a single engine-generated probe report "TLS interception is working" over a browser
that was refusing every intercepted connection.

That count is exposed three ways, all from the same query:

- `getCaInfo().interceptedHttpsExchanges` (`session.ts:444`) — drives the CA view's `verified` flag,
  strictly `> 0` (`CertificateView.tsx:75`);
- `getCaStatus().observedHttpsExchanges` (`session.ts:470`);
- the preflight `ca-trust` check — `ok` with a count, or a `warning` titled "No decrypted HTTPS
  traffic has ever been captured" when `interceptionEnabled && history.exchanges > 0 &&
  observedHttpsExchanges === 0` (`preflight.ts:160-178`).

Regression-tested at `test/engine/qaqc-v053.test.ts:136-148`: `repeater`/`https` and
`variation`/`https` rows leave the count at 0 while `countByScheme('https')` reads 2; a
`proxy`/`https` row moves it to 1; a `proxy`/`http` row leaves it there. Session-level DTOs are
covered separately at `:151-161`.

> **What this check does not prove.** It is a monotonic historical count over the whole project, not
> a live state. One decrypted exchange from a week ago keeps it reading "HTTPS interception working"
> forever — including after you have uninstalled the CA from the browser, after a `rotate`
> invalidated it, or from a different browser than the one you are about to test with. It proves
> *some* client trusted *some* CA generation at *some* point in this project's life. Issuing a new CA
> resets the guide's UI state (`CertificateView.tsx:60-68`) but does **not** reset the count.

### 6.9 HTTP/2 and HTTP/3

HTTP/2 interception is implemented and on by default (`defaultEngineConfig().interceptHttp2 = true`,
`config.ts:50`), plumbed as `enableHttp2` (`session.ts:389`) and toggled by "Intercept HTTP/2 (ALPN
h2)" (`SettingsView.tsx:216-223`).

- ALPN offers `h2` first (`:116-118`); `allowHTTP1: true` keeps http/1.1 clients working (`:141`).
- h2 requests are **translated to HTTP/1.1 upstream**: `normalizeRequestHeaders` strips
  `:`-prefixed pseudo-headers and synthesizes a `Host` from `:authority` (`:1035-1047`);
  `buildOutboundHeaders` refuses to forward any `:` header as a second guard
  (`proxyUtil.ts:36-38`). The upstream leg always requests `ALPNProtocols: ['http/1.1']` (`:571`).
- Captured exchanges are labelled `HTTP/2` (`:397`, `:407`).
- Responses back to an h2 client are lowercased and lose the reason phrase, as h2 requires
  (`writeResponseHead`, `:1010-1028`, h2 branch `:1018-1022`).
- Verified end to end at `test/engine/proxy.test.ts:187-224` (real h2 GET and h2 POST body).

**HTTP/3 / QUIC is not intercepted at all.** Clients normally fall back to h2/h1; if one insists on
h3, disable HTTP/3 in the browser (`certificate-management.md:102-104`).

> **Fidelity caveat on h2:** header casing is normalized by the protocol on the h2 leg, not lost by
> the proxy (`certificate-management.md:97-99`). If you are hunting header-casing or
> duplicate-header behaviour, force `http/1.1` by unticking Intercept HTTP/2 (`:100-101`).

### 6.10 WebSockets

Handled by `onUpgrade` (`:796-868`) on both the plain listener (`ws://`, `:236-238`) and the MITM
server (`wss://`, `:160-162`).

Flow: derive context; destroy the socket if the host is unresolvable (`:806-812`); open the upstream
leg — `tls.connect` with `rejectUnauthorized:false` and `ALPNProtocols:['http/1.1']` for `wss://`,
plain `net.connect` otherwise (`:814-823`); re-emit the request line plus serialized headers
(`:830-831`); buffer the response until `\r\n\r\n`, bounded at 64 KiB (`MAX_HANDSHAKE_BYTES`, `:65`,
`:842-847`, both peers destroyed if exceeded); capture the 101 as an exchange tagged `websocket`
(`:939-987`, tag `:979`); then tunnel.

Frame capture (`tunnelWithCapture`, `:874-937`) uses a streaming RFC 6455 parser per direction
(`wsFrame.ts`). It reassembles fragmented data messages, unmasks client→server frames, surfaces
`text`/`binary`/`ping`/`pong`/`close`, and stays wire-aligned across oversized frames by draining the
excess (`wsFrame.ts:1-11`, `:132-150`, `:203-226`). On a protocol violation it sets `broken`, releases
its buffer, and **stops capturing while the tunnel keeps forwarding** (`:56-80`). Backpressure is
handled both directions via `pause`/`drain`/`resume` (`proxyServer.ts:917-927`).

> **Hard limits with no UI or config exposure:** 5 000 messages per connection and 64 KiB captured per
> message (`:62-63`). Past 5 000, `emit` silently returns and frames keep flowing untouched (`:889`).
> Storage is aware of the ceiling — `WsRepo.listByExchange` defaults to a 6 000-row limit so stored
> frames are never hidden by retrieval (`wsRepo.ts:52-54`).

> **Bytes are forwarded unchanged. There is no WebSocket interception, editing, or replay** — the
> parsers only read (`:870-873`); `README.md:183-185` lists editable WebSocket replay as not
> implemented, and `capability-matrix.md:14` rates WebSockets "Partial".

> **The "Capture WebSocket frames" toggle is all-or-nothing** (`SettingsView.tsx:208-215`): with
> `captureWebSockets:false`, `captureWebSocketHandshake` returns immediately (`:944`) and the tunnel
> degrades to a raw `pipe` (`:855-859`) — so you get **no history row at all** for that connection,
> not merely a handshake without frames. The same raw-pipe path is taken if no `onWebSocketMessage`
> sink is wired, though the session always wires one (`session.ts:387`).

### 6.11 Interception: edit, forward, drop

The `Interceptor` (`src/engine/proxy/interceptor.ts`, 130 lines) is a queue, not a rules engine.
Requests and responses toggle independently (`interceptor.ts:29`).

- With interception off, `holdRequest`/`holdResponse` resolve immediately as `forward` (`:52`, `:71`).
- Toggling interception **off** releases the queue as **forward** — "stop holding my traffic and let
  it through" (`:37-48`, comment `:42-44`).
- **Emergency stop and proxy shutdown release as `drop`** (`session.ts:742`, `proxyServer.ts:266`).
  `releaseAll()` defaults to `drop` so a future caller that forgets to choose fails safe (`:111`).
  The comment at `:99-109` records the bug this fixed: releasing on `forward` made the emergency stop
  deliver every queued request to the target.

Two fidelity guards, both of which **fail loud rather than silently truncate**:

- An intercepted **request** body over `limits.body.maxCapturedBytes` is answered `413` with an
  explanatory message and is **not forwarded** (`proxyServer.ts:440-458`). Turn interception off for
  large uploads or they simply fail, and the failure looks like the target rejecting you.
- An intercepted **response** over the cap destroys the client response mid-transfer so the client
  sees a failed transfer (`:655-671`).

Neither applies when interception is off — the streaming path forwards every byte and just marks the
capture truncated.

Edits replace method, target, headers and body on the request (`:487-501`) and status code, status
message, headers and body on the response (`:701-715`), subject to the `Content-Length` limitation in
[6.3](#63-plain-http).

### 6.12 Timeouts and connection handling

| Leg | Timeout | Behaviour |
|---|---|---|
| Upstream HTTP/HTTPS request | `limits.upstreamTimeoutMs` (default 30 000 ms) as Node's socket-inactivity `timeout` | `:561`; on fire, `originReq.destroy(new Error('upstream timeout'))` (`:587`) |
| Client→proxy sockets | **none set** | no `server.timeout`, `keepAliveTimeout`, `headersTimeout`, `requestTimeout` or any `setTimeout(` anywhere in `src/engine/proxy/` (verified by grep) — Node defaults apply |
| CONNECT passthrough relay | **none** | `passthrough()` sets no timers (`:321-347`) |
| WebSocket upstream connect / tunnel | **none** | `onUpgrade` sets no timers (`:796-868`) |
| Repeater / Variation (`sendRaw`) | socket timeout **and** a wall-clock deadline | `net/httpClient.ts:99`, `:78` |

> **Note the asymmetry.** The Repeater path has a hard wall-clock deadline that keeps a partial body
> and marks it truncated (`httpClient.ts:72-78`, `:131-137`); the **proxy path has only an inactivity
> timeout**. A slow-drip origin can hold a proxied exchange open indefinitely as long as it sends a
> byte inside every timeout window.

Error handling is asymmetric on purpose (`:588-608`, `:610-625`): before response headers are sent,
an upstream failure produces `502 Bad Gateway (proxy upstream error)` (`:597`); **once streaming has
begun, the client response is destroyed** (`:594-595`) rather than having an error string appended
into the body — a truncated transfer is a real error signal, a "complete 200" with an error string
glued on is silent corruption. Regression-tested by "aborts (does not poison the body) on a
mid-stream upstream timeout" at `test/engine/proxy.test.ts:366`.

### 6.13 What the proxy does not do

- **No upstream proxy, no SOCKS, no proxy chaining.** Every outbound connection is made directly to
  the origin (`:567`, `:574`, `:823`). If your engagement requires egress through a specific IP, you
  must handle that outside TACNOC.
- **No transparent / invisible proxy mode.** The client must be configured to use the proxy
  explicitly.
- **The proxy does not enforce scope** ([5.6](#56-where-scope-is-enforced-and-where-it-is-not)).
- **The proxy does not apply your engagement identity** ([5.7](#57-engagement-identity)).
- **The proxy announces itself.** Every CONNECT response carries `Proxy-agent: TACNOC` (`:306`,
  `:339`), including on the no-interception passthrough path.
- **No proxy match/replace rules.** Edits are manual, per-message, through the intercept queue
  (`capability-matrix.md:13`; `README.md:183-186`).
- **Emergency stop does not stop the proxy.** `emergencyStop()` halts Variation jobs and drops the
  intercept queue (`session.ts:736-745`); it contains no call to any proxy stop. To stop traffic,
  toggle the Proxy chip (`App.tsx:187-194`).

### 6.14 Recovery: this project cannot be opened

See [4.7](#47-the-secret-store-and-the-cross-context-trap). In brief: the usual cause is **a
different build of the same app on the same machine** (packaged vs. dev launch), because
`safeStorage` keys off `userData`. `ElectronSecretStore.get` throws rather than returning `null`,
naming the app identity and `userData` path in use. The fix ships in the repo:

```
node scripts/reseal-project-secrets.mjs <projectDir> <oldUserDataDir>
```

---

## 7. The workbench tools

Seven engine modules under `src/engine/`, surfaced in the UI under the sidebar groups **Traffic**
(`Target Map`) and **Workbench** (`Repeater`, `Variation`, `Sequencer`, `Encoder / Decoder`,
`Compare`) — `App.tsx:35-75`. The analysis modules (`src/engine/analysis/`, except the sequencer)
have no dedicated panel; they are reachable through the engine API and the AI mesh tool registry
only. The Variation engine has its own section, [8](#8-automation-the-variation-engine-and-its-limits).

### 7.1 Which tools touch the network

The single most important table in this section. Two of the seven modules emit packets. They are
gated differently, and one of them is **not gated at all by the engine**.

| Module | Emits traffic? | Engine scope gate | Notes |
|---|---|---|---|
| `repeater/` | **Yes** | **None** | `repeater.ts:7-8`. Scope is *evaluated* only to stamp `inScope` on the recorded exchange (`:168`). `session.sendRepeater` adds no gate (`session.ts:680-692`) |
| `variation/` | **Yes** | **Twice** | Refused at job creation (`variationEngine.ts:144-154`); every rendered request re-checked against the rendered path (`:338-362`) |
| `scanner/` | No | **None, and none needed** | Checks never generate traffic (`scanner/types.ts:4-5`). Runs on *every* ingested exchange, in scope or not (`session.ts:319-341`) |
| `transforms/` | No | n/a | Pure, side-effect free (`codec.ts:5-6`) |
| `compare/` | No | n/a | Pure functions (`compare.ts:3`) |
| `target/` | No | Per-endpoint flag | Each endpoint carries `inScope` from a live evaluation (`siteMap.ts:106-111`) |
| `analysis/` | No | Varies | `surface.ts` drops out-of-scope endpoints (`:328-331`); `proof.ts` reads captured exchanges; `huntMemory.ts` recall fails closed to the open engagement (`session.ts:1090-1099`) |

> **Internalise this: the Repeater will send a request to a host that is not in your project scope
> and will not stop you.** The AI mesh compensates by adding its own gate in front of `send_repeater`
> (`ai/tools.ts:640-648`) — but that gate lives in the mesh tool, not in the Repeater.

### 7.2 Repeater

Three files: `repeater.ts` (send loop, 290 lines), `rawHttp.ts` (raw parse/serialize, 61),
`cookieJar.ts` (a deliberately partial cookie store, 84).

**What it does.** Sends one fully operator-authored HTTP/1.1 request to an origin, optionally
following redirects, and records the result as an `HttpExchange` tagged `source: 'repeater'`
(`:172`), `automated: false` (`:177`).

**Inputs** — `target: { scheme, host, port, raw }` where `raw` is the complete request text
(`shared/repeater.ts:17-23`); `options: RepeaterOptions` — `followRedirects`, `maxRedirects`,
`timeoutMs`, `useCookieJar` (`:25-31`); an optional `CookieJar` (session-scoped; `session.ts:688`
passes the session jar only when `useCookieJar` is set).

**Outputs** — `RepeaterResult`: the `HttpExchange`, a `redirects: RedirectHop[]` trail, optional
`TlsInfo`, and `totalMs` (`:38-44`). `TlsInfo` carries protocol, cipher name, `authorized`, any
`authorizationError`, subject/issuer CN, `validFrom`/`validTo`, and `fingerprint256`
(`repeater.ts:240-250`; type `shared/repeater.ts:5-15`).

**Raw editing fidelity.** `parseRawRequest` preserves header order, casing and duplicates
(`rawHttp.ts:3-5`), tolerates LF-only line endings (`:19`), and throws on a malformed request line
(`:27`) or a header line without a colon (`:33`).

**Redirect handling** (only when `followRedirects` is true):

- Followed codes: `301, 302, 303, 307, 308` (`:62`).
- On a **cross-host** redirect, `Cookie` and `Authorization` are dropped from the carried headers
  (`:137-139`).
- `303`, and `301`/`302` on a non-GET/HEAD method, are rewritten to `GET` with an empty body and
  `Content-Length`/`Content-Type`/`Transfer-Encoding` dropped (`:142-151`).
- The `Host` header is rewritten per hop (`:152-156`).

> **Only the final hop becomes an exchange.** One id is minted before the loop (`:84`) and reused for
> the single stored exchange (`:170`); intermediate hops survive only as `{url, status}` entries in
> `redirects` (`:125`). The stored request line, host, path and headers are the **final** hop's
> (`:169-189`), and `timing.durationMs` spans every hop (`:188`). If you need each hop in history,
> send each hop yourself.

> **Cookie jar limits.** `cookieJar.ts:1-8` says it plainly: not a full RFC 6265 implementation. It
> stores `name=value` per host, tracks `Secure` so Secure cookies are withheld from cleartext
> requests (`:49-57`), and treats `Max-Age<=0` or a past `Expires` as a deletion (`:73-83`).
> **`Path` and `Domain` are parsed but not enforced**, and there is no subdomain matching — the jar
> is a `Map` keyed on the exact host string (`:24`, `:50`).

**TLS posture.** Origin certificate validation is disabled (`rejectUnauthorized: false`, `:227`) and
the result is *recorded* in `TlsInfo.authorized` rather than enforced. ALPN offers `http/1.1` only
(`:228`) — the Repeater cannot speak HTTP/2 to an origin.

**Engagement identity.** If the profile mandates identification, `applyIdentity` rewrites the
outbound headers per request (not once per session), and the *rewritten* headers are what is stored
in history (`:99-103`).

**The panel** (`RepeaterView.tsx`). Toolbar (`:97-155`): scheme selector (`https` default), host box,
port box (443 default), **`follow redirects`**, **`cookie jar`**, **`Cookies (n)`**, a
**`Load saved…`** dropdown, **`Save`**, and **`Send ▶`**. The left **`Request`** pane is a plain
textarea; the unseeded default is `GET / HTTP/1.1` / `Host: example.test` / `User-Agent: TACNOC` /
`Accept: */*` (`DEFAULT_RAW`, `:11-12`). The right pane shows the response through a `MessageViewer`,
titled `<status> · <size> · <ms>` and, when TLS was used, `TLS <protocol> <cipher> · valid |
UNVERIFIED`, plus a redirect count (`:214-232`).

Send options are **fixed in the UI**: `followRedirects` off (`:20`), `useCookieJar` off (`:21`), and
on send it passes `maxRedirects: 10, timeoutMs: 20000` (`:51-54`). There is no per-send timeout
control. History and Target Map both offer **`Send to Repeater →`**, seeding scheme/host/port/raw
through the store (`TargetView.tsx:143-148`, `HistoryView.tsx:100-102`, `:224-225`, consumed at
`RepeaterView.tsx:38-45`).

**`Save`** stores the current scheme/host/port/raw under an auto-generated name `<host><HH:MM:SS>` —
concatenated with no separator, e.g. `example.test14:03:22` (`:66-78`, name built at `:69`) — and
**there is no rename control in the UI**.

**`Cookies (n)`** expands a `Cookie jar` panel with `Host · Name · Value`, plus **`Refresh`** and
**`Clear jar`** (`:157-195`).

> **The cookie-jar table is the inverse of the message viewer's mask.** Its values carry the
> `reveal-mask` class permanently and are additionally truncated to 40 characters — blurred, with
> **no reveal control at all** (`:186-188`), unlike `MessageViewer`, which has one.

> **Repeater sends are not audited.** There is no audit call anywhere in `src/engine/repeater/`; the
> only engine modules that append audit entries are `session.ts`, `variationEngine.ts`,
> `ai/orchestrator.ts` and `projectStore.ts` (import replay). The audit log is an *automation* log;
> the record of manual work is HTTP History.

### 7.3 Passive scanner

Three files: `types.ts` (the check interface), `passiveScanner.ts` (the runner), `checks.ts` (eleven
built-ins).

**Contract.** A `ScannerCheck` inspects **one already-observed exchange** and returns zero or more
findings. Checks never generate network traffic (`types.ts:4-5`). The runner fills in
ids/timestamps, redacts evidence, and hands findings to the store (`passiveScanner.ts:78-98`).

**When it runs.** On every exchange ingested by the session — proxy traffic, Repeater sends, and
Variation results alike — asynchronously and best-effort; a scan failure is logged, never fatal
(`session.ts:330-340`).

> **It is not filtered by scope.** `ingest()` calls `this.scanner.scan(ex)` with no `inScope`
> condition (`session.ts:319-341`). Out-of-scope traffic that crossed the proxy is scanned and
> produces findings like anything else — and a `Finding` carries **no scope field at all**
> (`shared/findings.ts:27-40`, `findingsRepo.ts:7-22`); only the linked exchange does. Findings from
> a host you are not authorized to test appear in Findings unmarked.

**Body materialization** (`passiveScanner.ts:116-142`):

- `MAX_SCAN_BODY_BYTES` = **1 MiB**; larger bodies are truncated to that prefix (`:19`, `:135`).
- `gzip` bodies are inflated with `maxOutputLength` set to the same 1 MiB — a zip-bomb body is
  skipped rather than allowed to exhaust memory (`:124-134`).
- A body whose MIME does not match
  `/(text\/|json|xml|javascript|x-www-form-urlencoded|html)/i` is scanned as text **only if it is
  ≤ 4096 bytes** (`:21`, `:137-140`). Larger non-textual bodies reach checks as an empty string.

> A secret at byte 2,000,000 of a JSON response, or inside a 5 KiB binary body, is invisible to
> `secrets-in-response`.

**Isolation.** Each check runs inside try/catch — "a faulty check cannot crash the scan" (`:1-5`,
`:76`, `:99-101`). Extension checks run in the isolated extension worker and are merged in
afterwards, also guarded (`:104-112`).

**Evidence redaction is applied twice.** Checks redact their own excerpts, and the runner
re-redacts every excerpt on the way out — described in the code as defense-in-depth (`:90-94`).

The eleven built-in checks are catalogued in [14.7](#147-the-11-passive-checks). Three behaviours
worth pulling out here:

> - **`reflected-input` is an observation, not a finding.** `info`/`tentative`, title beginning
>   `"Observation:"` (`checks.ts:476`), description stating it "is an OBSERVATION only — it is not
>   confirmed to be exploitable… this check does not test for injection" (`:480-482`). Do not report
>   it as XSS.
> - **The `cors` check is an if/else-if chain** (`:156`, `:174`, `:196`, `:215`). An endpoint matching
>   more than one branch reports only the first.
> - **`verbose-errors` contains a dead status branch** — `if (!m && statusCode < 500) return [];
>   if (!m) return [];` (`:343-344`). Both arms return the same thing, so the check fires on the
>   regex match alone; response status has no effect.

**What is not here.** No active probing of any kind — no payload is ever sent by the scanner
(`README.md:183`; `capability-matrix.md:19`).

#### Finding storage, dedupe, and suppression

`dedupeKey` is `"<module>|<check-supplied key>"` (`passiveScanner.ts:82`), and check keys are built
from an **endpoint key** of `host:port + pathname` (`checks.ts:10-17`).

> **The dedupe is narrower than the key suggests.** `FindingsRepo.upsert` treats a finding as a
> duplicate only when **both `exchange_id` and `dedupe_key`** already match (`findingsRepo.ts:50-55`).
> There is no cross-exchange dedupe. Browse the same page twenty times and you get twenty "Missing
> Content-Security-Policy" findings on the same endpoint. Use suppression rules, not the dedupe key,
> to control finding volume.

Suppression rules match on `module` / `dedupeKey` / `host`, empty fields acting as wildcards — with a
guard that a rule populating **none** of the three never matches anything (`findingsRepo.ts:156-172`,
comment `:158-160`). Host-scoped rules also fail safe: when the caller does not supply the host, the
rule does not match and the finding is shown (`:45-47`, `:164-168`).

> A suppressed finding is still **written** to the database and merely not announced — `upsert`
> returns `!suppressed` with the comment "Written, but invisible — do not announce it."
> (`findingsRepo.ts:57-79`).

`session.scannerModules()` returns the built-in module/version list plus extension check modules
(`session.ts:674-676`).

### 7.4 Sequencer

`src/engine/analysis/sequencer.ts`. Statistically screens a set of captured tokens for
predictability. The file's first sentence sets the boundary: "Results are screening signals, **not a
cryptographic proof of unpredictability**" (`:2-3`).

**Inputs.** `analyzeTokenSamples(samples: string[], encoding)` where encoding is
`text | hex | base64 | base64url` (`shared/sequencer.ts:3`; decoders `sequencer.ts:151-185`). In the
UI, samples are newline-separated text pasted into the Sequencer panel; blank and whitespace-only
lines are dropped (`SequencerView.tsx:11-13`).

> **There is no harvesting loop.** The panel's only engine call is `analyzeTokenSamples`
> (`SequencerView.tsx:18`), and nothing collects tokens from history or generates them from the
> target. You paste what you already captured (`capability-matrix.md:18`).

**Input limits** (`sequencer.ts:15-18`): `MAX_SAMPLES` 100,000 (`:35-37`); `MAX_SAMPLE_BYTES` 64 KiB
per sample (`:44-48`); `MAX_TOTAL_BYTES` 16 MiB decoded in total (`:50-54`); positional entropy
computed over at most the first **256** decoded bytes (`:213-214`). Decoding is strict: hex must be
even-length hex after stripping `0x`/whitespace/`:`/`-` (`:155-163`); base64 and base64url are
validated against the same length rule so a value cannot be accepted under one alphabet and rejected
under the other (`:170-179`).

**Outputs** (`shared/sequencer.ts:18-39`) — 20 fields: sample/unique/duplicate counts, total bytes,
min/max/mean decoded length, alphabet size, **Shannon bits per byte**, **min-entropy bits per byte**,
**estimated entropy bits per token** (sum of positional entropies weighted by per-position coverage,
`sequencer.ts:74-77`), **observed token min-entropy bits** (`:88`), bit-one ratio (`:94`), **monobit
p-value** (`:95`), **serial correlation** of adjacent decoded bytes (`:96`), **compression ratio**
(raw-deflate level 9 over the concatenated samples, `:97-98`), a positional entropy array, a list of
observations (`{level:"warning"|"info", message}`), and an overall assessment.

**Assessment** is one of `insufficient-data | poor | weak | no-obvious-bias`
(`shared/sequencer.ts:4`), decided numerically (`sequencer.ts:359-379`):

- `insufficient-data` — fewer than 100 samples **or** under 1 KiB decoded (`:363`).
- `poor` — any of: Shannon < 5 bits/byte; estimated per-token entropy < 32 bits; duplicate rate > 1%;
  compression ratio < 0.9 (with ≥1 KiB); monobit p < 0.01; |serial correlation| > 0.3 (`:370-377`).
- `weak` — any warning fired but none of the above (`:378`).
- `no-obvious-bias` — otherwise (`:378`).

`sequencer.ts:365-369` documents a fixed bug worth knowing as a design principle: the previous
version matched regexes against *formatted* warning strings, so a monobit p-value rendering in
exponential notation (`3.4e-27`) failed a `/p=0…/` test and the **strongest** bias was rated less
severe than a milder one. The grading is now monotonic on the numbers.

> **Read the assessment, not the warnings.** `observationsFor()` computes warnings unconditionally
> (`:253-346`) and `assess()` applies the sample-count gate afterwards (`:363`), so an
> `insufficient-data` verdict still ships warning-level observations. Quoting one of them in a report
> based on two samples is exactly the unreproducible claim the house rule forbids.

> **The best result the tool can return is `no-obvious-bias`** — absence of detected bias is not
> evidence of a CSPRNG. The monobit p-value uses a Numerical Recipes `erfc` approximation
> (`:381-405`). Per-token entropy assumes positional independence, which the observation text says
> out loud ("under the positional independence model", `:302`, `:308`). And the *warning* thresholds
> are tighter than the *grading* thresholds — a serial correlation of 0.2 raises a warning (`:317`)
> and grades `weak`, but only |r| > 0.3 grades `poor` (`:376`).

### 7.5 Encoder and Decoder

`src/engine/transforms/codec.ts`. **19 built-in transforms** in five categories (`TransformCategory`
at `:16`; registry `:161-211`) — the full table is [14.4](#144-the-19-transforms).

Behaviours that will bite if assumed otherwise:

> - **`html.decode` is a single left-to-right pass by design.** `.replace` never rescans its own
>   output, so `&amp;lt;` decodes to `&lt;` — a correct inverse of `html.encode` — rather than to `<`
>   (`:83-87`, `:88-101`). Only five named entities are recognised — `amp lt gt quot apos` (`:75-81`);
>   any other named reference is left untouched (`:99`). Numeric references are bounds-checked;
>   out-of-range or surrogate code points become U+FFFD instead of throwing (`:94-96`).
> - **`time.epoch-to-iso` guesses the unit by string length**: input of ≤ 11 characters after
>   trimming is treated as seconds, longer as milliseconds (`:122`). The comment above it says
>   "10-digit … 13-digit"; the executed test is `length <= 11`, so a 12-digit value is read as
>   milliseconds.
> - **`gzip.compress` / `gzip.decompress` are base64 in and out** (`:110-115`), not byte-in/byte-out.
> - `hex.decode` strips whitespace and **throws** `invalid hex input` on odd length or non-hex
>   (`:56-62`).
> - Hashes are hex digests of the UTF-8 bytes (`:105-107`). MD5 and SHA-1 are present for
>   interoperability with targets, not as a recommendation.

**JWT inspection** — `inspectJwt` is decode-only. The module header states it outright: "It never
verifies, re-signs, strips, or downgrades the signature/alg — there is deliberately no 'none-alg' or
signature-bypass helper here" (`:8-10`). It returns the decoded header and payload, the raw signature
segment as-is, a `wellFormed` flag (true only with all three segments), and a fixed note: "Decoded
for inspection only. Signature is NOT verified and is never altered." (`:142-158`). A segment that is
not valid base64url JSON comes back as `{_raw, _error}` rather than throwing (`:147-149`).

`applyTransform(id, input)` throws `unknown transform: <id>` for an unregistered id (`:213-217`). At
the session level, an **extension-registered transform with the same id takes precedence over the
built-in** (`session.ts:1554-1557`); `listTransforms()` returns built-ins followed by extension
transforms (`:1545-1552`).

> **The MCP surface is built-ins only.** `list_transforms` maps `BUILTIN_TRANSFORMS` directly
> (`mcp/tools.ts:219-220`) and `apply_transform` calls the built-in `applyTransform` (`:237`) —
> neither sees extension transforms, and neither honours the extension override the session applies.
> The same id can behave differently over MCP than in the app.

### 7.6 Compare

`src/engine/compare/compare.ts`. Three pure diff functions.

**`diffLines(a, b)` — line diff via LCS.** Returns `{type: 'equal'|'add'|'remove', text}[]` (`:7-12`).

> **Silent degradation above 5,000 lines.** `MAX_LINES_FOR_LCS = 5000` (`:15`). If either side
> exceeds it, the LCS table is skipped (`:22-29`) and there are **two** branches: byte-identical
> inputs return every line as `equal`; **any** difference returns every left line as `remove`
> followed by every right line as `add`. Technically a diff, practically useless — and **nothing in
> the output says the fallback fired**. `proof.ts` uses `diffLines` (`proof.ts:161`), so a proof over
> two very large bodies inherits this: `changedLines` and `excerpt` become the whole of both bodies.
> The `confirmed`/`refuted` verdict itself is unaffected — it is decided on status, header pairs, and
> raw body bytes.

**`diffJson(a, b)` — structural diff.** Parses both sides (**throws** on invalid JSON, `:73-75`) and
walks them, emitting `{path, kind: 'added'|'removed'|'changed', left?, right?}` (`:63-70`). Paths are
JSONPath-ish: `$.user.id` (`:77`, `:91`), `$.items[0]` (`:118`). Arrays are compared **positionally**
(`:115-124`) — inserting an element at the head reports every subsequent index as changed.

**`diffBytes(a, b)` — byte diff.** Returns `{equal, firstDiffOffset, leftLength, rightLength,
differingBytes}` (`:129-137`). `firstDiffOffset` is `-1` when the overlapping region is identical, or
`min(len)` when one is a prefix of the other (`:149`); `differingBytes` counts mismatches in the
overlap **plus** the absolute length difference (`:155`).

> **Compare's byte mode is not a binary comparer.** The panel UTF-8 encodes whatever you typed into
> the two text areas and base64s it (`CompareView.tsx:25`, `lib/format.ts:18-23`). To byte-diff real
> binary you must call `diffBytes` / the `diff_bytes` tool with your own base64.

> **Two documentation discrepancies.** (1) The MCP `diff_bytes` description advertises "first
> difference offset, **common prefix and suffix length**, and equality" (`mcp/tools.ts:266`) and
> `docs/mcp-server.md:22` repeats "common prefix/suffix" — the implementation returns neither; the
> five fields above are all there is, and `firstDiffOffset` happens to equal the common prefix
> length. (2) `ByteDiff.differingBytes` is documented as "Count of differing bytes within the
> overlapping region" (`:135`) but the implementation adds the absolute length difference on top
> (`:155`). Trust the type and the code.

`compare.ts` is consumed by the Compare panel (`main/ipc.ts:230-233`), by MCP (`diff_text`,
`diff_json`, `diff_bytes`), by the AI mesh (`diff_text`, `diff_json` only — there is no mesh
`diff_bytes`), and internally by `analysis/proof.ts` (`:30`).

### 7.7 Target map

`src/engine/target/siteMap.ts`. Builds a site map from **bounded history metadata rows** — origins,
then normalized paths under each (`:1`). It is an inventory of what you already captured; there is
**no crawler and no content discovery** (`capability-matrix.md:11`).

**Input.** `buildTargetMap(rows, scope, totalExchanges)` (`:34-38`), called from
`session.getTargetMap(maxExchanges = 100_000)` against `history.siteMapRows()` (`session.ts:651-655`).
The IPC channel passes the same default (`main/ipc.ts:212`).

**Output** (`shared/target.ts:32-43`) — `TargetMap { generatedAt, totalExchanges, analyzedExchanges,
truncated, sites[] }`, each site holding scheme/host/port, request count, first/last seen,
`inScopeEndpoints`, and sorted endpoints (`:20-30`). Each `TargetEndpoint` carries path, sorted
methods, status codes, MIME types, **query-parameter names**, request count, first/last seen,
`latestExchangeId`, and `inScope` (`:5-18`, populated `siteMap.ts:112-124`).

Details that affect how you read it:

- **Host canonicalization matches the scope gate**: `normalizeHost` lowercases and strips all
  trailing dots, so `Example.com` and `example.com.` collapse into one site (`:43-47`).
- **Scope is evaluated on the origin-form path *including the query*** — the exact shape the live gate
  sees (`:20-21`, `:67-69`, `:106-111`).
- **"Latest" uses strictly-greater comparison** so a same-millisecond tie does not overwrite the
  newest row's id with an older one (`:93-100`).
- **`parameterNames` are query-string names only** (`:154-176`). Body parameters, JSON fields and path
  parameters are not enumerated. This matters directly for the surface ranker, which scores on these
  names.
- **`truncated`** is `rows.length < totalExchanges` (`:149`); when true, the per-site/endpoint
  `requestCount` and `firstSeen` describe **only the analyzed window** (`shared/target.ts:36-41`).
- A target whose URL `new URL()` rejects (e.g. an unbracketed IPv6 authority) still yields a path and
  parameter names through a fallback parser (`:158-166`).

> **`Send to Repeater →` is the only handoff that exists.** `seedRepeater` is the only seed in the
> tree — `store.tsx:54`, `:183`; `HistoryView.tsx:101`; `TargetView.tsx:145`. No `seedVariation` or
> `seedSequencer` exists anywhere in `src/`; those panels are typed into by hand.

### 7.8 Analysis: surface ranking, proof, hunt memory

Three modules under `src/engine/analysis/`, all **pure and offline**, reachable through the engine
API and the AI mesh tool registry, **not** through a workbench panel. See also
[`engagement-and-hunting.md`](engagement-and-hunting.md).

#### `surface.ts` — deterministic attack-surface ranking

`rankAttackSurface(map, limit = 25)` (`:321`) scores each **in-scope** endpoint of a target map by
which defect class it most likely hides. Ten classes (`:26-36`): `access-control`, `ssrf`,
`path-traversal`, `injection`, `template-injection`, `command-injection`, `open-redirect`,
`reflection`, `auth`, `state-change`. Each has a hand-built parameter-name vocabulary (`:43-260`).

Scoring (`:336-374`):

| Signal | Points |
|---|---|
| A parameter name token in a class vocabulary | **3** (`:351`) |
| A path word token in a class vocabulary | **1** (`:355`) |
| A numeric / UUID / ≥24-hex segment in the path | **4** to `access-control` (`:302-312`, `:363`) |
| A mutating method (POST/PUT/PATCH/DELETE) present | **2** to `state-change` (`:314`, `:370`) |
| Mutating method *and* `access-control` already scored | **+2** to `access-control` (`:371-373`) |

Tokenization splits camelCase and lowercases; **only names are matched, never values** (`:288`,
`:295-299`). `limit` is clamped to 1–100 (`:411`). Out-of-scope endpoints are **dropped, not ranked**,
and reported as `outOfScopeSkipped` (`:328-331`, `:280-281`). Every result carries a fixed note:
ranking "only reorders where to look. It cannot add a host, an endpoint, or a finding, and every lead
still needs an observed-versus-control differential before it is real" (`:395-397`).

> **Stated limitation, from the code.** `:286-294` warns that parameter names are *not*
> untrusted-input-free: they come from captured traffic, and the target chooses the links and XHR URLs
> your browser follows, so a target **can** steer this ranking by emitting a decoy `?imageUrl=` on an
> endpoint of its choosing. The cost is misspent attention — the scope gate still bounds what may be
> touched, and the proof gate still decides what is real.

> **It scores query-parameter names only**, because the target map enumerates nothing else
> ([7.7](#77-target-map)) — an API that takes everything in a JSON body ranks near zero regardless of
> its real surface.

`session.rankAttackSurface(limit = 25)` builds the map with `getTargetMap()`'s default
100,000-exchange bound (`session.ts:1012-1014`), so ranking inherits the truncation behaviour.

#### `proof.ts` — the differential gate

`proveDifferential(control, test, claim)` (`:149-153`) reads two already-captured exchanges and grades
the difference. The premise (`:4-10`): **the model proposes, the engine proves.** Nothing can be
marked proven by assertion; a caller must name a CONTROL and a TEST exchange the engine can read.

Outcomes: `confirmed | refuted | inconclusive` (`:32`). Grading order (`:200-290`):

1. `inconclusive` if control and test are the **same exchange** (`:200-204`).
2. `inconclusive` if either exchange has no response (`:205-209`).
3. `inconclusive` if the two **requests are identical** — "any difference between the responses
   measures how nondeterministic the endpoint is, not how it behaves" (`:214-218`).
4. `refuted` if status, meaningful response headers, and body **bytes** are all identical (`:255-266`).
5. `confirmed` if status changed, or bodies differ, or meaningful headers differ — the reason string
   names which (`:268-286`).
6. Otherwise `inconclusive` (`:288-290`).

Precision controls:

- **Header pairs, not header names.** Comparing only the *set of names* made whole classes invisible:
  an open redirect changes `Location`'s value, session fixation changes `Set-Cookie`'s flags, a CORS
  or CSP defect changes a policy value — none add or remove a header, so all graded "refuted"
  (`:77-88`).
- **Incidental headers are excluded** so a `Date` can neither manufacture a finding nor block a
  refutation: `date, age, expires, keep-alive, report-to, x-request-id, x-trace-id,
  x-correlation-id, x-amzn-requestid, cf-ray, x-served-by, x-timer` (`:90-108`). The difference list
  is capped at 20 entries (`:121`).
- **Bodies are compared as bytes, not decoded text** — two different binary or differently compressed
  bodies decode to the same replacement characters and read as identical (`:170-173`).
- **Attributability.** `requestDelta` reports which of method / host / URL / request body / request
  headers differ (`:131-141`). More than one differing variable does not block a `confirmed`, but adds
  a caveat that the difference "cannot be attributed to any single one of them" (`:219-223`).

Caveats are attached for: a differing method (`:224-228`), a differing host (`:229-233`), a `429` on
either side ("may be rate limiting, not application behaviour", `:234-238`), a `5xx` (`:239-243`), a
truncated capture (`:244-248`), and differing lines that look like per-response noise — matched on
`csrf|nonce|token|timestamp|request[_-]?id|session|expires` (`:249-253`, `:293-297`).

`session.proveFinding()` fetches both exchange details, grades, and writes an audit entry
`proof.<outcome>` with the claim and both exchange ids (`session.ts:1022-1040`, action string `:1035`).

> **Boundary the module states about itself** (`:17-25`): it grades a **differential**, never a
> vulnerability. "The response differs" is a fact; "this is an IDOR" is an interpretation and stays
> the analyst's claim. A refutation is a real result and is recorded as one. Anything ambiguous grades
> `inconclusive` rather than rounding up.

#### `huntMemory.ts` — cross-engagement outcome store

A local append-only JSONL store, `hunt-outcomes.jsonl` (`:38`), keyed by **path shape** rather than
literal URL so a lesson transfers between objects and between targets (`:10-14`). `pathShape()`
reduces a path segment to `{id}` when it is all digits, a UUID, ≥16 hex chars, or a ≥20-char
vowel-free `[A-Za-z0-9_-]` token; other segments are lowercased (`:97-115`). `/api/orders/10432` →
`/api/orders/{id}`.

Bounds (`:38-43`): `MAX_RECORDS` 5,000 (constructor clamps the option to 100–100,000, `:135`),
`MAX_LINE_BYTES` 8 KiB (an over-long record is silently dropped, `:171`), `MAX_FILE_BYTES` 8 MiB (a
larger file is read **tail-only**, `:196-208`), `MAX_NOTE_CHARS` 600.

**Redacted on write, in that order.** Notes, claims, program, host and even the path are passed
through a `Redactor` configured to mask cookies, Authorization and secret patterns (`:127-131`,
applied `:157-168`) — and `:138-150` explains the ordering: redact first, *then* truncate, because the
reverse cuts a secret in half and leaves a fragment the redactor no longer recognises (a JWT sliced
before its third segment, a PEM block without its END line).

`recall()` merges matching records into one verdict per `(pathShape, class)` with
confirmed/refuted/inconclusive counts, `lastSeen`, the latest note, and an advisory `suggestion`
string chosen by the counts (`:269-308`; `suggestionFor` `:320-338`). Hostnames are returned **only
when the query is program-scoped** — another client's asset inventory is not context for this
engagement, and it would be egressed to the model provider along with everything else (`:290-293`).

> **`session.recallHuntHistory()` fails closed** (`session.ts:1054-1103`): recall is scoped to the open
> engagement's program label, falling back through the engagement profile, the project's
> authorization reference, then the project name. If no label can be derived, **nothing** is recalled
> rather than everything (`:1091-1099`). A freshly created project with an empty engagement profile
> recalls nothing until you set the program name or authorization reference. That is deliberate, not a
> bug. Cross-program recall exists but only when the operator asks (`allPrograms`, `:1083-1089`), never
> by a caller supplying a `program` string — because the model calling this reads untrusted target
> content (`:1068-1070`).

The module states its own authority limit (`:23-27`): **memory is advisory, never authority.** It
reorders attention and nothing else. It cannot mark a finding confirmed — only `proof.ts` does that —
and it cannot put a host in scope. The same sentence is returned with every recall result (`:310-312`).
`session.clearHuntMemory()` exists so operators working several programs under NDA can wipe it between
engagements (`session.ts:1264-1272`; `huntMemory.clear()` `:182-189`), audited as
`hunt-memory.cleared` (`session.ts:1270`).

---

## 8. Automation: the Variation engine and its limits

`src/engine/variation/` — two files: `variationEngine.ts` (job lifecycle, gates, execution, 791
lines) and `payloads.ts` (materialization, counting, iteration, rendering, 176). **This is the only
automated traffic generator in the product** and carries the densest safety controls.

It takes a base raw request containing operator-chosen position markers, substitutes payload values
at those markers per a mode, and sends the rendered requests under a rate limit and a concurrency
cap, recording every one as `source: 'variation'`, `automated: true`, with the `jobId` attached
(`:387-393`).

### 8.1 Modes and counts

(`payloads.ts:71-86`, where `lists` are the materialized payload lists per position)

| Mode | Requests generated | Assignment behaviour |
|---|---|---|
| `sniper` | `sum(len(list_i))` | One position varied at a time; others take `baseValue ?? ''` (`:101`, `:110-119`) |
| `batteringram` | `len(list_0)` | The same value in every position (`:104-109`) |
| `pitchfork` | `min(len(list_i))` | Lists advanced in lockstep (`:120-126`) |
| `clusterbomb` | `product(len(list_i))` | Full odometer cross-product (`:127-140`) |

`validatePlan` rejects any other mode string (`variationEngine.ts:502-504`). The UI defaults to
`batteringram` (`VariationView.tsx:33`).

### 8.2 Payload sources

(`shared/variation.ts:15-18`) `{kind:'list', values}`, `{kind:'range', from, to, step}`, and
`{kind:'builtin', set:'safe-structural'}` — `safe-structural` is the **only** accepted builtin;
anything else throws *"has an unsupported built-in payload set"* (`variationEngine.ts:553-556`).

`SAFE_STRUCTURAL` is **17** values (`payloads.ts:12-30`):

```
''  ' '  '0'  '1'  '-1'  '2147483647'  '9999999999'  'true'  'false'  'null'
'undefined'  'A'.repeat(256)  'unicode-한글-テスト'  '"'  "'"  '{}'  '[]'
```

`payloads.ts:4-6` states the intent: boundary/encoding/type probes, "intentionally contains no
injection, exploit, credential, or destructive strings." `shared/variation.ts:4-7` says the same at
the type level. **There is no bundled wordlist of any kind.**

### 8.3 Rate limiting, precisely

Rate limiting is **per job**, constructed fresh inside `run()`:

```
const bucket = new TokenBucket(plan.limits.requestsPerSecond);
const sem    = new Semaphore(plan.limits.maxConcurrency);
```
(`variationEngine.ts:260-261`)

- `TokenBucket` refills continuously at `ratePerSecond` with burst capacity
  `Math.max(1, Math.ceil(ratePerSecond))` (`util/rateLimit.ts:15`), and starts full (`:18`). At the
  default 8 rps that is an 8-request opening burst.
- `Semaphore` caps simultaneous in-flight requests (`rateLimit.ts:48-74`).
- **Only the token bucket is abort-aware.** `TokenBucket.take(signal?)` throws `AbortError` on an
  aborted signal (`:32-45`); `Semaphore.acquire()` takes no signal at all (`:56-67`). The job loop
  compensates by re-checking `signal.aborted` around both (`variationEngine.ts:267-275`).

> **There is no global or per-host rate pool.** Two jobs against the same host each get their own
> bucket and semaphore, so the host sees the sum. Nothing in `variationEngine.ts` coordinates across
> jobs. Three queued jobs at 8 rps against one origin deliver up to 24 rps.

### 8.4 The per-job cap and the absolute ceiling

Two distinct numbers, and the distinction matters:

| Control | Value | Source | Configurable? |
|---|---|---|---|
| `ABSOLUTE_MAX` | **100,000 requests** | `payloads.ts:32` | **No.** Hard-compiled ceiling |
| `limits.maxRequestsPerJob` | Per-plan | `shared/config.ts:29` | Yes — validated only as "a positive safe integer" (`variationEngine.ts:613-615`) |
| Engine default `maxRequestsPerJob` | 5,000 | `engine/config.ts:23` | — |
| Variation UI default | **500** | `VariationView.tsx:41` | — |

`createJob` computes the **exact** count from the true payload sizes and refuses in three layers,
each with its own message (`:156-169`):

1. `count <= 0` → *"Refusing to create job: the plan generates 0 requests."* (`:158`)
2. `count > ABSOLUTE_MAX` → *"…exceeding the absolute safety ceiling of 100000 (regardless of the
   configured per-job maximum)."* (`:162`)
3. `count > limits.maxRequestsPerJob` → *"…Narrow the payloads or raise the limit deliberately."*
   (`:167`)

`payloads.ts:65-70` records the design decision: the count is computed from the true payload sizes
and an over-limit plan is **refused rather than silently truncated**.

Creation and execution are separate calls. `createJob` returns `{ id, count }` and sends nothing
(`:186`); `run(id)` is a second, deliberate action (`session.ts:708-715`). The UI enforces this as a
two-button flow — **Prepare** (`VariationView.tsx:131`) shows *"This job will generate N request(s).
Review before running."* (`:308-311`) and **Run** (`:137`) stays disabled until a job exists (`:134`).

> **`maxRequestsPerJob` has no configured upper bound.** `ABSOLUTE_MAX` is the sole backstop. The
> UI's 500 is a UI default, not an engine limit; the engine default is 5,000.

### 8.5 Every other validated limit

| Constant | Value | Source |
|---|---|---|
| `MAX_BASE_REQUEST_BYTES` | 2 MiB | `:41`, enforced `:585-590` |
| `MAX_PAYLOAD_BYTES` | 64 KiB per **list** payload value | `:42`, enforced `:537-543` |
| `MAX_POSITIONS` | 16 positions (minimum 1) | `:43`, enforced `:505-507` |
| `MAX_RESPONSE_RULES` | 20 markers and 20 extractors | `:44`, enforced `:668-670` |
| `MAX_REGEX_LENGTH` | 512 characters | `:45`, enforced `:695-697` |
| `MAX_ANALYSIS_BYTES` | 256 KiB of response analysed | `:46`, applied `:468` |
| `maxConcurrency` | integer 1–64 | `:595-602` |
| `requestsPerSecond` | > 0 and ≤ 1000 | `:603-609` |
| `timeoutMs` | 100–120,000 | `:610-612` |
| Job `name` | ≤ 200 characters | `:499-501` |
| Destination port | integer 1–65535, scheme http/https | `:574-584` |
| Extractor `name` | 1–64 chars, unique per job | `:677-681` |
| Extractor `group` | integer 0–20 | `:682-689` |
| Response body captured | 10 MiB, then truncated | `net/httpClient.ts:39`, `:460-462` |
| Variation body capture thresholds | fixed 256 KiB spill / 10 MiB cap — **ignores project config** | `bodyLimits()`, `:460-462` |

> The 64 KiB byte cap applies to `list` values **only** (`:537-543`, inside the list branch at `:533`);
> `range` values are numbers and `builtin` is the fixed 17-value set, so neither is byte-checked.

Position markers must be non-empty, ≤128 chars, **present in the base request**, unique, and
**non-overlapping** — a marker that is a substring of another marker, or contains one, is rejected
(`:513-531`).

Two anti-amplification controls:

- **Pre-flight worst case.** `validateWorstCaseRequestSize` multiplies each marker's occurrence count
  by the largest payload's byte delta and refuses if the projected request exceeds 2 MiB (`:618-652`).
- **Render-time byte projection.** `renderRequest` projects each substitution's size *in bytes* before
  allocating and throws if it would exceed the cap (`payloads.ts:153-175`). The comment at `:144-152`
  names the case this closes: a payload value can itself contain another position's marker, which a
  later substitution then expands — amplification the pre-flight estimate does not model. A render
  failure is recorded as an error row, not silently dropped (`variationEngine.ts:312-336`).

> **ReDoS rejection on response regexes is a safety net, not a proof.** Response markers and
> extractors are scanned by `hasNestedQuantifier`, a pure linear scan (no regex execution) that
> rejects an unbounded quantifier applied to a group that itself contains one — `(a+)+`, `(a*)*`,
> `((a)*)*`, `([a-z]+)+`, including through wrapping groups (`:694-714`, `:716-766`). The comment at
> `:698-705` is candid: patterns pathological in ways it does not model — the example given is
> overlapping alternations like `(a|a)+` — still get through, and response analysis runs on the
> engine's event loop, so a catastrophic pattern freezes the job and defeats pause/stop. **Keep
> response regexes simple.**

### 8.6 Scope enforcement at two points

1. **At creation** — `evaluateScope` on `{scheme, host, port, path}` derived from the base request;
   the refusal names the destination and the scope reason (`:144-154`).
2. **Per request** — after rendering, the rendered path is re-evaluated. Out-of-scope renders are
   **skipped, counted in `job.skipped`, written as a result row with `skipped: true`, and audited** as
   `request.skipped-out-of-scope` (`:338-362`).

> **Variation re-checks the path per request, never the host.** Scheme, host and port come from the
> plan (`:247`) and are handed to `sendRaw` unchanged (`:369-372`); they are *not* re-derived from the
> rendered request. A payload injected into the `Host` header changes the header the target sees but
> cannot redirect the TCP connection. The second gate exists specifically because a payload can change
> the **path** into an out-of-scope area (`:341`).

### 8.7 Result rows

Per request (`shared/variation.ts:59-76`, populated `:420-435`): index, the payload assignment, the
exchange id, status, response length, word count, line count, a **sha256 hash truncated to the first
16 hex characters** (`:428`), truncation flag, duration and TTFB, `inScope`, `skipped`, `error`,
`markerHits` (each match truncated to 120 chars, `:472`) and named `extracted` values (each truncated
to 240 chars, `:477`) — all computed over at most `MAX_ANALYSIS_BYTES` = 256 KiB of the response
(`:468`).

### 8.8 Control, audit, and emergency stop

`pause` / `resume` / `stop` per job (`:199-225`), plus `emergencyStopAll()` which aborts every job at
once and emits `emergency-stop` (`:227-238`). `VariationJob.stop()` (`:113-119`) sets status
`stopped`, releases the pause gate, and aborts the job's `AbortController`; that signal is passed into
`sendRaw` (`:378`) and destroys the in-flight request (`net/httpClient.ts:102-108`).

Audit actions written by the engine: `job.create` (`:178-185`), `job.pause` (`:205`), `job.resume`
(`:215`), `job.stop` (`:223`), `emergency-stop` (`:229-234`), `job.start` (`:250-257`),
`job.complete` / `job.stopped` (`:289-295`, ternary `:292`), `request.skipped-out-of-scope`
(`:354-360`).

**`TacnocSession.emergencyStop()`** — `session.ts:736-745` — does exactly three things plus a `warn`
log line (`:744`):

1. `variation.emergencyStopAll()` — audit row, then `job.stop()` on **every** job.
2. `interceptor.releaseAll('drop')` (`:742`) — every held request **and** held response is resolved as
   `drop`, not `forward` (`interceptor.ts:111-129`). Both the session comment (`:738-741`) and the
   interceptor's (`interceptor.ts:100-106`) record that forwarding made "the one control whose entire
   job is *stop touching the target*" deliver every queued request to it.
3. Emits `'emergency-stop'` (`:743`), wired in the constructor to `mesh.stopAll()` (`:203`), aborting
   every in-flight run's controller — including the provider HTTP call (`orchestrator.ts:400` →
   `ai/providers/anthropic.ts:231-232`).

It is invoked from the red header button (`App.tsx:215-216`), the IPC method `emergencyStop`
(`main/ipc.ts:244`), and `before-quit` (`src/main/index.ts:128-134`).

> **What emergency stop does NOT do:**
> - **It does not stop the proxy.** The listener stays bound; new exchanges keep being captured and
>   forwarded.
> - **It does not turn interception off.** `interceptRequests`/`interceptResponses` are untouched —
>   `releaseAll` only drains the queues; the *next* request is held again.
> - **It does not cancel an in-flight Repeater request.** `Repeater.send(target, options, jar?)`
>   (`repeater.ts:67-71`) takes no `AbortSignal` — grep of `signal|Abort` across
>   `src/engine/repeater/` returns nothing. A request already on the wire completes.
> - **It does not cancel an AI tool call already dispatched.** The abort check runs *before*
>   `spec.handler(input)` (`orchestrator.ts:497`, `:525`) — a `send_repeater` already inside the
>   Repeater finishes.
> - **It does not stop the passive scanner or extension checks**, close the project, revoke the CA, or
>   clear anything.
> - **Held intercept messages are discarded.** Correct for a stop control, but any half-completed
>   manual workflow is lost.
> - **Stopped jobs are not resumable.** `run()` refuses a job whose status is not `created`:
>   *"job `<id>` already `<status>`"* (`:244`).

> **UI mismatch on `Run`.** The button is disabled only while `progress?.status === 'running'`
> (`VariationView.tsx:134`), whereas the engine requires status `created`. After `completed`,
> `stopped` or `paused`, `Run` looks available and produces an error in the red box. To run the same
> plan again, press **`Prepare`** for a new job.

### 8.9 The dead automation settings

> **Settings → "Automation limits (defaults for new variation jobs)" (`SettingsView.tsx:138`) is
> inert.** `EngineConfig.limits.automation` is written and read **only** by `SettingsView` — grepping
> `maxRequestsPerJob|requestsPerSecond|maxConcurrency` across `src/` returns the type
> (`shared/config.ts:23-29`), the defaults (`config.ts:20-23`), engine code that reads `plan.limits.*`
> (`variationEngine.ts`), JSON-schema description text (`ai/tools.ts:162-170`), and the two renderer
> views — and nothing else. The Variation view builds its plan from its own hardcoded state:
> concurrency `4` (`VariationView.tsx:39`), rps `8` (`:40`), `maxRequestsPerJob: 500` (`:41`),
> `timeoutMs: 20000` hardcoded inline (`:64`) — note the per-job max differs from the config default
> of 5,000, the timeout is not editable in that view at all, and the file makes no `getConfig` call.
> The engine states the split itself: "the variation engine takes limits per-job from the plan"
> (`session.ts:541-543`). **Set your pacing in the Variation form for every job; do not assume
> Settings did it.**

#### Under the AI mesh

`create_variation_job` costs **0** against the run's active-request budget — creating a job sends
nothing (`ai/tools.ts:690`). `run_variation_job` is charged the job's **actual total request count**,
not 1 (`:700-703`), and the orchestrator refuses it if it would exceed the remaining budget
(`orchestrator.ts:526-531`, rationale `:509-514`). This is what stops a model fanning out past the
per-run cap with one tool call.

---

## 9. The user interface

Everything below was read out of `src/renderer/`, `src/main/`, `src/preload/` and the engine modules
they call. Where a control does less than its label suggests, that is stated.

### 9.1 Window anatomy

The window is **frameless on Windows and Linux** and uses `titleBarStyle: 'hiddenInset'` on macOS
(`src/main/index.ts:73-75`). The app's own top bar *is* the title bar, so it is the drag region
(`<div className="topbar drag">`, `App.tsx:178`) and every interactive child opts out with `no-drag`
(`:102`, comment `:174-176`). Minimise / Maximise / Close are drawn by the renderer only where the OS
chrome is gone — `window:usesCustomControls` returns `process.platform !== 'darwin'`
(`main/ipc.ts:191`, consumed `App.tsx:85-144`).

#### Top bar (`TopBar`, `App.tsx:146-224`)

| Control | Behaviour |
|---|---|
| Brand | `TACNOC` in a `<span>` with `authorized testing` in a `<small>` beside it (`:179-183`) — two elements, not one dashed string |
| Project name chip | Shown only when a project is open (`:184`) |
| **Proxy chip** (`Proxy off` / `Proxy <host>:<port>`) | The **only** control that starts/stops the proxy; `title="Toggle proxy"`. Failures (port in use, no project) surface as a toast (`:159-194`) |
| `non-loopback bind` chip | Appears only while the proxy is running and `loopbackOnly` is false (`:195-199`) |
| Intercept chip | `Intercept on` / `Intercept off`, with ` (n)` appended **only when n > 0**; `n` is held **requests + responses** (`:148`, `:200-210`) |
| Jobs chip | `Jobs n` — variation jobs whose status is `running` or `paused` (`:149`, `:211-214`) |
| **`■ EMERGENCY STOP`** | `title="Halt all automated work"`. See [8.8](#88-control-audit-and-emergency-stop) |
| `☾` / `☀` | Theme toggle, `title="Toggle theme"`. **Not persisted** — plain `useState` defaulting to `dark` (`store.tsx:84`, toggle `:181`); there is no `localStorage`/`sessionStorage` reference anywhere in `src/renderer/src` |

#### Sidebar (`NAV`, `App.tsx:35-75`)

Five groups, sixteen views, exact labels:

- **Traffic** — `Target Map`, `HTTP History`, `Intercept`
- **Workbench** — `Repeater`, `Variation`, `Sequencer`, `Encoder / Decoder`, `Compare`
- **AI** — `AI Mesh`
- **Analysis** — `Findings`, `Scope`, `Audit Log`
- **Project** — `Engagement`, `CA Certificate`, `Extensions`, `Settings`

`Findings` and `Intercept` carry a numeric badge (`:234-239`). The default view on open is `history`
(`store.tsx:83`).

> **There are no keyboard shortcuts.** A case-insensitive search of `src/renderer/src` for `keydown`,
> `onkeydown`, `accesskey`, `ctrl+`, `cmd+`, `metaKey` and `keyboard` returns no matches.

#### Renderer security posture

`contextIsolation: true`, `nodeIntegration: false`, `sandbox: true`, `webviewTag: false`
(`src/main/index.ts:76-83`); external links open in the OS browser and in-app navigation away from the
shell is blocked (`:87-97`); CSP is
`default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:;
font-src 'self'; connect-src 'self'` (`src/renderer/index.html:8-11`). The preload bridge gives the
renderer exactly two capabilities — `invoke(method, ...args)` and `onEvent(handler)` — no Node, no
engine objects (`src/preload/index.ts:10-23`, design statement `:3-4`). See
[14.8](#148-ipc-and-event-surface).

### 9.2 Traffic views

#### `HTTP History` (`HistoryView.tsx`)

Toolbar (`:118-167`): free-text `Search url/host/method…`, `Any method`
(GET/POST/PUT/DELETE/PATCH/HEAD/OPTIONS), `Any status` (2xx/3xx/4xx/5xx), `MIME` substring,
`Any source` (`proxy` / `repeater` / `variation` / `import`), an **`in-scope only`** checkbox, a live
`N exchanges` count, and **`Clear`** — which calls `clearHistory()` immediately, **with no
confirmation dialog** (`:164-166`; consequences in [4.9](#49-deletion-behaviour)).

Table columns: `Time · Src · Method · Host · Path · Status · Len · Scope` (`:174-183`). `Src` shows an
`auto` badge for engine-generated requests (`:193`); `Scope` shows a per-row badge (`:201-205`).

> **The table shows at most 500 rows while the counter shows the true total.** The query is hard-coded
> to `{ limit: 500, sort: 'desc' }` (`:41`) while `total` comes from the page result (`:48-51`).
> Narrow with the filters rather than scrolling for older traffic — an operator scrolling will
> otherwise conclude older traffic was never captured.

Refreshes are debounced against capture bursts — 0 ms if the last load was >1.5 s ago, else 250 ms
(`:65-73`). Each load decrypts 500 rows' header JSON and inline bodies (comment `:54-64`).

**Inspector.** Selecting a row loads the full exchange: a notes box (`Notes for this exchange…`), a
`tags (comma-separated)` box, **`Save notes/tags`**, and **`Send to Repeater →`** (`:220-246`).

Request and response each render in a `MessageViewer` with four tabs — **`RAW`, `HEADERS`, `BODY`**
(labelled `JSON` when the body parses as JSON, `MessageViewer.tsx:64`), **`HEX`** — plus a size
readout, a `(capped)` marker and the content encoding (`:17`, `:55-73`). A separately-tracked display
truncation is called out with *"Body truncated for display; full bytes are stored."* (`:89-93`).

> **The credential "mask" is a CSS blur.** When `sensitive.hasCookies || hasAuthorization ||
> hasTokens`, a warn box appears — *"⚠ Contains likely credentials (…)"* — and the RAW/HEADERS/BODY
> panes get class `reveal-mask`, which is `filter: blur(5px)` with `cursor: pointer`
> (`styles.css:609-613`). The full plaintext is in the DOM, selectable and copyable, and any click on
> the pane un-blurs it permanently (`MessageViewer.tsx:42-46`, `:76-101`, `:98`, `:106`, `:116`). It
> is a shoulder-surfing and screenshot guard, not access control. **The `HEX` tab is not masked at
> all** — `{tab === 'hex' && <pre className="message hex">{hex}</pre>}` (`:121`) carries no
> `reveal-mask`, so a hexdump of the same credential-bearing body renders in the clear with no warning
> and no click.

> **The warning is computed over headers plus only the first 8,192 characters of the body**
> (`detectSensitive`, `redactor.ts:294-326`; window at `session.ts:626-629`), on a body already capped
> at `VIEW_MAX_BYTES = 4 MiB` for display (`session.ts:117`, `:622-625`). A credential past that
> offset produces no warning and no blur.

If the exchange carries the `websocket` tag, the response pane is replaced by a **`WebSocket frames`**
table — `# · Dir (↑ c→s / ↓ s→c) · Kind · Len · Payload`, with a `N captured` count — that live-updates
on the `ws-message` event for the selected socket (`HistoryView.tsx:85-92`, `:281-331`). Payload cells
show the first 200 decoded characters (`:312-315`).

#### `Target Map` (`TargetView.tsx`)

Three panes: **`Origins`** (columns `Origin · Paths · Reqs`, where the `Paths` **cell** is rendered as
`in-scope/total` while the **header** reads just `Paths`, `:197`, `:211-213`), **`Endpoints`**
(`Method · Path · Parameters · Status · MIME · Seen · Scope · Last`, `:242-279`), and **`Latest
exchange for endpoint`** with its own **`Send to Repeater →`** (`:139-149`). Toolbar: a filter box
(`Filter host, path, or parameter…`) matching origin id, path, method or parameter name (`:85-90`,
`filterEndpoints` `:296-312`), an **`in-scope only`** checkbox (`:91-98`), a
`N origins · M endpoints · K exchanges` readout, and **`Refresh`** (`:83-105`). If the map was built
from a bounded slice, a warn box says *"This map is based on the newest N of M exchanges…"*
(`:113-119`). Loads are debounced like history, with a 150 ms floor (`:35-40`).

### 9.3 Intercept

`InterceptView.tsx`.

1. Tick **`Intercept requests`** and/or **`Intercept responses`**. The toolbar right-hand hint reads
   *"N held request(s), M held response(s)"* (`:111-140`).
2. Held messages appear in the left **`Held queue`** pane (`:143-180`) as rows badged `REQ` (method,
   host, target, plus an `in`/`out` scope badge, `:151-167`) or `RES` (status code, host, target —
   **no scope badge**, `:168-178`). Empty state: *"No held messages. Enable interception, then
   generate traffic through the proxy."*
3. Click a row. The right pane **`Editor (request)`** / **`Editor (response)`** (`:184`) loads the
   message as raw editable text.
4. Edit, then **`Forward`** (primary) or **`Drop`** (danger) (`:186-191`).

**How your edit is parsed.** On forward, the draft is split at the first blank line; the first line is
the request line (or status line, matched by `/HTTP\/\d(?:\.\d)?\s+(\d+)\s*(.*)/`); every subsequent
line with a `:` at index > 0 becomes a header; everything after the blank line is the body,
base64-encoded (`:13-37`, `:73-93`).

> **Malformed edits fail quietly.** Line endings are normalised (`\r\n` → `\n`) before parsing, so you
> can type either (`:19`, `:74`). A header line with no colon is **silently dropped**, not an error
> (`:27-30`, `:82-85`). A malformed request line falls back to method `GET`, target `/` (`:32-33`). An
> unparseable status line leaves the original status untouched — only headers and body are applied
> (`:89`).

> **Three ways to empty the queue, two of which discard traffic.** Un-ticking the intercept checkbox
> releases held messages as **forward** (`interceptor.ts:37-48`). **Emergency stop** releases them as
> **drop** (`session.ts:736-745`). **Stopping the proxy** also releases as **drop**
> (`proxyServer.ts:260-266`). Know which one you are pressing.

### 9.4 Findings

`FindingsView.tsx`. There is nothing to start — the empty state says so: *"No findings yet. Capture
some traffic — the passive scanner runs automatically."* (`:145-152`). New findings arrive as
`finding` events and bump the sidebar badge (`store.tsx:125-127`).

Toolbar (`:57-74`): `Passive findings`, an **`include suppressed`** checkbox, a
**`Suppression rules (n)`** toggle, and a hint reading `N scanner modules · M findings`.

Left table: `Sev · Title · Confidence · Module`; suppressed rows render at 50 % opacity (`:120-144`).
Right `Detail` pane shows Confidence, `Module vVersion`, Exchange id, Dedupe key, **Description**,
**Remediation**, and **`Evidence (redacted)`** as `[location] field: excerpt` blocks (`:157-189`).

Two suppression controls (`:190-197`): **`Suppress (false positive)`** / **`Un-suppress`** for one
finding, and **`Suppress this type (rule)`** which creates a persistent rule keyed on `module` +
`dedupeKey` (`:36-47`). Rules are listed under `Suppression rules` with `Module · Dedupe key · Host ·
Reason` and a `✕` to delete (`:76-116`); unset fields display as `any`.

> **Redaction policy is snapshotted at scan time.** `setConfig` rebuilds the scanner so changes apply
> *to new scans* (`session.ts:538-545`; the Settings card says the same, `SettingsView.tsx:229-232`).
> Findings already stored keep the redaction they were created with. Tightening redaction does not
> retroactively clean old evidence.

### 9.5 Engagement

`EngagementView.tsx`. Preflight is at the top on purpose — an expired CA, an empty scope and an
untrusting browser all look identical from the operator's chair: a session that seems to work and
finds nothing (`:1-9`).

**Preflight card** (`:204-239`). Heading reads `Preflight · ready to test` or `· not ready`, with
**`Re-check`** (`:214-216`). Each row is `BLOCKER` / `warning` / `ok` (`:30-34`), a title, a detail
line and a `→ remedy` line (`:222-235`). Checks are catalogued in [5.8](#58-preflight).

**Engagement card** (`:347-393`) — `Program`, `Platform` (placeholder `hackerone`), `Handle`,
`Authorization reference` (placeholder *"program URL, engagement ticket, or signed scope document"*).
All fields save on blur. A rejected profile is rolled back to what is actually stored and the reason
toasted — an optimistic value left on screen would show a refused change as saved (`:110-128`).

**Traffic identity card** (`:396-495`) — `Required User-Agent` (placeholder
`e.g. greynoc-research (h1: greynoc)`), an **`Enforce on every generated request`** checkbox, and an
`Identity header` / `Value` table with `Add header` / `Remove`. The footer states the boundary: *"When
enforcement is on, the Repeater and the Variation engine rewrite every request they generate to carry
these. Traffic captured through the proxy is never rewritten — your browser's User-Agent is not ours
to change."* (`:490-494`).

**Proposed scope card** (`:242-344`) — **`Re-read folder`** (`:245-247`) reports *"Read N document(s)
in \<folder\> — X in scope, Y excluded, Z unclear."* (`:250-259`); a table lists each candidate host
with its **Reading** (`in scope` / `unclear` + reason) and **Found in** — file, line number and the
matching text (`:271-314`, evidence cell `:304-310`). Only hosts the documents call in-scope are
pre-ticked (`:67-69`). **`Add N selected to scope`** (`:317-323`) builds rules in the engine via
`scopeRulesFromProposal`. The footer is the rule to work by: *"a document is a claim about
authorization, not authorization itself"* (`:325-330`).

**Engagement folder card** (`:498-587`) — path box, **`Choose…`**, a document-kind chip row
(`scope`/`engagement`/`report`/`recon`/`notes`/`other`, `:528-534`), and a classified file table
showing the first 12 documents with their classification reasons (`:541-556`). The egress warning is
repeated here (`:513-519`). When the project sits inside a hunt folder whose documents are one level
up, a warn box offers **`Use that folder`** (`:564-586`).

**Interception certificate card** (`:590-640`) — a status line (`subject · N day(s) left · SHA-256
<fp>`, or `REVOKED — <reason> · HTTPS is passing through unread`, plus the decrypted-HTTPS count,
`:592-602`), **`Issue new CA`**, **`Revoke CA`** (`:603-610`), and a history table `When · Action ·
Reason · Fingerprint` showing up to 10 entries (`:616-639`). Both actions prompt for a reason via
`window.prompt` and refuse to proceed if you cancel (`:166-196`); both are audited and both refresh
the CA on connections already open (`session.ts:481-518`).

> **Issuing a new CA invalidates the one your browser trusts.** The toast says so: *"New CA issued.
> Install it in your test browser — the old one no longer works."* (`:172`). You must re-run the
> `CA Certificate` guide. Revoking turns interception off entirely; HTTPS tunnels then pass through
> unread (`:189`).

### 9.6 Supporting views

- **`Sequencer`** (`SequencerView.tsx`, 200 lines) — paste one token per line; choose
  `plain text bytes` / `hex-decoded bytes` / `Base64-decoded bytes` / `Base64url-decoded bytes`
  (`:38-41`); **`Analyze`** (`:44-46`, disabled with zero samples). Reports samples/unique, decoded
  bytes, token length, byte alphabet, Shannon and min entropy, estimated and observed per-token
  entropy, one-bit ratio, monobit p-value, serial correlation, compression ratio (`:91-123`), graded
  observations (`:125-134`), per-position entropy capped at the first 256 decoded bytes (`:136-163`),
  and an assessment chip (`:67-74`). Its own warn box says it is *"a statistical screen, not proof
  that a token generator is unpredictable"* and asks for at least 100 samples, preferably thousands
  (`:59-63`).
- **`Encoder / Decoder`** (`EncoderView.tsx`, 116 lines) — a transform dropdown grouped by category
  (`encode`, `decode`, `hash`, `compress`, `inspect`, `other`, `:49`), Input/Output panes,
  **`Apply →`** (`:63-65`); plus a **JWT inspector** (`:84-112`) that *"Decodes header + payload for
  inspection only. The signature is never verified or altered."* (`:86-89`). It calls `listTransforms`
  with no filter, so built-in and extension transforms are merged (`:17`).
- **`Compare`** (`CompareView.tsx`, 99 lines) — Left/Right textareas (`:44-61`), mode `text (line)` /
  `JSON-aware` / `byte-level` (`:35-39`), **`Compare`** (`:40-42`). Byte mode reports equality, first
  differing offset, both lengths and the differing-byte count (`:89-94`).
- **`Audit Log`** (`AuditView.tsx`, 59 lines) — `Time · Actor · Action · Target · Detail` (`:30-34`), a
  **`Refresh`** button (`:22-24`), the hint *"every automated action is recorded here (secrets
  redacted)"* (`:20`); loads 1000 entries (`:12`). Full action catalogue in
  [Appendix B](#appendix-b-audit-action-catalogue).
- **`Extensions`** (`ExtensionsView.tsx`, 78 lines) — **`Load bundled example (header-hygiene)`**
  (`:41-43`), a `Loaded` list showing name, version, description and granted permission tags
  (`:47-63`), and an `Extension-provided transforms` card listing transforms whose id starts with
  `ext.` (`:16`, `:65-74`). Warning copy at `:36-40`. See [12](#12-the-extension-sdk).
- **`Scope`** (`ScopeView.tsx`) — the `Add rule` card and two tables; see [5.3](#53-the-scope-data-model-and-decision-procedure)
  for semantics. Fields left to right (`:155-231`): list (`include` default / `exclude`), match
  (**`exact` default**, `subdomain`, `wildcard`), host (placeholder
  `host e.g. example.test or *.example.test`), ports (comma list, blank = any), scheme (`any scheme`
  default), path prefix (stored as `{kind:'prefix', value}`), **`Add`** (empty host refused with the
  toast *"Enter a host pattern."*, `:59-71`). Saves are **optimistic with rollback** — a failed
  `setScope` restores the previous state and toasts, so a rejected rule can never look accepted
  (`:46-57`); the view re-syncs on the `scope-changed` event (`:41-43`). Both lists render as
  `Include rules` / `Exclude rules` tables with columns `On · Match · Host · Schemes · Ports · Path`
  plus a trailing unlabelled column holding the `✕` delete button (`:84-128`, `:233-240`).
- **`AI Mesh`** (`AiMeshView.tsx`, 452 lines) — off by default and the only outbound path. See
  [11](#11-the-ai-mesh).

### 9.7 Settings

`SettingsView.tsx`, 310 lines. Four cards, then the save controls, then a Project card. A
`Save settings` toast states the apply semantics exactly: *"Settings saved. Redaction & repeater
limits apply now; listener and capture settings apply on the next proxy start."* (`:70-72`).

| Card | Fields (exact labels) | Default | Applies |
|---|---|---|---|
| Proxy listener (`:100-135`) | `Bind host`, `Port` | `127.0.0.1`, `8080` | next proxy start |
| Automation limits (defaults for new variation jobs) (`:137-170`) | `Max concurrency`, `Requests / second`, `Request timeout (ms)`, `Max requests / job` | 4, 8, 20000, 5000 | **stored only — see [8.9](#89-the-dead-automation-settings)** |
| Capture & body limits (`:172-225`) | `Spill to disk after (MB)`, `Max captured / body (MB)`, `Max proxy connections`, `Upstream timeout (ms)`, plus checkboxes `Capture WebSocket frames` and `Intercept HTTP/2 (ALPN h2)` (`:207-224`) | 5, 100, 512, 30000; both boxes on | next proxy start |
| Secret redaction (`:227-259`) | `Mask cookies`, `Mask Authorization headers`, `Mask secret patterns (tokens/keys)` | all on | new scans |
| Project (`:272-284`) | **`Export project…`**, **`Close project`** | — | immediate |

Below the cards sit **`Save settings`** and **`Reload`** (`:263-270`); `Reload` re-reads the stored
config and discards unsaved edits.

> **"Clamped" means floored, not capped.** `save()` runs each value through
> `clamp = (n, min, fallback) => Number.isFinite(n) && n >= min ? n : fallback` (`:11-12`, applied
> `:36-66`). A value below the minimum, or non-numeric, is replaced by the default; a value *above*
> any sane ceiling is stored as typed. Blank bind host → `127.0.0.1`, port < 1 → `8080`, concurrency
> < 1 → 4, rate < 1 → 8, timeout < 1000 ms → 20000, max requests/job < 1 → 5000, spill < 64 KiB →
> 5 MB, `maxCapturedBytes` floored at the spill threshold with a 100 MB fallback, connections < 1 →
> 512, upstream timeout < 1000 ms → 30000. The real upper bounds on automation are enforced per job by
> the engine (`variationEngine.ts:593-616`), so typing 500 into concurrency is stored as 500 and the
> 1–64 refusal arrives at **Prepare**, not at Save.

Entering a non-loopback bind host raises an inline warn box — *"Non-loopback bind. Binding to X
exposes the intercepting proxy beyond this machine…"* — matched against the same loopback set the
engine uses (`:6-8`, `:128-134`; `config.ts:34`).

The capture card states the invariant that matters most: *"The proxy always forwards every byte to
the peer; these caps only limit what is captured."* (`:174-177`).

### 9.8 Exporting, and what redacted covers

This is where the tool's documentation and the tool disagree. Read this before you send anything to a
programme.

**`Export project…`** opens a save dialog titled *"Export project"*, defaulting to
`<project name>.gnbexport.json`, and writes pretty-printed JSON (`main/ipc.ts:94-104`). Contents and
omissions: [4.10](#410-import-and-export).

| Artifact | Redacted? | Where |
|---|---|---|
| Findings **evidence** | **Yes** — at scan time, twice | `checks.ts:132, 258, 291, 357, 414, 486`; `passiveScanner.ts:90-93` |
| Structured logs | Yes — the logger holds a `Redactor` | `logger.ts:42, 51, 88-89` |
| Audit `target` + `detail` | Yes — hardcoded all-on redactor | `auditRepo.ts:11-15`, `:22`, `:30` |
| Hunt memory on write | Yes — hardcoded all-on | `huntMemory.ts:127`, `:149` |
| Extension host traffic/checks/findings | Yes — hardcoded all-on | `src/sdk/host.ts:116`, `:328-330`, `:342-364`, `:398`, `:490-492` |
| AI mesh tool results, when `redactBeforeSend` is on | Best-effort | `session.ts:159-164`; `orchestrator.ts:734-740` |
| UI display of credential-bearing messages | Blurred until revealed (not the HEX tab) | `MessageViewer.tsx:42-46`, `:76-101` |
| **Project export — exchange headers and bodies** | **No** | `ProjectStore.export()` never constructs or calls a `Redactor` (`projectStore.ts:187-244`) |

> **Two in-tree statements overstate redaction coverage. Do not rely on either.**
> 1. `Settings → Secret redaction` describes itself as masking secrets *"in logs, findings evidence,
>    and exports"* (`SettingsView.tsx:229-232`), and the redactor module header says the same
>    (`redactor.ts:5-6`). The export path does not redact.
> 2. **The "sanitized report export" does not exist.** `docs/project-format.md:79` advises *"Use the
>    sanitized report export when sharing findings externally"* and `SECURITY.md:44` says "Prefer
>    sanitized report export". A search for `sanitized`, `report export`, `exportReport`,
>    `exportFindings` returns only the extension SDK's sanitized *traffic* events and those
>    documentation sentences — no code path, no `INVOKE_METHODS` entry, no button.
>    `docs/capability-matrix.md:22` records the gap and lists **Reporting** as planned item 5
>    (`:44-45`). Treat those sentences as forward references, not instructions.

**The procedure that is actually available.** To hand a finding to a programme today:

1. Open `Findings`, select the finding. Its **`Evidence (redacted)`** block, Description and
   Remediation are already secret-redacted and safe to transcribe (`FindingsView.tsx:179-189`).
2. Record `Module vVersion`, `Dedupe key` and `Exchange` id for reproducibility (`:167-178`).
3. For request/response proof, open the exchange in `HTTP History` and copy from the `MessageViewer` —
   **while it is still blurred, check what you are about to reveal.** The warn box names which
   sensitive fields were detected (`MessageViewer.tsx:76-87`).
4. Confirm redaction is on in `Settings → Secret redaction` (three independent toggles, all defaulting
   to `true`, `SettingsView.tsx:233-258`; `config.ts:44-48`). Remember these apply to new scans, not
   retroactively.
5. **Use `Export project…` for archival and for moving a project between machines, not for sharing
   with a programme.**

The redactor's coverage, for judging residual risk, is in [13](#13-safety-and-limits).

---

## 10. The MCP server

TACNOC's analysis engine is exposed to MCP (Model Context Protocol) clients as a set of callable
tools. The server is a plain Node process spawned over stdio — no Electron, no window, no project
file, no listening socket, no network egress of any kind.

The "no egress" claim is checkable rather than asserted: the complete module set the server loads
(ten files, below) imports only `node:fs`, `node:path`, `node:url`, `node:crypto` and `node:zlib`. No
`node:net`, `node:http`, `node:https`, `node:tls`, `fetch`, or third-party dependency appears
anywhere in that closure.

Everything it exposes is **read-only and offline**. No *tool* opens a project, reads a secret, writes
to disk, or emits a packet (`src/mcp/tools.ts:4-20`). The one disk read in the whole process is the
entry point resolving its own version from `package.json` at startup (`src/mcp/index.ts:28-43`). That
property is the entire safety argument for handing this to an agent, and the test suite is built to
break loudly if it stops being true.

Source: `src/mcp/` — three files, 637 lines (`index.ts` 66, `protocol.ts` 255, `tools.ts` 316).
Reference doc: [`mcp-server.md`](mcp-server.md) (130 lines).

> **Documentation gap.** `docs/mcp-server.md` is the only Markdown file in the tracked tree that
> mentions MCP. `README.md` does not list `npm run build:mcp` among its Common commands (`:98-113`),
> does not link `docs/mcp-server.md` from its Documentation section (`:204-215`), and contains no
> occurrence of "MCP", "plugin", "Claude" or "Anthropic" anywhere in its 219 lines. Onboarding from
> the README alone, you will not learn this server exists.

### 10.1 What it is

| | |
|---|---|
| Server name advertised | `tacnoc` (`src/mcp/index.ts:19`) |
| Version advertised | read from `package.json` at runtime — `0.6.1` (`index.ts:28-43`, `package.json:3`) |
| Transport | newline-delimited JSON-RPC 2.0 on stdin/stdout |
| Protocol revision default | `2025-06-18` (`protocol.ts:19`) |
| Capabilities declared | `{ tools: {} }` only — no resources, no prompts (`protocol.ts:124`) |
| Tools | 8, all read-only, all zero-traffic |
| Runtime requirement | Node ≥ 22.12 (`package.json:10-12`) |
| Extra dependencies | none — the loaded module closure pulls in no runtime dependency at all |

The version lookup walks up to six directories from the compiled module looking for a `package.json`
whose `name` is `greynoc-tacnoc`, falling back to `'0.0.0-dev'` if it never finds one
(`index.ts:30-42`). From `out/mcpsrv/mcp/` the repo root is three levels up, so a normal build reports
the real version.

> Move the build output somewhere with no `greynoc-tacnoc` `package.json` within six parent
> directories and the server reports `0.0.0-dev` instead of failing — a silent symptom, not an error.
> *(Read from the code; not exercised empirically.)*

Nothing outside `src/mcp/` references the server: `grep -rni mcp src/ --include=*.ts --include=*.tsx`
returns matches only inside `src/mcp/`. **The Electron app does not start, supervise, or know about
this server** — it is spawned exclusively by an external MCP client. *(Stated on the basis of that
negative grep and the absence of any spawn of `out/mcpsrv` in the tree.)*

### 10.2 The hand-rolled transport

`src/mcp/protocol.ts` implements the transport by hand rather than depending on
`@modelcontextprotocol/sdk`. The reasoning, verbatim in the file header (`:4-8`): TACNOC ships three
runtime dependencies and a published SBOM, and "for a security research tool the dependency surface
is part of the threat model"; the stdio transport is newline-delimited JSON-RPC and "the surface we
need is four methods, so the SDK would add more supply-chain surface than it saves."

(The header's "four methods" counts the request methods — `initialize`, `ping`, `tools/list`,
`tools/call`. The `switch` handles six method *names*, the two extra being the
`notifications/initialized` / `initialized` aliases, answered with silence.)

This is measurable. The compiled server emits **ten `.js` files** and imports nothing from
`node_modules`:

```
out/mcpsrv/mcp/index.js          out/mcpsrv/engine/analysis/sequencer.js
out/mcpsrv/mcp/protocol.js       out/mcpsrv/engine/compare/compare.js
out/mcpsrv/mcp/tools.js          out/mcpsrv/engine/scope/scope.js
out/mcpsrv/shared/model.js       out/mcpsrv/engine/transforms/codec.js
out/mcpsrv/shared/scope.js
out/mcpsrv/shared/sequencer.js
```

No storage module, no renderer code, no WASM SQLite, no `node-forge`, no `@anthropic-ai/sdk`. Import
census: `index.ts` takes `node:fs`, `node:path`, `node:url` plus its two local modules (`:13-17`);
`protocol.ts` has **no** import statements at all; `codec.ts` takes `node:crypto` and `node:zlib`
(`:13-14`); `sequencer.ts` takes `node:zlib` (`:6`) plus type-only imports; `scope.ts` and
`shared/scope.ts` are type-only; `compare.ts` and `shared/model.ts` import nothing.

#### Methods implemented

`protocol.ts:115-154`. Anything else returns `-32601`.

| Method | Behaviour |
|---|---|
| `initialize` | Returns `{protocolVersion, capabilities:{tools:{}}, serverInfo:{name,version}}`. **Echoes the client's requested `protocolVersion` back verbatim** when it is a non-empty string, otherwise substitutes `2025-06-18` (`:116-127`) |
| `notifications/initialized` / `initialized` | Acknowledged by staying silent — the handler returns `null` and nothing is written (`:130-132`) |
| `ping` | Empty `{}` result — unless sent as a notification (no `id`), in which case no response at all (`:134-135`) |
| `tools/list` | `{tools:[{name, description, inputSchema}]}` (`:137-144`) |
| `tools/call` | Dispatches by `params.name` with `params.arguments` (`:146-147`, `:157-185`) |

Any message without an `id` is a notification and is never answered, including an unknown method
(`:107`, `:151-153`).

> **`initialize` echoes whatever version the client asks for**, as long as it is a non-empty string. A
> client asking for a nonsense revision gets that nonsense back rather than a rejection. The rationale
> is that every revision so far is wire-compatible for the tool subset used here, so echoing avoids a
> spurious negotiation failure.

#### Five transport invariants

1. **stdout carries JSON-RPC frames and nothing else.** A stray write — a banner, a `console.log`, a
   dependency's deprecation notice — corrupts the stream and the client drops the connection
   (`:10-13`). All diagnostics go to stderr through `log()`, which prefixes `[tacnoc-mcp] ` (`:55-57`).
   The startup banner format string is
   `` `v${version} ready — ${tools.length} read-only tools: ${server.toolNames().join(', ')}` ``
   followed by `'offline analysis only: no project is opened and no traffic is generated.'`
   (`index.ts:50-51`), which for this tree renders as:
   ```
   [tacnoc-mcp] v0.6.1 ready — 8 read-only tools: inspect_jwt, analyze_tokens, list_transforms, apply_transform, diff_text, diff_json, diff_bytes, evaluate_scope
   [tacnoc-mcp] offline analysis only: no project is opened and no traffic is generated.
   ```
   *Provenance: the format string, version, and tool names and order are each read out of the tree;
   the rendered banner itself was not re-observed by spawning the built binary.*
2. **A tool that throws produces an error *result*, not a transport error** —
   `{content:[{type:"text",text:"error: …"}], isError:true}` so the calling model can read it and
   adapt (`:175-184`).
3. **Results are truncated at 100,000 characters** (`MAX_RESULT_CHARS`, `:35`) with a visible marker:
   `… [truncated: N more characters omitted. Narrow the input — e.g. fewer samples, a smaller slice —
   for a complete result.]` (`:74-79`). Non-string results are `JSON.stringify(value, null, 2)`'d
   first; an unserializable value degrades to `String(value)` rather than throwing (`:60-72`).
4. **Messages are processed strictly in arrival order** — each awaited before the next is dispatched,
   via a promise chain (`:206`, `:217`). MCP clients tolerate out-of-order responses; serial handling
   is chosen because reproducibility is what this project's evidence rules care about (`:198-201`).
5. **A malformed line does not kill the session.** Unparseable JSON returns `-32700` with `id: null`
   and the server keeps reading (`:230-237`). A throw inside the dispatcher returns `-32603` and logs
   (`:242-249`).

JSON-RPC codes used: `-32700` parse error, `-32600` invalid request (missing method, `:111-113`),
`-32601` method not found *and* unknown tool name (`:153`, `:162`), `-32603` internal dispatcher error
(`:247`). Constants `:24-27`. Duplicate tool names are rejected at construction, not at call time
(`:91`). `SIGINT`/`SIGTERM` exit cleanly with status 0 (`index.ts:55-57`); an unhandled rejection in
`main()` logs and exits 1 (`:63-66`).

### 10.3 Building it

See [2.4](#24-building-the-mcp-server) for the build command and the two CI gaps. Sanity-check the
build by hand — it speaks newline-delimited JSON-RPC on stdio and needs no client (the invocation is
in the source header, `index.ts:9-10`):

```bash
echo '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' | node out/mcpsrv/mcp/index.js
```

> **Treat the emitted file list as a build-time assertion.** If a build ever starts emitting storage
> or renderer files, an import crept in that breaks the offline guarantee in `src/mcp/tools.ts` — that
> is a build failure, not a surprise (`tsconfig.mcp.json:12-15`).

> **A fresh clone has no server.** `out/` is gitignored, and `.mcp.json` points at
> `out/mcpsrv/mcp/index.js`, which does not exist until you build — the client simply fails to spawn
> it, with no obvious hint that a build step was missed (`.mcp.json:11-13`).

### 10.4 Registering it with a client

#### As a plugin

This repo *is* the plugin. `.claude-plugin/plugin.json` declares it (name `tacnoc` `:2`, version
`0.6.1` `:4`, Apache-2.0 `:9`), and the root `.mcp.json` is described as discovered automatically at
the plugin root (`.mcp.json:3`):

```json
{
  "mcpServers": {
    "tacnoc": {
      "type": "stdio",
      "command": "node",
      "args": ["${CLAUDE_PLUGIN_ROOT}/out/mcpsrv/mcp/index.js"]
    }
  }
}
```

(`.mcp.json:15-21`; the file also carries a `$comment` array at `:2-14`.) `.claude-plugin/` contains
exactly one file — `plugin.json`. There are no `commands/` or `agents/` directories, so the plugin
ships the MCP server and nothing else.

`${CLAUDE_PLUGIN_ROOT}` resolves to wherever the plugin lands, so the entry needs no absolute path
(`.mcp.json:5-6`). Per `docs/mcp-server.md:56-57` you enable it by adding the repo path to
`enabledPlugins` in your Claude Code settings — **that instruction is documentation prose only**;
`enabledPlugins` appears nowhere else in this tree, so nothing here demonstrates or validates the
setting. Likewise, `${CLAUDE_PLUGIN_ROOT}` expansion and plugin-root auto-discovery are asserted by
`.mcp.json`'s own comments; no code in this repo performs either.

#### As a project server

`${CLAUDE_PLUGIN_ROOT}` does **not** expand outside plugin context (`.mcp.json:6-9`;
`docs/mcp-server.md:59-61`). A workspace registering the server directly must use an absolute path in
its own `.mcp.json`:

```json
{
  "mcpServers": {
    "tacnoc": {
      "type": "stdio",
      "command": "node",
      "args": ["C:\\path\\to\\GreyNOC Belcher\\out\\mcpsrv\\mcp\\index.js"]
    }
  }
}
```

(`docs/mcp-server.md:63-73`.)

#### Allowlist by name, never by wildcard

Tools appear to the client as `mcp__tacnoc__<tool>` (`docs/mcp-server.md:75`). Pre-allow them
**individually** rather than with an `mcp__tacnoc__*` wildcard, so that a tool added later has to be
allowed deliberately instead of silently inheriting the grant (`:75-77`).

> **A future TACNOC traffic tool would bypass a host guard that matches by tool name.** In a
> workspace whose `PreToolUse` guard matcher names specific traffic-generating tool patterns, no
> `mcp__tacnoc__` entry appears — correctly today, because none of the eight can emit a packet. Add a
> traffic tool and it would be outside that matcher by construction. Update the matcher **before**
> the tool ships, and keep the pre-allow list by-name.

### 10.5 Tool reference

All eight are confirmed against `src/mcp/tools.ts:172-315` and against a live registered server.
Registry order: `inspect_jwt, analyze_tokens, list_transforms, apply_transform, diff_text, diff_json,
diff_bytes, evaluate_scope`.

Summary table: [14.5](#145-the-8-mcp-tools). Every result is delivered as
`{"content":[{"type":"text","text":"<pretty-printed JSON>"}]}` (`protocol.ts:172-174`); the examples
below show the decoded `text`.

Three schema facts apply to **all** tools:

- Every top-level `inputSchema` is
  `{type:"object", properties:…, required?:…, additionalProperties:false}` via the `OBJECT` helper
  (`tools.ts:127-135`). The two hand-written nested schemas — `SCOPE_RULE_SCHEMA` (`:137-166`) and the
  `scope` object (`:288-297`) — also set `additionalProperties:false`. The one exception is the scope
  rule's `path` sub-schema, declared as bare `{type:"object", description:…}` with no `properties`
  (`:156-159`), so it is unconstrained by the schema.
- **The server does not validate against `inputSchema`.** `tools/call` passes `params.arguments`
  straight to the handler (`protocol.ts:165-171`). `required` and `additionalProperties:false` are
  hints the *client* may enforce; server-side, only the hand-written `str()`/`strArray()` checks
  (`tools.ts:39-61`) apply.
- Several handlers deliberately pass `required = false` — `apply_transform.input`, both sides of
  `diff_text`, `diff_json`, `diff_bytes` (`:236`, `:246`, `:260`, `:276-277`) — so a missing field
  becomes `''` rather than an error. A missing `diff_json` argument therefore fails later, inside
  `JSON.parse('')`, as an `isError` result rather than a clean "required" message.

#### `inspect_jwt`

Decode a JWT and report header, payload claims and signature presence. **Decode-only** — it never
verifies a signature, never re-signs, never strips or downgrades `alg` (`codec.ts:8-11`).

Input: `{token}` (`tools.ts:178-181`), `required`. Output — `JwtInspection` (`codec.ts:132-140`):
`header`, `payload`, `signatureB64Url` (`''` when absent), `wellFormed` (true only if
`parts.length === 3`), `note` (fixed string).

```json
→ {"name":"inspect_jwt","arguments":{"token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiZXhwIjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"}}
← { "header":  { "alg": "HS256", "typ": "JWT" },
    "payload": { "sub": "1234567890", "exp": 1516239022 },
    "signatureB64Url": "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
    "wellFormed": true,
    "note": "Decoded for inspection only. Signature is NOT verified and is never altered." }
```

A malformed token is a normal result, not an error: `token: "not-a-jwt"` returns
`header: {"_raw":"not-a-jwt","_error":"not valid base64url JSON"}`, `payload: null`,
`signatureB64Url: ""`, `wellFormed: false`, no `isError` (`codec.ts:144-150`; pinned at
`test/mcp/mcpServer.test.ts:298-301`).

> **Correction to the tool's own description.** It advertises "signature presence, and **expiry
> state**" (`tools.ts:177`). There is no expiry state — `JwtInspection` has no expiry field and
> `inspectJwt()` computes none; the `exp` claim is simply passed through inside `payload`. Compare
> `payload.exp` yourself; `apply_transform` with `time.epoch-to-iso` renders it (`1516239022` →
> `"2018-01-18T01:30:22.000Z"`).

#### `analyze_tokens`

Statistically screen captured tokens for predictability. Full semantics in [7.4](#74-sequencer).

Input (`tools.ts:189-202`): `{samples: string[], encoding?: "text"|"hex"|"base64"|"base64url"}`,
`samples` required. **An unrecognised `encoding` silently falls back to `text`** rather than erroring
(`:206-209`) — a typo like `base-64` will not error; it will analyse the raw characters and give a
different, wrong answer.

Output — `SequenceAnalysis`, 20 fields. Limits, each a thrown error surfaced as `isError`:

| Limit | Value | Message |
|---|---|---|
| `MAX_SAMPLES` | 100,000 | `Too many samples: the analyzer limit is 100,000.` (`sequencer.ts:35-37`) |
| `MAX_SAMPLE_BYTES` | 65,536 per sample | `Sample N exceeds the 65,536-byte limit.` (`:44-48`) |
| `MAX_TOTAL_BYTES` | 16 MiB | `Decoded samples exceed the 16 MiB analysis limit.` (`:50-54`) |
| `MAX_POSITIONAL_BYTES` | 256 | not an error — `positional[]` capped (`:213-214`) |
| empty `samples` | — | `Provide at least one non-empty token sample.` (`:34`) |
| a sample decoding to zero bytes | — | `Sample N decodes to an empty token.` (`:43`) |

Every encoding except `text` is validated and rejects malformed samples (`decodeSample`, `:152-184`):
`Sample N is not valid even-length hexadecimal.` (`:160-162`), `Sample N is not valid Base64.`
(`:167`; validator `:187-191`), `Sample N is not valid Base64url.` (`:174-177`).

```json
→ {"name":"analyze_tokens","arguments":{"samples":["deadbeef","cafebabe"],"encoding":"hex"}}
← { "assessment": "insufficient-data",
    "encoding": "hex", "sampleCount": 2, "uniqueCount": 2, "duplicateCount": 0,
    "totalBytes": 8, "minLength": 4, "maxLength": 4, "meanLength": 4,
    "alphabetSize": 7, "shannonBitsPerByte": 2.75, "minEntropyBitsPerByte": 2,
    "estimatedEntropyBitsPerToken": 4, "observedTokenMinEntropyBits": 1,
    "bitOneRatio": 0.71875, "monobitPValue": 0.00046525819691108365,
    "serialCorrelation": -0.2730289816632465, "compressionRatio": 1.375,
    "observations": [ … 4 warnings … ] }
```

That capture is the illustration of the trap in [7.4](#74-sequencer): an `insufficient-data` verdict
still ships four `warning` observations.

#### `list_transforms`

Input: `{}` (`tools.ts:218`) — takes nothing. Output: array of `{id, label, category}` projected from
`BUILTIN_TRANSFORMS` (`:219-221`). The 19 entries are in [14.4](#144-the-19-transforms).

#### `apply_transform`

Input: `{id, input}` (`:227-233`). Output: `{id, output}` (`:234-238`). `input` is fetched with
`required = false` server-side (`:236`), so omitting it transforms the empty string rather than
erroring. An unknown id throws `unknown transform: <id>` (`codec.ts:213-216`) as an `isError` result.

```json
→ {"name":"apply_transform","arguments":{"id":"base64.encode","input":"GNBB-CANARY"}}
← {"id":"base64.encode","output":"R05CQi1DQU5BUlk="}

→ {"name":"apply_transform","arguments":{"id":"base64-decode","input":"x"}}
← content: "error: unknown transform: base64-decode"   isError: true
```

> **Transform ids use dots, not hyphens** — `base64.decode`, not `base64-decode`. The repo keeps a
> test for exactly that mistake (`test/mcp/mcpServer.test.ts:329-333`).

#### `diff_text`

Input: `{a, b}` (`:245`). Output: array of `LineDiff` = `{type: "equal"|"add"|"remove", text}`
(`compare.ts:7-12`).

```json
→ {"name":"diff_text","arguments":{"a":"HTTP/1.1 200 OK\nrole: user",
                                   "b":"HTTP/1.1 200 OK\nrole: admin"}}
← [ {"type":"equal","text":"HTTP/1.1 200 OK"},
    {"type":"remove","text":"role: user"},
    {"type":"add","text":"role: admin"} ]
```

> **Two corrections to the tool's own description** (`:244`, "returning the changed lines with their
> kind"): (1) it returns **every** line, unchanged ones included (`compare.ts:47` pushes `type:'equal'`
> rows) — on a large response that is the whole body, not a summary, and it counts against the 100k
> truncation ceiling; (2) the field is named `type`, not `kind`. (`diff_json` uses `kind`. They are
> genuinely inconsistent with each other.) See also the 5,000-line silent fallback in
> [7.6](#76-compare).

#### `diff_json`

Input: `{a, b}` (`:253-259`) — both are **JSON text**, not objects. Output: array of `JsonDiffEntry`
= `{path, kind: "added"|"removed"|"changed", left?, right?}` (`compare.ts:63-70`). Equal documents
yield `[]` (`:82`). Invalid JSON throws from `JSON.parse` (`:74-75`) and surfaces as `isError`.

```json
→ {"name":"diff_json","arguments":{"a":"{\"role\":\"user\",\"id\":7}",
                                   "b":"{\"id\":7,\"role\":\"admin\"}"}}
← [ {"path":"$.role","kind":"changed","left":"user","right":"admin"} ]
```

Key order differs between the two documents and produces no noise — the point of using this over
`diff_text` on API responses. (Same pair asserted at `test/mcp/mcpServer.test.ts:344-352`.)

#### `diff_bytes`

Input: `{a_base64, b_base64}` (`:267-273`). Output — `ByteDiff`, exactly five fields
(`compare.ts:129-137`); see [7.6](#76-compare) for the semantics and the two doc/impl mismatches.

```json
→ {"a_base64":"QUJD","b_base64":"QUJE"}       // "ABC" vs "ABD"
← {"equal":false,"firstDiffOffset":2,"leftLength":3,"rightLength":3,"differingBytes":1}

→ {"a_base64":"QUJD","b_base64":"QUJDRA=="}   // "ABC" vs "ABCD"
← {"equal":false,"firstDiffOffset":3,"leftLength":3,"rightLength":4,"differingBytes":1}
```

> **No base64 validation, and no error.** The handler calls `Buffer.from(str(…), 'base64')` with no
> check (`tools.ts:274-278`). Node's decoder skips invalid characters, so garbage decodes to garbage
> silently: `a_base64: "!!!not base64!!!"` against `"QUJE"` returns
> `{"equal":false,"firstDiffOffset":0,"leftLength":6,"rightLength":3,"differingBytes":6}` with
> `isError` absent. Compare `analyze_tokens`, which *does* validate its hex/base64/base64url input and
> rejects bad samples. Feeding an unvalidated capture to `diff_bytes` yields a confident numeric answer
> about bytes that were never in the response.

#### `evaluate_scope`

Decide whether a URL falls inside an engagement's authorized scope, using TACNOC's own fail-closed
evaluator — the same `evaluateScope()` at `src/engine/scope/scope.ts:92` that the engine gates
automated traffic on. **Offline. Sends no traffic and does not resolve the host.**

Input (`tools.ts:285-300`): `{url, scope}`, both required. `scope` has `include` and `exclude`, each
an array of `SCOPE_RULE_SCHEMA` (`:137-166`):

| Rule field | Type | Default if omitted |
|---|---|---|
| `host` | string — `example.com` or `*.example.com` | **required**; missing throws `scope.<include\|exclude>[N].host is required` (`:77`) |
| `hostMatch` | `exact` \| `subdomain` \| `wildcard` | `wildcard` if `host` contains `*`, else **`exact`** (`:79-85`) |
| `schemes` | array of `http`/`https` | `[]` = any scheme (`:87-89`; unknown entries filtered out) |
| `ports` | array of number | `[]` = any port (`:90-92`; non-finite entries filtered out) |
| `path` | `{kind:"prefix"\|"regex", value}` | absent = any path; dropped entirely if `value` is not a string (`:104-110`) |
| `enabled` | boolean | `true` — only an explicit `false` disables (`:96`) |
| `label` | string | absent — `reason` then quotes the `id` (`scope.ts:100`, `:109`) |
| `id` | string | `include-N` / `exclude-N`, 1-based (`:95`) |

**Normalization deliberately under-claims.** An unspecified `hostMatch` becomes `exact`, never
`subdomain` — rationale at `:63-70`: scope decides what may be touched, so when the input is ambiguous
the answer should under-claim. Any `path.kind` that is not the literal string `"regex"` becomes
`"prefix"` (`:108`). A non-object rule throws `scope.<kind>[N] must be an object` (`:72-74`); a
non-object `scope` throws `"scope" must be an object with "include" and optional "exclude" arrays`
(`:115-117`).

Output: `{url, target, inScope, matchedInclude?, matchedExclude?, reason, normalizedScope}` — the
`ScopeDecision` (`shared/scope.ts:55-62`) spread between the echoed input and the normalized rules
(`:312`).

> **Six keys on a parseable URL, three on an unparseable one.** `matchedInclude` and `matchedExclude`
> are mutually exclusive, so you never see both. An unparseable URL, or any scheme other than
> `http`/`https`, returns `{inScope:false, reason:"unparseable URL, or a scheme other than
> http/https", url}` — **no `target`, no `normalizedScope`** (`:304-311`). Code that blindly reads
> `result.target` will crash on a `file://` or malformed URL.

```json
→ {"name":"evaluate_scope","arguments":{
    "url":"https://api.example.com/v1/users?id=7",
    "scope":{
      "include":[{"host":"*.example.com","label":"program wildcard"}],
      "exclude":[{"host":"api.example.com","path":{"kind":"prefix","value":"/admin"}}]}}}
← { "url": "https://api.example.com/v1/users?id=7",
    "target": {"scheme":"https","host":"api.example.com","port":443,"path":"/v1/users?id=7"},
    "inScope": true,
    "matchedInclude": "include-1",
    "reason": "Included by rule \"program wildcard\"",
    "normalizedScope": { … } }
```

The same scope with `url: "https://api.example.com/admin/x"` returns `inScope:false`,
`matchedExclude:"exclude-1"`, `reason: "Excluded by rule \"exclude-1\""` — the reason falls back to
the rule **id** because that exclude rule carries no `label`.

> **Name collision.** `src/engine/ai/tools.ts:598` defines a *different* tool also called
> `evaluate_scope`, for the in-app AI mesh. That one reads the live project scope via
> `session.getScope()` (`:604-608`) and takes only a `url` (`:601`); the MCP one takes the scope as an
> argument. Their failure strings differ too — the mesh tool returns `"unparseable or unsupported
> URL"` (`:606`) where the MCP tool returns `"unparseable URL, or a scheme other than http/https"`.
> In logs, `mcp__tacnoc__evaluate_scope` is this one.

> **A PASS here is not authorization.** The tool answers "does this URL match the ruleset you handed
> me", nothing more. It does not resolve DNS, consults no engagement file, and has no knowledge of
> what your programme actually authorized.

### 10.6 The registry test that fails on purpose

`test/mcp/mcpServer.test.ts` — 26 tests across 4 `describe` blocks: `MCP protocol` (`:101`, 9),
`tool registry contract` (`:208`, 2), `evaluate_scope` (`:228`, 6), `analysis tools` (`:287`, 9). It
runs under `npm test`, therefore under `npm run ci` and the CI `quality` job on all three OSes.

The load-bearing one is `exposes only offline, read-only tools` (`:209-218`):

```ts
const EXPECTED_TOOLS = [
  'inspect_jwt','analyze_tokens','list_transforms','apply_transform',
  'diff_text','diff_json','diff_bytes','evaluate_scope',
].sort();

expect(buildReadOnlyTools().map(t => t.name).sort()).toEqual(EXPECTED_TOOLS);
```

A hardcoded list (`:18-27`) compared for **exact equality**, so it breaks on an addition, a removal,
or a rename. Intentional — the file header says why (`:5-11`): the tool handlers do **not** carry the
per-run request budget, the audit record, or the abort check; those live in the AI orchestrator's
`wrapActive`. `EXPECTED_TOOLS.length` is also asserted as the length of `result.tools` (`:201`), so the
count is pinned twice.

The suite also pins the safety properties this manual claims:

| Test | Pins |
|---|---|
| `defaults an unstarred host to an EXACT match, not a subdomain match` (`:245`) | the narrow normalization default |
| `fails closed when no include rule is defined` (`:229`) | empty scope admits nothing |
| `refuses a non-http scheme rather than guessing` (`:269`) | `file://` cannot be scoped in |
| `rejects a scope whose rule has no host` (`:277`) | a hostless rule is an error, not a wildcard |
| `decodes a JWT without asserting the signature is valid` (`:288`) | output must not match `/signature (is )?valid\|verified: ?true/` (`:295`) |
| `does not rate high-entropy tokens as poor` (`:313`) | the analyzer is not a rubber stamp |
| `rates predictable tokens as poor` (`:303`) | 160 sequential `SESSIONID-acct-NNNNNN` samples → `poor` |
| `reports a failing tool as an error RESULT, not a transport error` (`:144`) | the model can read failures |
| `truncates an oversized result instead of flooding the caller` (`:173`) | the 100k ceiling |
| `enforces the input size cap` (`:363`) | the 2,000,000-character input cap |
| `gives every tool a description and an object input schema` (`:220`) | description > 30 chars, `inputSchema.type === 'object'` |

### 10.7 Adding a tool

A read-only, offline tool is a normal change: add it to `buildReadOnlyTools()` (`tools.ts:172`) and
update `EXPECTED_TOOLS` (`test/mcp/mcpServer.test.ts:18`).

A **traffic-generating** tool (Repeater, Variation) is not, and the registry test will fail on purpose
to stop it going in unnoticed. Per `docs/mcp-server.md:110-130`, before exposing one:

1. **Re-implement the active-request guard.** The handlers in `src/engine/ai/tools.ts` carry scope
   gating (`:99`, `:607`), but the per-run request budget (`config.maxActiveRequestsPerRun`), the
   `mesh.request` audit record, and the abort check live in `orchestrator.ts` → `wrapActive()`
   (`:515`; budget `:527-531`; audit `:537-543`; abort `:520`, `:525`). Exposing handlers directly
   inherits the scope gate and silently drops all three.
2. **Give it a session.** Active tools need a real `TacnocSession` with a project, which reintroduces
   the secret-store and single-writer constraints the current server avoids entirely
   (`src/mcp/tools.ts:10-14`).
3. **Extend the client's own guardrails** — see the warning in
   [10.4](#104-registering-it-with-a-client).

The reason step 1 matters is worth restating: the current server is safe *because nothing it exposes
can reach a target*, not because it is guarded. Remove that property and there is currently no guard
underneath it.

---

## 11. The AI mesh

TACNOC is local-first with exactly one deliberate exception. The AI mesh is that exception: **the
only code path in the product that sends data to a third party**, and it is off until you turn it on.

> `SECURITY.md:12-13` — "**No telemetry.** There is no analytics, no usage reporting, no update check,
> and no network sink for logging. The tool never phones home."
>
> `SECURITY.md:14-23` — "**One outbound path exists, and only when you switch it on — the AI mesh.** …
> **captured request and response content — including any secrets, cookies, and PII it contains — and
> the documents in the engagement folder are sent to the configured model provider.**"

Read "outbound path" precisely. TACNOC's proxy, Repeater and Variation engine obviously do open
sockets — that is the product — using Node's built-ins (`proxyServer.ts:20-21`, `repeater.ts:11-12`,
`net/httpClient.ts:7-8`), to destinations the operator puts in scope. **The mesh is the only path
that sends anything to a party that is not the target.** There are no hard-coded third-party endpoints
anywhere in `src/engine` or `src/main` (grep for `https://` returns none outside comments), and of the
three runtime dependencies only `@anthropic-ai/sdk` makes network calls.

The mesh is a five-role loop over the same engine primitives you drive by hand. It has no networking
of its own: everything it does to a target goes through the Repeater or the Variation engine, behind
the same scope gate.

```
recon → planner → [ attacker → analyst ]×N → reporter
```
(`orchestrator.ts:4-5`)

Recon runs first and is not optional. If recon's text matches `/^\s*BLOCKED\s*:/i` the run stops
before planning and the recon text becomes the report (`:286-296`, `isBlocked()` `:682-684`).

### 11.1 Default state

`defaultAiConfig()` — `src/shared/ai.ts:198-221`:

| Setting | Default | Effect |
|---|---|---|
| `enabled` | `false` | `start()` throws `'AI mesh is disabled. Enable it in AI settings first.'` (`orchestrator.ts:140`) |
| `egressAcknowledged` | `false` | `start()` throws the egress error (`:141-147`) |
| `redactBeforeSend` | `false` | **No redaction runs by default, even once the mesh is enabled** |
| `autonomy` | `'auto'` | Attacker gets active tools once the mesh is on |
| `roles` | all `claude-opus-5`; effort `high`, `xhigh`, `xhigh`, `high`, `high` for recon/planner/attacker/analyst/reporter (`ai.ts:210-214`) | |
| `runTokenBudget` | `0` (no soft budget) | |
| `maxActiveRequestsPerRun` | `50` | Hard per-run cap on target-touching requests |
| `workspaceAccess` | `true` | Engagement-folder tools are built — but only reachable once the mesh runs at all |
| `allowCertOps` | `false` | `issue_ca` / `revoke_ca` are not built into the registry |

**What staying off preserves.** With `enabled: false` (or `egressAcknowledged: false`) no mesh run can
start, so no captured content, no engagement document, and no project metadata reaches the provider.

> **One caveat: the Test connection button is not gated by `enabled` or `egressAcknowledged`.**
> `checkAiProvider()` (`session.ts:1416-1448`) reads the stored key and calls `messages.countTokens`
> with the literal message `'ping'` (`anthropic.ts:146-156`). That is a real outbound HTTPS call to
> the provider, made with the mesh switched off. It carries the API key, the model id and the word
> `ping` — no captured data, no project data — and it generates nothing.

### 11.2 Exactly what data leaves the machine

Per role turn, the provider request body is assembled at `anthropic.ts:200-229`. It contains:

1. **The role system prompt**, verbatim, with `cache_control: {type: 'ephemeral'}` (`:206-213`). Text
   is `systemPromptFor(role)` (`prompts.ts:121-123`) = shared `PREAMBLE` (`:26-43`) + role body
   (`ROLE_BODIES`, `:45-119`). No operator or target data.
2. **The role's user message** (`:214`), built by `reconPrompt` / `plannerPrompt` / `attackerPrompt` /
   `analystPrompt` / `reporterPrompt` (`orchestrator.ts:673-732`). These embed your free-text
   `objective`, any `plan.hosts` (via `hostLine()`, `:669-671`), and — for later roles — the **full
   previous role's output text**, the accumulated round-by-round analysis, and the list of declined
   roles.
3. **The tool registry for that role**: every tool's `name`, `description` and `inputSchema`
   (`:184-186`, `:215`, `toBetaTool` `:358-366`). The descriptions are long prose and are sent every
   turn.
4. **Every tool result**, `JSON.stringify`'d (`:377`).

Item 4 is where your data actually goes:

| Tool | What its result carries off the machine |
|---|---|
| `get_exchange_detail`, `send_repeater` | A full `ExchangeDetail` (`shared/detail.ts:36-52`): URL, method, **all request and response headers verbatim**, and **the body as base64** (`bodyBase64`, `session.ts:630-638`), truncated only at `VIEW_MAX_BYTES = 4 MiB` (`:117`, applied `:622-625`). `send_repeater` deliberately returns the exchange detail rather than the raw `RepeaterResult` (`tools.ts:672-680`) |
| `read_workspace_file` | The text of any engagement-folder document, up to `MAX_READ_BYTES = 2 MiB` (`workspace.ts:36`) |
| `list_workspace`, `search_workspace` | File paths, sizes, and matching lines from the engagement folder |
| `get_preflight` | Project **name and absolute directory path**, `authorizationRef`, CA status, every in-scope hostname, proxy bind host/port, workspace root path and notable filenames, exchange/finding counts (`preflight.ts:283-299`; shape `shared/engagement.ts:314-337`) |
| `get_engagement_profile` | Program, platform, **researcher handle**, authorization reference, required User-Agent policy and identity headers, workspace directory, operator notes (`shared/engagement.ts:48-73`) |
| `query_history`, `get_target_map` | Exchange summaries; the discovered site/endpoint map with in/out-of-scope flags (`tools.ts:565-566`, `:574-575`) |
| `list_ws_messages` | Captured WebSocket frames (`:556`) |
| `recall_prior_hunts` | Prior-hunt claims, notes and path shapes for the current programme |
| `get_variation_results` | Per-request status, lengths, timings, extracted values (`:708`) |
| `list_findings` | Passive-scan and extension findings (`:591`) |

**What never leaves**, verified: the API key (read main-side at `session.ts:1427` and `:1487`, never
crosses IPC — `AiKeyStatus`, `shared/ai.ts:112-116`, carries only `configured`/`secure`/`backendName`);
the CA private key and the project DEK (denied by name at every workspace depth,
[4.12](#412-the-workspace-reader)); hunt memory as a store (local-only under
`app.getPath('userData')/hunt-memory`, `src/main/index.ts:51-54`) — though individual recalled
*records* do egress via `recall_prior_hunts`.

> **Not redacted, even with redaction on: the prompts themselves.** `redactTool` wraps tool *handlers*
> only (`orchestrator.ts:735-740`). The `messages` array — your objective, and the previous role's
> model-written text — is mapped verbatim (`anthropic.ts:214`). A secret the recon role quoted into
> its own summary is re-sent verbatim to the planner, the attacker and the reporter. The engine
> briefing likewise prints every preflight check as `- [severity] title — detail`, carrying the
> **authorization reference** (`preflight.ts:83`) and the **CA subject + fingerprint** (`:146`), plus
> engagement-folder file names, enabled in-scope and excluded hosts, and ranked endpoint paths with
> exchange ids (`session.ts:839-925`).

### 11.3 The egress acknowledgement

**Enforcement** is a single check at the top of `MeshOrchestrator.start()`:

```ts
// orchestrator.ts:141-147
if (!config.egressAcknowledged) {
  throw new Error(
    'AI egress is not acknowledged for this project. Running the mesh sends captured ' +
      'traffic (including any secrets, cookies, and PII) to the model provider. Acknowledge ' +
      'egress in AI settings to proceed.',
  );
}
```

It is **per project**: the config lives in `project_meta` key `project.ai` (`session.ts:1362`,
`:1367-1368`), so acknowledging on one engagement does not acknowledge another.
`normalizeAiConfig()` re-validates every value on load because "a project file is data, not trusted
configuration" (`shared/ai.ts:223-232`).

**Audit** is written on the toggle, not on the run (`session.ts:1369-1376`): `ai.egress-enabled` /
`ai.egress-disabled`, actor `user`, with the comment "Egress toggles are security-relevant — always
audited."

> So the audit log tells you *when the operator consented*, not *what was sent*. **There is no
> per-payload egress record anywhere in the tree.**

**UI.** `AI → AI Mesh` (`App.tsx:55-56`). The acknowledgement is a checkbox labelled *"Acknowledge
egress (send captured traffic to provider)"* (`AiMeshView.tsx:252`), whose label turns warning red once
ticked (`:245`). A standing banner above it states the same thing (`:180-185`). Two further switches,
each its own choice:

- *"Read the engagement folder during recon (its contents are sent to the provider)"* →
  `workspaceAccess` (`:281`). Off means `workspaceTools()` returns `[]` (`tools.ts:184-185`).
- *"Allow the mesh to issue and revoke the interception CA (breaks installed trust)"* →
  `allowCertOps` (`:292`, red when on at `:285`). Off means `certificateTools()` returns only
  `get_ca_status` (`tools.ts:261`).

A third checkbox, *"Redact secrets (cookies, auth, tokens) before sending — best-effort"* (`:260`), is
`redactBeforeSend`.

### 11.4 Redaction before send

Off by default. When on, every tool in the registry is wrapped so its result passes through
`redactAiValue` before the SDK serializes it:

```ts
// orchestrator.ts:255-256
const redact = ctx.config.redactBeforeSend ? this.deps.redactResult : undefined;
const finalTools = redact ? active.map((spec) => redactTool(spec, redact)) : active;
```

The redactor for this path is hard-wired with all three masks on, independent of the project's own
redaction config (`session.ts:159-164`).

`redactAiValue` (`redactor.ts:199-227`) walks the result structurally and does four things:

- `headers` arrays → `Redactor.redactHeaders` (`:126-128`). **Thorough.** `Cookie`/`Set-Cookie` values
  masked with names preserved; `Authorization`/`Proxy-Authorization` wholly masked; and `x-api-key`,
  `x-auth-token`, `x-amz-security-token`, `x-csrf-token`, `x-xsrf-token` wholly masked
  (`CREDENTIAL_HEADERS` `:23-33`, applied `:100-124`). Note the gating: those extra credential headers
  are masked under `maskAuthorization`, **not** `maskSecretPatterns` (`:111-122`) — deliberate, and it
  matters only if someone reuses `Redactor` elsewhere with a different config.
- `bodyBase64` → decoded, **decompressed first** when `contentEncoding` is gzip/x-gzip/br/deflate (so
  patterns match the plaintext rather than reversible base64), pattern-masked byte-safely in latin1,
  re-encoded, and `contentEncoding` cleared once decompressed (`redactBase64Body`, `:265-288`;
  `tryDecompress` `:245-263`). Decompression is capped at `MAX_DECOMPRESSED = 8 MiB` against bombs
  (`:242`).
- `url` and `target` strings → `redactUrl` (`:131-148`), which masks sensitive query-parameter values
  (`SENSITIVE_PARAM_NAMES`, `:44-45`) *and* pattern-masks the path, so a JWT in a REST segment is
  caught (`:134-137`).
- everything else → recursive `redactText` over the 12 `SECRET_PATTERNS` (`:56-80`).

> **State the limit plainly.** Body masking is pattern-based and best-effort. The type's own comment
> says so: *"an opaque, non-pattern token sitting in a body may still pass"* (`shared/ai.ts:79-80`). A
> session identifier with no recognisable prefix, in a JSON body, is **not** caught. Header masking is
> the part you can rely on. And redaction never touches the prompt text carrying previous roles'
> output.

### 11.5 Provider configuration

Only one backend exists. `src/engine/ai/provider.ts` is the seam (`LlmProvider`), and
`AnthropicProvider` (`anthropic.ts:118`) is the only implementation — `src/engine/ai/providers/`
contains exactly one file, and `grep -rn "implements LlmProvider" src/` returns exactly that line.

> **`AiProviderId` admits `'openai'`** (`shared/ai.ts:18`) and `normalizeAiConfig` will store it
> (`:247`), but there is no OpenAI provider file — `session.ts:1436` and `:1492` construct
> `AnthropicProvider` unconditionally, so a role configured as `'openai'` **silently runs against
> Anthropic** with whatever model id you typed.

**Key storage.** App-wide, not per project: `ElectronSecretStore` writing `secrets.enc.json`
(`electronSecretStore.ts:19`) under `<userData>/ai-secrets` (`src/main/index.ts:50`), key name
`anthropic.apiKey` (`session.ts:158`). Backed by Electron `safeStorage` — DPAPI on Windows, Keychain
on macOS, libsecret on Linux (`electronSecretStore.ts:1-8`). If OS encryption is unavailable, values
are stored *obfuscated only*, `isSecure()` returns false (`:22-28`), `backendName()` reports
`safeStorage (unencrypted fallback)` (`:30-34`), and the UI shows `UNENCRYPTED fallback`
(`AiMeshView.tsx:193`). TACNOC never reads the key from the environment: the only `process.env` use in
`src/engine` and `src/main` is `ELECTRON_RENDERER_URL`, and `apiKey` is always passed explicitly to
the SDK (`anthropic.ts:124-127`).

**Base URL override.** `config.baseUrl` is honoured **only when it is a well-formed `https:` origin** —
anything else is dropped and the SDK default used (`normalizeBaseUrl`, `shared/ai.ts:290-298`). The
reason is stated at `:281-289`: this value decides which host receives the operator's API key, and a
hand-edited project file carrying `http://…` would hand the key to that host in cleartext.

**Per-turn request shape** (`anthropic.ts:200-229`):

| Field | Value | Source |
|---|---|---|
| `max_tokens` | `32_000`, or `64_000` when role effort is `xhigh`/`max` | `orchestrator.ts:68-69`, `:389`, `:397` |
| `max_iterations` | `24` (the provider's own fallback of 32 is never reached from the mesh) | `orchestrator.ts:71`, `:398`; `anthropic.ts:205` |
| `stream` | always `true` | `anthropic.ts:226` |
| `thinking: {type:'adaptive'}` | only when the model id prefix-matches `ADAPTIVE_THINKING` | `:53-62`, `:187`, `:227` |
| `output_config.effort` | only when the id prefix-matches `EFFORT` | `:78-87`, `:190`, `:228` |
| `output_config.task_budget` | only when the id prefix-matches `TASK_BUDGET` **and** `runTokenBudget / 5 >= MIN_TASK_BUDGET (20_000)` | `:65-71`, `:188`; `orchestrator.ts:70`, `:390`, `:399` |
| `anthropic-beta` header | `task-budgets-2026-03-13`, only with a task budget | `:89`, `:233` |

> **Model-capability lists are matched by id prefix and fail silently** (`startsWithAny`, `:91-92`).
> The file warns that the failure of omission is silent: a family name not in `ADAPTIVE_THINKING` runs
> with thinking disabled while the operator believes they set the largest quality lever the app has
> (`:34-52`).

**Verify before you spend.** `provider.verify(model)` uses `messages.countTokens`, which
authenticates and resolves the model but generates nothing (`:146-156`). `describeApiError`
(`:303-356`) maps 401 / 403 / 404 / 429 / 400 / connection / 5xx each to one named remedy.

### 11.6 The tool registry

`buildTools(session, grants)` — `ai/tools.ts:493-715`. Thirty tools maximum; **24** with both grants
off (the four workspace tools and the two CA-mutating tools drop out of the array entirely rather than
being filtered later).

`ToolEffect` has four values, and the file documents why the axis was split (`:37-55`): `mutates` used
to mean both "charges the budget" and "unsafe for a read-only role", and conflating them "handed CA
destruction to every role including the reporter" (`:44`).

The full table is [14.6](#146-the-30-ai-mesh-tools). Four registry details worth knowing:

- **`send_repeater` is scope-gated at the tool boundary, not in the engine** — "the Repeater does not
  enforce scope, so the mesh must" (`:640-642`). `meshRepeaterScopeDecision` (`:92-106`) canonicalizes
  scheme and port, then evaluates scope against the **origin-form path the Repeater will actually
  send**, parsed with the Repeater's own parser (`requestPath`, `:83-89`). The handler forwards **the
  canonicalized destination the gate approved, not the raw model input** — because tool input is not
  schema-validated at runtime and `'HTTPS'` would be checked as TLS but sent cleartext (`:650-664`).
  `followRedirects: false, maxRedirects: 0` is hard-coded (`:666-667`).
- **`apply_transform` is restricted to built-ins.** Extension transforms are excluded because an
  extension runs operator-loaded code that may hold network capability, "which would be a traffic path
  outside the scope gate, the request budget, and the audit log" (`:471-474`).
- **`recall_prior_hunts` has no `program` field on purpose.** "This model reads untrusted target
  content, and a program label lifted from a captured response would otherwise re-point the query at
  another client's records" (`:339-342`). Scoping is engine-side and fails closed.
- **`propose_scope_from_workspace` proposes and never writes.** "Read-only — it CANNOT change scope,
  and a document is not authorization" (`:222`); the engine states the same rule twice more
  (`session.ts:1108`; `scopeProposal.ts:13-16`).

### 11.7 Budget, audit, abort

Three controls live in one place — `MeshOrchestrator.wrapActive()` at `orchestrator.ts:515-549`:

```ts
if (!spec.mutates) return this.wrapAbort(runId, spec);
return {
  ...spec,
  handler: async (input) => {
    const state = this.runs.get(runId);
    if (!state || state.controller.signal.aborted) return { error: 'run stopped' };
    const cost = Math.max(0, Math.trunc(await (spec.requestCost?.(input) ?? 1)));
    if (cost > 0 && state.progress.activeRequests + cost > config.maxActiveRequestsPerRun) {
      return { error: `active-request budget (…) for this run would be exceeded: …` };
    }
    if (cost > 0) {
      state.progress.activeRequests += cost;
      this.emitProgress(state);
      const target = targetOf(input);
      this.deps.audit({ ts: Date.now(), actor: `ai-mesh:${state.progress.role ?? 'attacker'}`,
                        action: 'mesh.request', ...(target ? { target } : {}),
                        detail: { tool: spec.name, requests: cost } });
    }
    return spec.handler(input);
  },
};
```

1. **The per-run active-request budget** (`:527`) is charged by the number of HTTP requests an action
   actually launches, not one-per-tool-call. A fuzz job is charged its full size before it runs
   (`requestCost` for `run_variation_job` reads `listVariationJobs().find(...)?.total`,
   `tools.ts:701-702`), so the model cannot fan out past the cap. Refusal comes back as a tool
   *result*, not an exception, so the model can narrow and retry.
2. **The audit write** is `mesh.request`, actor `ai-mesh:<role>`, with the target URL and the request
   count — and it happens **only when `cost > 0`** (`:532-544`). The *attempt* is separately visible in
   the activity stream via `onToolCall` (`:401-410`), including attempts the cap later refuses.
3. **The abort check** is in every branch. Non-mutating tools get `wrapAbort` (`:492-501`) rather than
   nothing, because "Emergency stop has to also stop a CA revocation or a memory write that was
   dispatched a moment before the operator hit it" (`:517-519`).

> **The documented trap: these live in the wrapper, not the handlers.**
>
> `src/mcp/tools.ts:16-20` — "If a traffic-generating tool (Repeater, Variation) is ever added, it
> inherits NONE of the above and must additionally re-implement the per-run request budget, the audit
> record, and the abort check that live in `engine/ai/orchestrator.ts` (`wrapActive`) — **the tool
> handlers themselves do not carry them.**"
>
> `docs/mcp-server.md:118-122` — "**Exposing handlers directly inherits the scope gate and silently
> drops all three.**"
>
> The split is deliberate — scope is the hard boundary and belongs with the handler; budget/audit/abort
> are properties of *a run* and there is no run outside the orchestrator. But **`buildTools()` on its
> own is not a safe surface.** Pulling a spec out of that array and calling it directly — e.g.
> `buildTools(session, grants).find(t => t.name === 'send_repeater').handler(...)` — gets you a
> scope-checked request with no budget, no audit row, and no stop button. Address specs by name, never
> by index: `send_repeater` sits at index 26 zero-based with both grants on and shifts by up to six
> when grants are off.

A second consequence of the same split: `wrapActive` branches on `spec.mutates`, and `issue_ca`,
`revoke_ca`, `note_exchange` and `record_hunt_outcome` all declare `mutates: false` (`tools.ts:270`,
`:279`, `:531`, `:375`). They get abort handling but **no `mesh.request` audit row**. The CA operations
are still audited by their own engine methods as `ca.rotated` / `ca.revoked` with actor `'ai-mesh'`
passed by the tool handler (`session.ts:486-491`, `:508-513`; `tools.ts:271`, `:280`).
**`note_exchange` and `record_hunt_outcome` produce no audit entry at all** (`session.ts:641-643`,
`:1048-1052`). `create_variation_job` has `mutates: true` but `requestCost: () => 0`, so it also
produces no `mesh.request` row — the Variation engine logs it independently as `job.create` /
`job.start`, actor `'variation-engine'` (`variationEngine.ts:180-181`, `:252-253`).

### 11.8 Run bounds and role permissions

| Bound | Value | Where |
|---|---|---|
| Roles per run | 5 (recon, planner, attacker×N, analyst×N, reporter) | `execute()`, `orchestrator.ts:252-372` |
| `MAX_ROUNDS` on attacker→analyst | 3, or earlier if the analyst emits `DONE` on its own line (`/^\s*DONE\s*$/im`) | `:53`, `:319`, `:342` |
| `MAX_ITERATIONS_PER_ROLE` | 24 tool-call iterations per role turn | `:71`, `:398` |
| Active-request budget | `maxActiveRequestsPerRun`, default 50 | `:527`; `ai.ts:217` |
| Token budget | `runTokenBudget`, `0` = none; loop breaks when input+output ≥ it | `:322`, `:657-660` |
| Concurrent runs | **exactly one** — a second `start()` throws | `:157-165` |
| Empty scope | fail-closed; counts only **enabled** include rules | `:170-176`; re-checked ahead of the key in `session.ts:1483-1485` |
| Retained run history | `MAX_RETAINED_RUNS = 20` terminal runs; `MAX_STEPS = 1000` per run | `:52`, `:72`, `:552-558`, `:581` |

The one-run rule exists because the cap is per run: *"N concurrent runs spend N×cap requests against
the target while every displayed number still reads 'within budget'"* — and it was reachable by
accident, since leaving and re-entering the AI view re-enabled Start (`:151-156`).

Normalization caps a stored config at `runTokenBudget ≤ 100,000,000` and
`maxActiveRequestsPerRun ≤ 100,000` (`ai.ts:269-275`); the comment at `:279-285` explains why: a
non-numeric `maxActiveRequestsPerRun` "would make every budget comparison `NaN` and silently disable
the per-run request cap".

**Role → effect matrix** (`ROLE_EFFECTS`, `:86-92`; enforced by `mayCall`, `:504-507`):

| Role | read | local-write | environment | target-traffic |
|---|---|---|---|---|
| recon | ✓ | | | |
| planner | ✓ | | | |
| attacker | ✓ | ✓ | ✓ | ✓ |
| analyst | ✓ | ✓ | | |
| reporter | ✓ | | | |

*"The roles documented as read-only are read-only in code, not just in the prompt"* (`:80-81`). Under
`autonomy: 'readonly'`, `READONLY_WITHHELD = ['target-traffic', 'environment']` is subtracted from
every role (`:98`, `:505`) — the environment half is included because *"'No traffic' has to include the
environment change that silently stops traffic being captured at all"* (`:94-97`).

**A declined turn is never silent.** A refusal arrives as HTTP 200 with `stop_reason: 'refusal'` and
usually empty content (`anthropic.ts:13-19`). `noteRefusal` (`orchestrator.ts:468-489`) records an
error step, appends a `mesh.refused` audit row, and adds the role to `declined`. A declined recon or
planner turn falls back to `engineBriefing()` — deterministic preflight/scope/folder/ranked-surface
data, and deliberately never throwing (`:437-460`) — rather than discarding the run (`:268-285`,
`:303-316`). A declined reporter produces an explicit `'NO REPORT WAS WRITTEN'` report carrying the
unreviewed analysis, because leaving `state.report` empty made a run that had sent real traffic present
as a completed engagement with a blank report (`:349-366`). A turn cut off at the output ceiling gets
its own error step (`:420-427`).

### 11.9 Limitations

- **Egress is the operator's choice, not a defended boundary.** `THREAT_MODEL.md:54`: *"Residual risk:
  when enabled, captured content and engagement documents leave the machine — this is the operator's
  explicit choice, not a defended boundary."*
- **Redaction is off by default and best-effort on bodies.** Only headers are thorough. Prompt text is
  never redacted.
- **`autonomy: 'approve'` does nothing.** It is in the type union, marked `(future)` (`ai.ts:42`), and
  survives `normalizeAiConfig` (`:265`), but `mayCall` only special-cases `'readonly'`
  (`orchestrator.ts:505`), and the UI offers only `auto` and `readonly` (`AiMeshView.tsx:268-269`). A
  hand-edited project file set to `'approve'` runs fully autonomous.
- **No rate limiter on the mesh's Repeater path.** `session.sendRepeater` (`:680-692`) calls
  `Repeater.send` directly; `src/engine/repeater/` contains three files and a case-insensitive grep
  for `rate|limiter|throttle|token bucket` across them returns nothing. Rate limits are mandatory
  fields of a Variation plan only (`tools.ts:160-171`). The module doc-comment line *"scope is gated
  in code, rate limits are real, the audit log is written on every request"* (`prompts.ts:13`) is in
  the **file's header comment describing the preamble**, not in the `PREAMBLE` string a model sees —
  and it is true for Variation and not for `send_repeater`, where the only bounds are the per-run
  budget and the 24-iteration per-role cap.
- **The budget is charged on a prediction.** `run_variation_job` charges the job's declared `total`; if
  the job id is not found it charges `1` (`tools.ts:701-702`). A job that terminates early still
  consumed its full charge.
- **`plan.hosts` is unreachable from the desktop UI.** `MeshRunPlan.hosts` narrows the run to specific
  already-in-scope hosts (`ai.ts:183-184`) and feeds `hostLine()` in every prompt
  (`orchestrator.ts:669-671`), but `AiMeshView.start()` sends `{ objective }` only
  (`AiMeshView.tsx:163`).
- **Untrusted input is a prompt rule, not a mechanism.** Captured responses and workspace documents are
  attacker-controllable. The module comment (`prompts.ts:18-21`), the preamble (`:34`) and two tool
  descriptions (`tools.ts:203`, `:222`) all say to treat them as data, and the scope gate physically
  prevents an out-of-scope request regardless of what the model is told — but **there is no sanitizer
  between a captured response body and the model's context.**

**Test coverage of these bounds** (`test/engine/aiMesh.test.ts`, 773 lines): egress refusal (`:140`),
empty-scope fail-closed (`:159`), the per-run cap (`:174`), cost-by-request-count charging (`:271`),
the per-role iteration cap (`:293`), readonly autonomy (`:228`), emergency stop (`:248`), run-history
pruning (`:310`), the `send_repeater` scope gate including absolute-form request lines and the
canonicalized destination (`:331-454`), the redaction behaviours (`:455-517`), declined turns
(`:518-626`), and one-run-at-a-time (`:627-708`).

See [`engagement-and-hunting.md`](engagement-and-hunting.md) for the preflight, proof-gate,
hunt-memory and attack-surface-ranking layers the mesh consumes, and [`mcp-server.md`](mcp-server.md)
for why the MCP surface deliberately stops short of these tools. The mesh shipped in **0.4.0** and was
introduced there as "the first feature in TACNOC that sends data off the machine"
(`CHANGELOG.md:479-505`).

---

## 12. The Extension SDK

Three files, 808 lines:

| File | Lines | Role |
|---|---|---|
| `src/sdk/api.ts` | 125 | The public type surface. Types only — plus three exported constants (`SDK_VERSION`, `ELEVATED_PERMISSIONS`, `ALL_PERMISSIONS`; `:24`, `:35`, `:37-44`) |
| `src/sdk/host.ts` | 504 | `ExtensionHost` — forks the child process, owns the RPC bridge, redacts everything crossing the boundary, materializes findings |
| `src/sdk/subprocessRuntime.ts` | 179 | The child-process bootstrap, embedded as a `String.raw` template (`EXTENSION_HOST_SOURCE`, `:26`) that the host writes to a temp `.cjs` and forks |

Covered by 13 tests in `test/engine/sdk.test.ts` (309 lines), one Playwright UI step
(`test/e2e/full.spec.ts:144-147`) and one packaged check (`packaged.spec.ts:50`, asserting at `:92`
that exactly one extension resolved under `resourcesPath`). Read
[`extension-sdk.md`](extension-sdk.md) first — it is accurate about the isolation model. This section
covers what it does not: the actual loading path, identifiers, failure modes, and which parts are
wired to nothing.

### 12.1 The extension model

An extension is **one file of CommonJS-shaped JavaScript plus one `manifest.json`**, exporting a
single function:

```js
function activate(tacnoc) { /* register capabilities here */ }
module.exports = { activate: activate };
```

`ExtensionModule` (`api.ts:123-125`) is the whole contract. The host hands `load()` a **source
string**, not a path (`host.ts:262`) — the child never resolves a module, never reads a file, and
`require` is not in scope.

> **A multi-file extension is impossible, and an extension cannot have npm dependencies.** Everything
> ships in one file.

The child evaluates the source in a `vm` context whose only injected globals are `module`, `exports`,
`tacnoc` and `console` (`subprocessRuntime.ts:76-85`), then calls the exported `activate(api)` (`:102`).
The export is looked up as `module.exports.activate` with a fallback to `exports.activate` (`:93`); if
neither is a function the load fails with
`extension <id> does not export an activate(tacnoc) function` (`:94`).

**One child process serves every extension.** `TacnocSession` constructs exactly one `ExtensionHost`
in its constructor (`session.ts:175`), and it lives for the session, not the project — torn down only
in `dispose()` (`:304`), wired to Electron `before-quit` (`src/main/index.ts:128-133`). All loaded
extensions share that process, its 256 MB heap, and its fate.

### 12.2 Loading

**The desktop application has exactly one extension-loading path, and it loads exactly one hard-coded
extension.**

- The IPC method list contains `listExtensions` and `loadExampleExtension` (`shared/ipc.ts:155-156`),
  and the renderer binds only those two (`api.ts:181`, `:183`). There is **no `loadExtension` IPC
  channel.**
- `loadExampleExtension` (`main/ipc.ts:249-255`) reads `manifest.json` and `extension.js` from a fixed
  directory resolved by `exampleExtensionDir()` (`:33-41`): in dev,
  `<repo>/examples/extensions/header-hygiene` relative to the built `out/main/` file; when
  `app.isPackaged`, `<process.resourcesPath>/examples/extensions/header-hygiene`.
- The Extensions view offers a single button, `Load bundled example (header-hygiene)`
  (`ExtensionsView.tsx:41-43`). No file picker, no directory scan, no extension folder.

**To load your own extension you must call the engine directly:**
`TacnocSession.loadExtension(manifest, source, granted)` (`session.ts:1527-1535`), from your own Node
code embedding the engine. There is no CLI (`package.json` declares no `bin` key), and the MCP server
exposes no extension tools.

> **The permission prompt does not exist.** `api.ts:4-7` describes the model as "an extension declares
> the permissions it needs in its manifest, **the user approves them**, and the host injects an API
> object that exposes ONLY the granted capabilities." The Extensions view repeats it (`:37`). The first
> and third clauses are implemented; the approval step is not. The only shipped caller passes the
> manifest's own permission list as the grant:
> `await session.loadExtension(manifest, source, manifest.permissions);` (`main/ipc.ts:253`). There is
> no approval dialog anywhere in the renderer. `ExtensionHost.load()` intersects `granted` with
> `manifest.permissions` (`host.ts:269`) and then, if an elevated permission was declared but withheld,
> only **logs a warning** and continues (`:270-278`) — it does not refuse the load. Capability gating
> is real and enforced in the child (`subprocessRuntime.ts:54-68`; `sdk.test.ts:83-90` proves a
> withheld `transforms` permission yields zero registered transforms while checks still register), but
> **the decision of what to grant currently belongs entirely to whoever calls `loadExtension`**, and in
> the shipped app that caller grants everything asked for. If you embed the engine, `granted` is your
> enforcement point.

### 12.3 Manifest reference

`ExtensionManifest` (`api.ts:46-55`):

| Field | Type | Required | Notes |
|---|---|---|---|
| `id` | string | yes | Namespace key for every artifact this extension registers, and the rollback key in the child. A duplicate id is rejected at the host (`host.ts:266-268`) |
| `name` | string | yes | Shown in the Extensions view (`ExtensionsView.tsx:52`) |
| `version` | string | yes | Displayed next to the name (`:52`). Not used for finding provenance — see [12.8](#128-identifiers-and-namespacing) |
| `description` | string | yes | Shown in the Extensions view (`:53`) |
| `author` | string | no | The only optional field (`api.ts:51`). Referenced nowhere outside the type and the example manifest — not rendered in any view |
| `sdkVersion` | string | yes | **Not enforced.** Occurrences in the tree: the type declaration (`:53`), four test fixtures, the example manifest — nothing reads the value (`docs/extension-sdk.md:117-122`; `CHANGELOG.md:225-228`) |
| `permissions` | `Permission[]` | yes | Declared set; the effective set is `granted ∩ permissions` |

No manifest validation runs at load beyond the duplicate-id check — no schema, no required-field check,
no id character restrictions.

> **A manifest with no `permissions` array throws a `TypeError` in the host**, not a zero-permission
> load: `host.ts:269-270` dereferences `manifest.permissions.includes(...)` and
> `manifest.permissions.filter(...)` before any RPC is sent. The child's `(manifest.permissions || [])`
> fallback at `subprocessRuntime.ts:73` is unreachable through `ExtensionHost.load()`. *(Read from
> `host.ts:269-270`; not executed.)*

Example (`examples/extensions/header-hygiene/manifest.json`, verbatim):

```json
{
  "id": "header-hygiene",
  "name": "Header Hygiene (example)",
  "version": "1.0.0",
  "description": "Harmless example extension: flags an X-Debug response header, adds a ROT13 transform, counts sanitized traffic, and provides a read-only header-summary tab.",
  "author": "GreyNOC",
  "sdkVersion": "1.0.0",
  "permissions": ["passive-checks", "transforms", "read-traffic", "ui-tabs"]
}
```

### 12.4 Permissions and the API surface

Six permissions (`api.ts:26-32`), two elevated — `read-traffic` and `findings` (`:35`). Each gates
exactly one method onto the injected `tacnoc` object (`subprocessRuntime.ts:54-68`). A method for an
ungranted permission is **absent**, not throwing — which is why the example guards every registration
with `if (tacnoc.registerX)`.

| Permission | Injects | Elevated | Wired end-to-end? |
|---|---|---|---|
| `read-traffic` | `onTraffic(handler)` (`:54`) | yes | Yes — `session.ts:328` |
| `passive-checks` | `registerScannerCheck(check)` (`:55-57`) | no | Yes — `passiveScanner.ts:104-112` |
| `transforms` | `registerTransform(t)` (`:58-61`) | no | Yes — `session.ts:1545-1552`, `:1554-1557` |
| `findings` | `createFinding(f)` (`:64`) | yes | Yes — `session.ts:179-182` |
| `ui-tabs` | `registerEditorTab(tab)` (`:65-66`) | no | **No — registered and stored, never rendered** |
| `context-menu` | `registerContextMenuAction(a)` (`:67-68`) | no | **No — no code path can ever invoke it** |

Always present regardless of permissions (`api.ts:109-112`, `subprocessRuntime.ts:50-52`):
`tacnoc.version` (the host SDK version string, `'1.0.0'`, `api.ts:24`), `tacnoc.manifest`, and
`tacnoc.log(message)` — which posts a log line to the host at level `info`, prefixed `[<extId>] `
(`:52`). The host writes it through `Logger`, which redacts the message string (`logger.ts:88`).

> **Extension log lines go to Electron main-process stdout.** `consoleSink` is the sole default sink
> (`logger.ts:52`, `:116-121`) and `rootLogger` is constructed with no options (`:129`);
> `src/main/*.ts` configures no sink. There is **no file sink and no in-app log viewer**, so warn-level
> failures like `onFinding sink threw` are invisible in normal use.

#### Method signatures

```ts
onTraffic(handler: (event: SanitizedTrafficEvent) => void): void
registerScannerCheck(check: ScannerCheck): void
registerTransform(transform: TextTransform): void
createFinding(finding: ExtensionFinding): void
registerEditorTab(tab: ExtensionEditorTab): void
registerContextMenuAction(action: ExtensionContextMenuAction): void
```
(`api.ts:114-119` — all six declared optional, the type-level expression of the gating.)

`ScannerCheck` is the engine's own passive-check interface (`scanner/types.ts:33-39`):
`{ module, version, appliesTo?, run }`, where `run(ctx) => RawFinding[]` (`:22-31`) and `ctx` is
`ScanContext = { exchange, requestBodyText, responseBodyText, redactor }` (`:13-20`).

`TextTransform` is the engine's codec interface (`codec.ts:18-24`):
`{ id, label, category, transform }`, category one of `'encode' | 'decode' | 'hash' | 'compress' |
'inspect'` (`:16`).

`ExtensionFinding` (`api.ts:75-88`) requires `exchangeId`, `dedupeKey`, `title`, `severity`,
`confidence`, `description`, `remediation`, `evidence[]` — none optional. Evidence entries are
`{ location, excerpt, field? }` (`:83-87`) with `location` one of `'request-headers' |
'response-headers' | 'response-body' | 'url' | 'tls'` (`shared/findings.ts:20`), `severity` one of
`info|low|medium|high|critical` (`:6`) and `confidence` one of `tentative|firm|certain` (`:8`).

#### The two dead capabilities

`ui-tabs` and `context-menu` are worse off than `docs/extension-sdk.md:54-57` suggests ("accepted and
validated by the host … inert until that surface lands"). **No validation runs on either** — the child
stores the object as given (`subprocessRuntime.ts:66`, `:68`) and the host records only
`{extensionId, id, label}` (`host.ts:293-298`).

- **Editor tabs:** `ExtensionHost.renderTab()` exists (`host.ts:417-426`) and the child handles the
  `renderTab` message (`subprocessRuntime.ts:158-162`), but `renderTab` and `getEditorTabs` have **no
  caller anywhere in `src/`**.
- **Context-menu actions:** worse. The child handles an `invokeAction` message (`:163-166` — the sole
  occurrence of that string in the tree), but **`ExtensionHost` has no method that sends it.** There is
  no host-side code that can ever fire a context-menu action. `getContextMenuActions()` (`host.ts:437`)
  likewise has no caller.

`docs/adr/0006-subprocess-extension-host.md:36-38` claims "Passive checks, transforms, tab renders and
context-menu actions are invoked over an async RPC bridge" — for context-menu actions the sending half
does not exist; for tab renders it exists but is never called.

> `docs/extension-sdk.md:125-126` names five "host getters", **two of which do not exist**:
> `drainCreatedFindings` (findings are pushed, not drained — `subprocessRuntime.ts:64` →
> `host.ts:202-218`) and `getScannerChecks` (the real method is `getCheckModules`, `host.ts:440`).
> `getTransforms`, `getEditorTabs` and `getContextMenuActions` do exist (`:431`, `:434`, `:437`).

### 12.5 Lifecycle

**Startup.** The `ExtensionHost` constructor runs at session construction, before any extension exists.
It `mkdtempSync`s `tacnoc-ext-*` under the OS temp dir (`host.ts:122`), writes `extension-host.cjs`
with mode `0o600` (`:123-124`), and `fork()`s it (`:125-131`) with:

- `env` scrubbed to `ELECTRON_RUN_AS_NODE=1` plus only `PATH`, `SystemRoot`, `windir`, `TEMP`, `TMP`,
  `HOME`, `USERPROFILE`, `LANG`, `TZ` (`:31-49`);
- `execArgv: ['--max-old-space-size=256']` (`:129`);
- `stdio: ['ignore','ignore','ignore','ipc']` — no inherited stdio at all (`:128`);
- `cwd` set to the temp dir (`:127`); `serialization: 'advanced'` (`:130`); `child.unref()` (`:133`).

The child posts `{type:'ready'}` as its last bootstrap statement (`subprocessRuntime.ts:178`);
`host.ready` resolves there. The four RPC methods await it (`load` `:263`, `runChecks` `:320`,
`applyTransform` `:407`, `renderTab` `:418`), but `dispatchTraffic()` does **not** — it only checks
`this.child.connected` (`:304-306`). Traffic dispatch is fire-and-forget and not ready-gated.

**Load.** `host.load(manifest, source, granted)` → duplicate-id check (`:266-268`) → grant intersection
(`:269`) → RPC `{type:'load'}` (`:280-285`) → child compiles and runs the source top-level in the `vm`
with `timeout: 2000` (`subprocessRuntime.ts:91`) → child calls `activate(api)` (`:102`) → child returns
the registration inventory (`:113-119`) → host merges it into its metadata arrays (`host.ts:290-300`).

**Rollback.** The child snapshots the registries before `activate()` (`:97-100`) and, if `activate`
throws, deletes only the keys this activation added (`:103-109`). Proven by `sdk.test.ts:170-201`: an
orphaned check from a failed `activate` does not run on later scans.

**Invocation.** Four host→child entry points:

| Trigger | Host method | Child handler |
|---|---|---|
| Every ingested exchange | `dispatchTraffic()` (`host.ts:304-307`), fire-and-forget, skipped when `trafficSubscribers === 0` (`:305`) | `subprocessRuntime.ts:146-149` |
| Passive scan of every exchange | `runChecks()` (`:314-335`), async RPC, returns `[]` immediately when no checks are registered (`:319`) | `:150-152` |
| Encoder view transform | `applyTransform()` (`:406-415`) | `:153-157` |
| *(nothing)* | `renderTab()` (`:417-426`) | `:158-162` |
| *(nothing — no host sender exists)* | — | `:163-166` (`invokeAction`) |

"Every ingested exchange" means all three traffic producers: the proxy (`session.ts:386`), the
Variation engine (`:247`), and Repeater sends (`:690`) — all route through `ingest()` (`:319-341`).

Inside `runChecks`, each check gets its **own `structuredClone` of the exchange**
(`subprocessRuntime.ts:129`) so one check cannot perturb what a later check — or a later `appliesTo` —
observes; if the clone throws, the shared object is used as a fallback. This was ADR 0006 second-round
finding 4 (`adr/0006:74-76`). A throwing check is caught and logged as a warn inside the child
(`:134-136`); it does not abort the other checks.

**Shutdown.** `terminate()` sends `{type:'shutdown'}` (`host.ts:462`), then `SIGKILL` after 500 ms
(`:466`), then removes the temp dir (`:470`). The child also exits on IPC `disconnect` so it can never
be orphaned (`subprocessRuntime.ts:176`).

> **Crash — fail closed, and no recovery.** On an *unexpected* child exit the host logs an error and
> clears every capability array: extensions, checks, transforms, tabs, actions, traffic subscribers
> (`host.ts:161-181`), and removes the temp dir (`:181`). The app never advertises a check that can no
> longer run. All pending RPCs reject (`:159-160`); later calls reject immediately (`:236-238`).
> **There is no re-fork** — the code says so: "Re-fork on demand is future work; for now the operator
> sees the error and can reload" (`:164-166`). One crashed extension kills extension support for the
> rest of the session; restart the app. Verified by `sdk.test.ts:286-308`, which SIGKILLs the child and
> asserts transforms reject while `runChecks` resolves to `[]`.

### 12.6 What an extension can and cannot reach

The permission model governs the `tacnoc` object. The `vm` context governs everything else, and it is
narrower than most people expect. Reconstructing the context exactly as `subprocessRuntime.ts:76-90`
builds it (`vm.createContext(sandbox, {codeGeneration:{strings:false, wasm:false}})`) on Node v24.14.1
and probing every name:

| Name | `typeof` inside the extension |
|---|---|
| `require`, `process` | `undefined` |
| `setTimeout`, `setInterval`, `queueMicrotask` | `undefined` |
| `Buffer`, `URL`, `TextEncoder`, `TextDecoder`, `fetch`, `structuredClone` | `undefined` |
| `crypto`, `performance`, `atob`, `btoa`, `AbortController` | `undefined` |
| `JSON`, `Math`, `Promise`, `Date`, `RegExp`, `Reflect`, `Proxy`, `WeakRef`, `Intl`, `Error`, `globalThis` | present |
| `console`, `tacnoc`, `module`, `exports` | present (the four injected names) |
| `eval(...)`, `new Function(...)`, `Function(...)` | all throw `EvalError: Code generation from strings disallowed for this context` |
| `tacnoc.constructor` | `function` — the documented escape handle; see [12.10](#1210-security-considerations) |

*Probe method: rebuilt the sandbox object and `vm.createContext` options from
`subprocessRuntime.ts:76-90` in a standalone script and ran the same
`new vm.Script(...).runInContext(ctx, {timeout:2000})` call the loader uses. The proxy was not started
and no packet was sent.*

So an extension gets ECMAScript, plus `tacnoc`, `module`, `exports`, and a three-method `console`.
**No timers.** No `Buffer`, so no binary work beyond strings. No `URL`, so parse URLs by hand. No
`crypto`, so no hashing without writing it yourself. And `console.info` / `console.debug` /
`console.table` are `undefined` — the shim defines only `log`, `warn`, `error`
(`subprocessRuntime.ts:80-84`); calling anything else is a `TypeError`.

What it cannot reach through *any* route: the host process's memory, the `TacnocSession`, the project
database, the secret store, the CA private key. Those live in a different OS process and the bridge
carries only structured-cloneable messages (`host.ts:130`, `adr/0006:33-34`, `THREAT_MODEL.md:27-38`).

### 12.7 The data an extension sees

Everything crossing into the child is redacted first, by an `ExtensionHost`-owned `Redactor`
constructed with **all three masks hard-on** (`session.ts:176`).

> This is **not** the project's redaction config — the `PassiveScanner` takes
> `project.config.redaction` (`session.ts:265`) but the `ExtensionHost` does not. An operator who
> turns redaction down in Settings does not widen what extensions see; turning it up does not narrow
> it further.

**`onTraffic` events** (`SanitizedTrafficEvent`, `api.ts:57-72`, built by `host.sanitize()` at
`:482-503`): id, source, scheme, host, port, method, redacted URL, `inScope`, redacted request headers,
and — when a response exists — status code, redacted response headers, MIME. **Bodies are not included
at all** (`api.ts:57-58`).

**Passive checks** get more, but still redacted (`host.ts:326-331`): the exchange with its URL and
request/response headers passed through the redactor and raw body bytes stripped
(`redactExchangeForChecks`, `:342-365`), plus `requestBodyText` and `responseBodyText` run through
`redactor.redactText()`. The comment at `:321-325` explains why: without it, the *non-elevated*
`passive-checks` permission would see strictly more secret material than the *elevated* `read-traffic`
one.

Two things this does **not** cover:

> - **Scope is not a boundary.** `ingest()` dispatches every exchange regardless of `inScope`
>   (`session.ts:328`), and `PassiveScanner.scan()` applies no scope test before invoking the extension
>   runner (`passiveScanner.ts:58-114`, `:104-112`). Extensions observe out-of-scope traffic metadata;
>   `event.inScope` is advisory, and honouring it is the extension's job.
> - **`ctx.redactor` inside a check is a no-op.** The child passes `redactorShim`
>   (`subprocessRuntime.ts:37-43`) as `ctx.redactor` (`:130`) — `redactText` and `redactUrl` are
>   identity functions, `redactHeaders` returns its argument, and `redactBodyText` returns `''`. Its
>   TypeScript type says `Redactor`. Copy a built-in check that leans on `ctx.redactor` and the
>   redaction silently disappears. The inbound data is already redacted, so this is not a leak *into*
>   the extension — but do not rely on it for anything you emit.

Findings are re-redacted on the way back: `materialize()` runs every evidence excerpt through
`redactText()` (`host.ts:398`).

### 12.8 Identifiers and namespacing

Get these wrong and findings land under the wrong module or transforms collide.

| Artifact | Key format | Source |
|---|---|---|
| Transform id | `ext.<extensionId>.<transform.id>` | `subprocessRuntime.ts:60` |
| Editor tab key | `<extensionId>:<tab.id>` | `:66` |
| Context action key | `<extensionId>:<action.id>` | `:68` |
| Check module (finding provenance) | `ext:<extensionId>:<check.module>` | `:114`, `:133` |
| Finding module, via `createFinding` | `ext:<extensionId>` | `host.ts:209` |
| Finding `dedupeKey` | `<module>\|<your dedupeKey>` | `host.ts:388` |

`moduleVersion` for a check-produced finding is the check's own `version` (`subprocessRuntime.ts:133`
→ `host.ts:333`); for a `createFinding()` finding it is **hard-coded `'1.0.0'`** (`host.ts:210`) — your
manifest version is not recorded.

The renderer's Extensions view filters extension transforms with `id.startsWith('ext.')`
(`ExtensionsView.tsx:16`); the Encoder view calls the same `listTransforms` with no filter
(`EncoderView.tsx:17`), merging built-in and extension transforms (`session.ts:1545-1552`), and
`applyTransform` routes to the child only when `extHost.hasTransform(id)` (`:1554-1557`).

### 12.9 A minimal worked example

The bundled example is `examples/extensions/header-hygiene/extension.js` — 84 lines exercising four
capabilities: a passive check for `X-Debug` (`:16-44`), a ROT13 transform (`:47-59`), a traffic counter
(`:63-68`), and a read-only editor tab (`:71-81`), each guarded on a feature check. Read it. A smaller
one that shows only the load-bearing shape:

`manifest.json`
```json
{
  "id": "cache-control-audit",
  "name": "Cache-Control Audit",
  "version": "1.0.0",
  "description": "Flags responses that carry no Cache-Control header.",
  "author": "you",
  "sdkVersion": "1.0.0",
  "permissions": ["passive-checks"]
}
```

`extension.js`
```js
function activate(tacnoc) {
  tacnoc.log('cache-control-audit active (sdk ' + tacnoc.version + ')');

  // Guard every registration: an ungranted permission means the method is ABSENT.
  if (!tacnoc.registerScannerCheck) return;

  tacnoc.registerScannerCheck({
    module: 'cache-control',
    version: '1.0.0',
    appliesTo: function (ex) {
      return !!ex.response;
    },
    run: function (ctx) {
      var ex = ctx.exchange;
      var has = ex.response.headers.some(function (h) {
        return h.name.toLowerCase() === 'cache-control';
      });
      if (has) return [];
      return [
        {
          dedupeKey: ex.host + '|no-cache-control',
          title: 'Response has no Cache-Control header',
          severity: 'info',
          confidence: 'firm',
          description: 'The response omits Cache-Control; intermediaries may cache it by default.',
          remediation: 'Set an explicit Cache-Control on responses that carry user data.',
          evidence: [{ location: 'response-headers', excerpt: 'Cache-Control: (absent)' }],
        },
      ];
    },
  });
}

module.exports = { activate: activate };
```

This mirrors the shape of the bundled example (`extension.js:17-43`) and the `ScannerCheck`/
`RawFinding` interfaces (`scanner/types.ts:22-39`). *(Written for this manual; not a file in the tree
and not executed. The identifier claims below follow from `subprocessRuntime.ts:114` and
`host.ts:388`.)* Findings from this check reach the project as module
`ext:cache-control-audit:cache-control`, dedupeKey
`ext:cache-control-audit:cache-control|<host>|no-cache-control`.

Loading it requires embedding the engine (there is no UI path):

```ts
const manifest = JSON.parse(await fs.readFile('manifest.json', 'utf8'));
const source = await fs.readFile('extension.js', 'utf8');
await session.loadExtension(manifest, source, ['passive-checks']);   // session.ts:1527
```

### 12.10 Security considerations

The honest posture, which `docs/extension-sdk.md:82-88`, `THREAT_MODEL.md:27-38` and ADR 0006
(`:40-46`) all state consistently: **this is a strong boundary, not a sandbox. Only load extensions you
trust.**

**What the boundary gives you.** The child is a separate OS process with a scrubbed environment, a
256 MB heap, no inherited stdio, its own cwd, and an IPC-only bridge that carries no object references.
A full `vm` escape lands in that child and nowhere else — it cannot read the engine, the session, the
project database, the secret store, or the CA private key. Everything handed to the extension is
redacted first, with masks forced on independent of user settings.

**What it does not give you.** The child keeps Node's built-ins. `subprocessRuntime.ts:15-23` says so
directly: a determined extension can reach the child realm's globals via a host-realm function's
`.constructor` and from there the child's own filesystem and network. The probe above confirms the
handle is live — `typeof tacnoc.constructor` is `function` inside the context, and `tacnoc` is a
host-realm object. There is no seccomp-bpf, no AppContainer, no `sandbox_init` (`adr/0006:43-44`).

> **The correct threat statement: a malicious extension can read and write your filesystem and make
> arbitrary network connections from your host, using your credentials and your egress IP. It just
> cannot read TACNOC's secrets while doing it.** On an authorized engagement an extension with outbound
> network access, running on the operator workstation during a test, is an out-of-scope traffic source
> and an exfiltration path for whatever the operator's user account can read. Loading an unaudited
> extension mid-engagement is a scope risk, not just a host-security risk.

**Availability, not just confidentiality.** Three denial-of-service shapes are reachable from a benign
bug:

1. `activate()` is called **outside** the `vm` timeout (`subprocessRuntime.ts:102` is a plain call
   after the `runInContext` at `:91`; the 2 s `timeout` option covers only top-level evaluation). An
   infinite loop in `activate` wedges the child permanently. The host's `load` RPC times out at 5 s
   (`host.ts:233`) but the child stays hung, and every subsequent RPC — including every passive scan —
   times out too.
2. Check `run()`, `transform()` and `render()` have **no in-child timeout at all**
   (`subprocessRuntime.ts:132`, `:156`, `:161` are plain calls). Only the 5 s host-side RPC bounds the
   caller.
3. One child serves all extensions, and a crash drops every extension's capabilities with no re-fork.

`host.ts:240-242` acknowledges the first two: "A misbehaving extension can run an infinite loop the
child process cannot interrupt."

**Robustness against a hostile child is genuinely good.** The IPC `message` handler is fully wrapped so
a malformed message can never throw out of the listener and crash the host (`host.ts:187-228`), and a
non-object `finding` payload is dropped at `:206`. `materialize()` coerces every finding field,
defaulting an out-of-range severity to `info` and confidence to `tentative` (`:374-383`) and a
non-array `evidence` to `[]` (`:384`). `sdk.test.ts:219-251` proves the host survives
`createFinding(42)` and `createFinding(null)`, still delivers the valid finding that follows, and still
answers RPCs; `:253-284` proves `severity:"OMEGA"` → `info` and `confidence:"absolute"` → `tentative`.

> One field escapes coercion: `evidence[].location` is a bare cast with a `'response-body'` default
> (`host.ts:397`), not a membership test against the five legal values. An extension can store an
> arbitrary `location` string in a finding.

**Auditing checklist for a third-party extension.** Because it is one file with no dependencies, review
is tractable — read all of it:

- Does it try to escape the `vm` (`.constructor`, `__proto__`, prototype walking off a passed-in
  object)? Nothing else in the file should be reaching for a function's `constructor`.
- Does it exfiltrate? With no `fetch`/`Buffer`/timers/`crypto` in scope, an exfil path requires an
  escape first — so an escape attempt *is* the finding.
- What does it declare? Grant the minimum; `granted` is intersected with the manifest (`host.ts:269`),
  so passing a narrowed array actually narrows the API.
- `sdkVersion` is decorative. Do not treat it as a compatibility gate.

### 12.11 Maturity

The SDK is **structurally sound and functionally partial**. The isolation work is real, reviewed
(ADR 0006 `:59-93` records a second adversarial round with nine confirmed-and-fixed findings — items
1-7 in the extension host, items 8-9 in the release/checksum config), and regression-tested
(`adr/0006:91-93`). The four data-plane capabilities — checks, transforms, traffic, findings — work end
to end and are proven by tests. But:

- Two of six permissions (`ui-tabs`, `context-menu`) drive nothing; `context-menu` has no invocation
  path at all, in either direction.
- There is no user-facing way to load any extension other than the bundled example, and no approval UI
  despite both the API doc comment and the Extensions view copy describing one.
- Version negotiation is declared and unimplemented.
- The host cannot recover from a child crash without an app restart.

`docs/capability-matrix.md:23` rates Extensions "Implemented", which is fair for the engine but
overstates the product surface. **Treat the SDK as an engine-embedding API that happens to ship one
demo, not as a plugin ecosystem.**

---

## 13. Safety and limits

For every control: what it covers, and what it does not. Read the right-hand column as the operative
one.

### 13.1 Scope

**Covers.** Variation job creation and every generated Variation request; the AI mesh's
`send_repeater`; starting an AI mesh run at all. Fail-closed by default — a new project is in scope
for nothing. Excludes evaluated first and always win. Paths derived with the same parser the sender
uses, so an absolute-form request line cannot smuggle a path past a path-scoped rule.

**Does not cover.** The proxy (labels only, forwards everything). The human-driven Repeater. The
interceptor. The passive scanner. History rows already stamped (scope edits are not retroactive). A
`*` in a host string under `exact` or `subdomain` (literal asterisk, silently dead). A rule with
`enabled` absent from a hand-edited project file (preflight and the mesh gate count it, `evaluateScope`
does not). IDN/punycode folding. IPv6 bracket-form differences between `targetFromUrl` and
`parseAuthority`. An invalid regex on an *exclude* rule, which then protects nothing without an error.

### 13.2 Authorization reference

**Covers.** Preflight reports it as a blocker when absent from both the profile and the project, and
quotes it in the `ok` check's detail.

**Does not cover.** Anything mechanical. No engine path refuses to act because it is missing, including
`startMeshRun`, which checks scope and the API key only. The single soft halt is the recon role
answering `BLOCKED:` — model-mediated, except on the declined-recon path where the engine's own
briefing prepends it deterministically.

### 13.3 Preflight

**Covers.** Fifteen graded checks grounded in observable facts — certificate validity windows, the
count of decrypted HTTPS exchanges actually captured, the `User-Agent` on requests already sent.

**Does not cover.** Enforcement. `ready` is read only by the AI briefing text and the Engagement view.
A `BLOCKER` row stops nothing. `proxy-bind` is raised *after* the proxy has already bound to the
non-loopback address.

### 13.4 Limits

**Covers.** Per-job request ceiling with a hard-compiled `ABSOLUTE_MAX` of 100,000 that no
configuration can raise; per-job token-bucket rate limiting and a concurrency semaphore; validated
bounds on concurrency (1–64), rate (≤1000/s), timeout (100–120,000 ms), positions (1–16), payload
value size (64 KiB, list payloads only), base request size (2 MiB) with a worst-case pre-flight and a
render-time byte projection; a response-regex ReDoS structural check; a per-mesh-run active-request
budget charged by requests actually launched.

**Does not cover.** Cross-job or per-host rate pooling — three jobs at 8 rps deliver 24 rps to one
origin. Any upper bound on `maxRequestsPerJob` beyond `ABSOLUTE_MAX`. Any upper bound in the Settings
UI (`clamp` only floors). Regex patterns pathological in ways the structural check does not model
(`(a|a)+`), which freeze the job on the engine's event loop and defeat pause/stop. The mesh budget
caps request *count*, not rate — 50 requests at 1000 rps with concurrency 64 is within the rules. And
`Settings → Automation limits` configures nothing at all.

### 13.5 Emergency stop

**Covers.** Every Variation job (abort signal reaches the in-flight `sendRaw`); the intercept queue,
released as **drop**; every AI mesh run, including the provider HTTP call. Also fires automatically on
application quit.

**Does not cover.** The proxy — the listener stays bound and keeps capturing and forwarding.
Interception state — the next request is held again. An in-flight Repeater request — `Repeater.send`
takes no `AbortSignal`. An AI tool call already dispatched. The passive scanner, extension checks, the
project, the CA, or any stored data. Stopped jobs are not resumable. Held intercept messages are
discarded, so any half-completed manual workflow is lost.

### 13.6 The audit log

**Covers.** Automation: variation job lifecycle, out-of-scope skips, mesh start/request/refusal/
completion/error, CA rotate and revoke, engagement profile updates, hunt-memory clears, AI egress
toggles, proof gradings, project folder adoption. `detail` and `target` are redacted on write with a
hardcoded all-on redactor. No setting can disable it, and there is no `UPDATE` or `DELETE` against
`audit_log` anywhere in `src/`.

**Does not cover.** Manual traffic — no Repeater send, no proxied request, no interception
forward/drop/edit produces a row. Tamper-resistance — the rows sit in plaintext columns in a SQLite
file the operator owns and can edit with any tool; "immutable automation audit"
(`capability-matrix.md:26`) should be read as "the app never rewrites it". Entries emitted with no
project open, which the optional chain in `session.ts:196` silently drops. The target host of a
`run_variation_job` `mesh.request` row, because `targetOf` finds no `url`/`target`/`base` in that
tool's `{id}` input. `note_exchange` and `record_hunt_outcome`, which write nothing. Reads are capped
at 500 (`AuditRepo.list`) / 1000 (the Audit view) / 5000 (the export), all `ORDER BY id DESC`, with no
pagination and no oldest-first view.

### 13.7 Secret redaction

One class, `Redactor` (`redactor.ts:82-157`), three booleans, mask string `[REDACTED]` (`:20`).

Header rules (`redactHeaderValue`, `:100-124`):

| Header | Governed by | Result |
|---|---|---|
| `cookie` | `maskCookies` | each `name=value` pair keeps its **name**, value replaced (`:171-179`) |
| `set-cookie` | `maskCookies` | first pair's value replaced, **attributes preserved** (`:161-169`) |
| `authorization`, `proxy-authorization` | `maskAuthorization` | whole value replaced (`:105-110`) |
| `x-api-key`, `x-auth-token`, `x-amz-security-token`, `x-csrf-token`, `x-xsrf-token` | **`maskAuthorization`** (deliberately, not `maskSecretPatterns`) | whole value replaced (`CREDENTIAL_HEADERS` `:23-33`, minus `OWN_TOGGLE_HEADERS` `:36-41`, branch `:116-122`) |
| anything else | `maskSecretPatterns` | free-text pattern pass (`:123`) |

Twelve patterns, in order, "more specific patterns run first" (`SECRET_PATTERNS`, `:52-80`):
`private-key` (PEM block), `jwt`, `aws-access-key` (`AKIA…`), `google-api-key` (`AIza…`),
`github-token` (`gh[posru]_…`), `slack-token` (`xox[baprs]-…`), `stripe-key`
(`(sk|rk|pk)_(live|test)_…`), `anthropic-key` (`sk-ant-…`), `openai-key`
(`sk-(proj|svcacct|admin)-…`), `bearer`, `basic`, and `sensitive-assignment` — a generic `key=value`
whose key name contains password/passwd/pwd/secret/api_key/apikey/token/auth, masking **the value
only** (`:76-79`, applied `:90-91`).

URL handling (`redactUrl`, `:131-148`): query parameters whose URL-decoded name matches
`SENSITIVE_PARAM_NAMES` — `access_token`, `id_token`, `refresh_token`, `api_key`, `apikey`, `secret`,
`client_secret`, `password`, `passwd`, `pwd`, `auth`, `session`, `sig`, `signature`, `code` (`:44-45`)
— have their values replaced wholesale; the path and remaining values still get the pattern pass.

**Covers** (surface → config used): structured logs, hardcoded all-on (`logger.ts:88`, `:94-113`);
audit `target` + `detail`, hardcoded all-on; passive-scanner finding evidence, **project config**;
extension host traffic/check payloads/findings, project config; hunt memory on write, hardcoded
all-on; AI tool results when `redactBeforeSend` is on, hardcoded all-on.

**Does not cover.**

- **Storage.** The proxy, Repeater and Variation engine store the real bytes. Redaction protects
  *derived* artifacts only — the module header says exactly that (`:10-13`).
- **The message viewer.** `getExchangeDetail` → `messageDetail` returns **unredacted** headers and body
  plus a `SensitivityReport` (`session.ts:615-639`), and the "mask" is a CSS blur that the HEX tab does
  not even apply.
- **The project export.** Raw decrypted bodies and raw headers. Findings and audit rows in the export
  are redacted only because they were redacted *at write time* — and findings replayed by `import()`
  are not redacted at all (`projectStore.ts:276`).
- **AI prompts and the engine briefing**, which carry the authorization reference, the CA subject and
  fingerprint, engagement-folder filenames, in-scope and excluded hosts, and ranked endpoint paths.
- **Bodies, reliably.** Pattern-based and best-effort: "an opaque, non-pattern token sitting in a body
  may still pass" (`shared/ai.ts:79-80`).
- It is deliberately conservative: "better to occasionally miss an exotic secret than to mangle large
  amounts of normal traffic" (`redactor.ts:10-11`). Do not treat it as a guarantee.
- **`redactBeforeSend` defaults to `false`.**

### 13.8 At-rest encryption

**Covers.** Request and response headers, inline request and response bodies, per-exchange notes,
WebSocket payloads, and every blob file — AES-256-GCM under a per-project DEK, with blob ids derived by
HMAC so the store is not a known-plaintext oracle. Verified against raw disk bytes by test, not against
the API.

**Does not cover.** Every plaintext column listed in [4.6](#46-what-is-encrypted-at-rest-and-what-is-not),
notably `url`, `host` and `target` — and URLs routinely carry secrets. `project_meta` (scope, config,
engagement profile, AI config). `findings`, including evidence. `suppressions`. `audit_log`.
**`saved_requests.raw`, the full raw HTTP request text including whatever `Cookie` or `Authorization`
it carried.** And it does not survive an export, which is plaintext.

With the file-backed secret store — the default for anything that is not the Electron app — it protects
nothing against someone holding the folder, because `secrets.key` is in the same directory.
`isSecure()` returns `false` and the file calls itself obfuscation-grade. Preflight only warns.

### 13.9 The TLS interception CA

**Covers.** Per-project, generated locally, RSA-3072, five-year validity, private key in OS secure
storage under the desktop app. The app never installs or removes it from a trust store; every install
guide ships its removal command. Rotate and revoke both drop currently-intercepted sockets so plaintext
cannot keep flowing under a status that says interception is off. A revocation marker survives a
reopen.

**Does not cover.** Any external revocation mechanism — no CRL, no OCSP. Leaf key rotation — one
RSA-2048 key pair is shared by every host and regenerated only on project open. The certificate/key
pairing — nothing checks that a loaded key matches a loaded certificate, which is how the
headless-open path silently pairs an old key with a new certificate. Client-side trust — removing it is
your separate action. And it can be rotated or revoked by the AI mesh when `allowCertOps` is granted.

### 13.10 The MCP boundary

**Covers.** Eight tools, all pure and offline. No project, no SQLite, no secret, no packet, no
listening socket, no third-party import. The loaded module closure imports only `node:fs`, `node:path`,
`node:url`, `node:crypto`, `node:zlib`. A registry test pinned to an exact list fails on any addition,
removal or rename.

**Does not cover.** Input validation against `inputSchema` — the server does not enforce it, and four
handlers deliberately default missing arguments to `''`. `diff_bytes` base64 validation. Protocol
version negotiation — `initialize` echoes whatever the client asked for. And the boundary is safe
*because nothing it exposes can reach a target*, not because it is guarded: the budget, audit and abort
controls live in the AI orchestrator's `wrapActive`, not in the tool handlers.

### 13.11 The AI mesh boundary

**Covers.** Four gates before a run starts (`enabled`, `egressAcknowledged`, an enabled include rule,
an API key), each per project. Role→effect permissions enforced in code, not prompt. A per-run
active-request budget charged by requests launched. One run at a time. `send_repeater` scope-gated at
the tool boundary with redirects forced off and the canonicalized destination forwarded. A read-only,
denylisted, containment-checked workspace reader. `baseUrl` honoured only as an `https:` origin.

**Does not cover.** `Test connection`, which reaches the provider with the mesh off. Prompt redaction.
Body redaction beyond patterns. `autonomy: 'approve'`, which is inert. A rate limiter on the mesh's
Repeater path. Any sanitizer between attacker-controlled captured content and the model's context. A
per-payload egress record. And it does not make egress a defended boundary — `THREAT_MODEL.md:54` calls
it "the operator's explicit choice".

### 13.12 The extension boundary

**Covers.** A separate OS process with a scrubbed environment, a 256 MB heap, no inherited stdio, its
own cwd, and an IPC-only bridge carrying no object references. A `vm` context with `eval` and
`Function` disabled and no Node globals. All data redacted on the way in with masks forced on.
Permission gating by method absence. Registration rollback on a failed `activate`. Fail-closed on an
unexpected child exit. Full coercion of finding fields from a hostile child.

**Does not cover.** A sandbox. The child keeps Node's built-ins, and `tacnoc.constructor` is a live
handle into the host realm — a malicious extension can read and write your filesystem and make
arbitrary network connections from your host. Timeouts on `activate()`, `run()`, `transform()` or
`render()` inside the child. Recovery from a crash (no re-fork; restart the app). Scope — extensions
see out-of-scope traffic metadata. `evidence[].location` validation. And the shipped app grants every
extension every permission its own manifest asks for, because the approval UI does not exist.

---

## 14. Reference

### 14.1 npm scripts

Every script in `package.json:13-36`, in file order.

| Script | Exact command | What it does | When an operator needs it |
|---|---|---|---|
| `dev` | `electron-vite dev` | Launches the desktop app in dev mode | Normal development |
| `build` | `npm run typecheck && electron-vite build` | Typechecks, then bundles main/preload/renderer into `out/` | Before `start`, `test:e2e`, or any packaging |
| `build:mcp` | `tsc -p tsconfig.mcp.json` | Emits the standalone MCP stdio server to `out/mcpsrv/` | After cloning, and after changing `src/mcp` or engine modules it imports |
| `start` | `electron-vite preview` | Runs the built bundles | Sanity-checking a production bundle without packaging |
| `typecheck` | `tsc --noEmit -p tsconfig.json` | Typecheck only, no emit | Part of `ci`; standalone for a fast check |
| `lint` | `eslint . --ext .ts,.tsx --max-warnings 0` | ESLint, **zero warnings tolerated** | Part of `ci`; required before PRs (`CONTRIBUTING.md:30`) |
| `lint:fix` | `eslint . --ext .ts,.tsx --fix` | Same, applying autofixes | Clearing mechanical lint failures |
| `format` | `prettier --write "src/**/*.{ts,tsx,css}" "test/**/*.ts"` | Rewrites source formatting in place | Fixing a `format:check` failure |
| `format:check` | `prettier --check "src/**/*.{ts,tsx,css}" "test/**/*.ts"` | Verifies formatting; fails without changing files | Part of `ci` |
| `test` | `vitest run` | 28 test files under `test/**/*.test.ts`, headless, loopback-only | The default gate; no build required |
| `test:watch` | `vitest` | Watch mode | Iterating on engine code |
| `test:coverage` | `vitest run --coverage` | V8 coverage over `src/engine`, `src/shared`, `src/sdk`; text + HTML | Coverage review |
| `test:e2e` | `playwright test` | 10 declared tests across 7 specs, driving the real Electron app | **Requires `npm run build` first and a display.** Mandatory release gate |
| `audit` | `npm audit --audit-level=high` | Dependency audit of the **full tree** — no `--omit` flag | Pre-release step 3; also `release.yml:38` |
| `ci` | `npm run format:check && npm run lint && npm run typecheck && npm run test` | The quality gate | Before every PR and before tagging |
| `sbom` | `node scripts/generate-sbom.mjs` | CycloneDX 1.5 SBOM from `package-lock.json` → `sbom.json` | Pre-release step 4 |
| `dist` | `npm run build && electron-builder` | Builds, then packages the **host platform's** configured targets into `dist/` | Generic packaging. `release.yml:76` runs `npm run dist -- --publish never` |
| `dist:win` | `node scripts/package-windows.mjs` | **Wipes `dist/`**, builds, packages NSIS + portable, writes the checksum manifest | Cutting Windows artifacts on a Windows host |
| `dist:linux` | `node scripts/package-linux.mjs` | Builds and packages the Linux x64 `tar.gz` (cross-builds from Windows) | Cutting the Linux archive |
| `dist:dir` | `npm run build && electron-builder --dir` | Unpacked app directory only — no installer | Inspecting packaging output |
| `checksums` | `node scripts/checksums.mjs` | SHA-256 manifest of `dist/` → `dist/SHA256SUMS-<os>.txt` | After any packaging that did not write one |
| `release:prepare` | `npm run ci && npm run audit && npm run sbom` | Gate + audit + SBOM | Immediately before bumping the version and tagging |

### 14.2 Configuration keys and defaults

`DEFAULT_LIMITS` / `defaultEngineConfig()` — `src/engine/config.ts:14-52`.

| Setting | Default | Where enforced |
|---|---|---|
| `listener.host` | `127.0.0.1` | `DEFAULT_PROXY_HOST`, `shared/model.ts:173` |
| `listener.port` | `8080` | `DEFAULT_PROXY_PORT`, `model.ts:174` |
| `body.spillToDiskAfterBytes` | 5 MiB (`config.ts:16`) | `BodyCollector`, `bodyCollector.ts:56` |
| `body.maxCapturedBytes` | 100 MiB (`:17`) | `bodyCollector.ts:37`, `:44-46` — capture stops, body marked `truncated` |
| `automation.maxConcurrency` | 4 (`:20`) | **nothing reads it** |
| `automation.requestsPerSecond` | 8 (`:21`) | **nothing reads it** |
| `automation.timeoutMs` | 20 000 (`:22`) | **nothing reads it** |
| `automation.maxRequestsPerJob` | 5 000 (`:23`) | **nothing reads it** |
| `maxProxyConnections` | 512 (`:25`) | `proxyServer.ts:281-283` — socket destroyed over the cap |
| `upstreamTimeoutMs` | 30 000 (`:26`) | `proxyServer.ts:561` |
| `redaction.maskCookies` | `true` (`:45`) | [13.7](#137-secret-redaction) |
| `redaction.maskAuthorization` | `true` (`:46`) | [13.7](#137-secret-redaction) |
| `redaction.maskSecretPatterns` | `true` (`:47`) | [13.7](#137-secret-redaction) |
| `captureWebSockets` | `true` (`:49`) | proxy |
| `interceptHttp2` | `true` (`:50`) | ALPN `h2` offered |
| `SAFE_BIND_HOSTS` | `127.0.0.1`, `::1`, `localhost` (`:34`) | advisory only (`isLoopbackBind`, `:36-38`) |

AI config defaults — `src/shared/ai.ts:198-221`: see [11.1](#111-default-state).

### 14.3 Constants and caps

| Constant | Value | Source |
|---|---|---|
| Database filename | `belcher.db` | `projectStore.ts:36` |
| Blobs directory | `blobs/` | `:37` |
| CA certificate | `ca.pem` | `:38` |
| DEK secret key name | `project-data-key` | `:39` |
| CA key secret name | `tls-ca-private-key` | `certificateAuthority.ts:34` |
| Blob-id HMAC label | `belcher-blob-id` | `contentCipher.ts:27` |
| File-store scrypt salt | `belcher-secret-store` | `secretStore.ts:114`, `:123` |
| DEK size | 32 bytes | `contentCipher.ts:17` |
| GCM IV / tag | 12 / 16 bytes | `contentCipher.ts:15-16` |
| Schema version (`user_version`) | 2 | `migrations.ts:170-172` |
| Export format version | 1 | `projectStore.ts:35` |
| Export format tag | `greynoc-belcher-project` | `:217` |
| Spill-to-disk threshold (default) | 5 MiB | `config.ts:16` |
| Max captured body (default) | 100 MiB | `config.ts:17` |
| Import inline/blob threshold | 64 KiB (hardcoded) | `projectStore.ts:317` |
| Export per-body cap (default) | 25 MiB | `:188` |
| Export audit cap | 5000 entries | `:227` |
| Export page size (exchanges + WS) | 2000 rows | `:192` |
| History query limit | default 200, clamp 1–2000 | `historyRepo.ts:261` |
| History view row cap (UI) | 500 | `HistoryView.tsx:41` |
| Site-map row cap | 100 000 (default and clamp) | `historyRepo.ts:234-235` |
| WS messages per exchange (default fetch) | 6000 | `wsRepo.ts:54` |
| WS frames captured per connection | 5000 (`WS_MAX_MESSAGES`) | `proxyServer.ts:62` |
| WS bytes captured per message | 64 KiB | `:63` |
| WS handshake buffer cap | 64 KiB (`MAX_HANDSHAKE_BYTES`) | `:65` |
| CA history cap | 50 entries | `session.ts:120` |
| Leaf certificate cache | 1024 entries (LRU) | `certificateAuthority.ts:161` |
| `ca.pem` file mode | `0o644` | `certificateAuthority.ts:208` |
| Revocation-marker / secret-store file modes | `0o600` | `:113`; `secretStore.ts:88`, `:106`; `electronSecretStore.ts:46` |
| Variation `ABSOLUTE_MAX` | 100 000 requests | `payloads.ts:32` |
| Variation `MAX_BASE_REQUEST_BYTES` | 2 MiB | `variationEngine.ts:41` |
| Variation `MAX_PAYLOAD_BYTES` | 64 KiB (list values only) | `:42` |
| Variation `MAX_POSITIONS` | 16 | `:43` |
| Variation `MAX_RESPONSE_RULES` | 20 markers, 20 extractors | `:44` |
| Variation `MAX_REGEX_LENGTH` | 512 chars | `:45` |
| Variation `MAX_ANALYSIS_BYTES` | 256 KiB | `:46` |
| Variation body capture | 256 KiB spill / 10 MiB cap (ignores project config) | `:460-462` |
| `SAFE_STRUCTURAL` payload count | **17** | `payloads.ts:12-30` |
| Scanner `MAX_SCAN_BODY_BYTES` | 1 MiB | `passiveScanner.ts:19` |
| Scanner non-textual body cutoff | 4096 bytes | `:21` |
| Sequencer `MAX_SAMPLES` | 100 000 | `sequencer.ts:15` |
| Sequencer `MAX_SAMPLE_BYTES` | 64 KiB | `:16` |
| Sequencer `MAX_TOTAL_BYTES` | 16 MiB | `:17` |
| Sequencer positional cap | 256 bytes | `:18` |
| Compare `MAX_LINES_FOR_LCS` | 5000 | `compare.ts:15` |
| Proof header-difference list cap | 20 | `proof.ts:121` |
| Surface ranking `limit` | default 25, clamp 1–100 | `surface.ts:321`, `:411` |
| Hunt memory `MAX_RECORDS` | 5000 (option clamped 100–100 000) | `huntMemory.ts:39`, `:135` |
| Hunt memory `MAX_LINE_BYTES` / `MAX_FILE_BYTES` / `MAX_NOTE_CHARS` | 8 KiB / 8 MiB / 600 | `:40-43` |
| Workspace bounds | 2000 entries / depth 8 / 256 KiB default read / 2 MiB max read / 500 files / 200 matches (search default 50) | `workspace.ts:33-38`, `:453-454` |
| MCP single string input cap | 2 000 000 chars | `mcp/tools.ts:34` |
| MCP single result cap | 100 000 chars | `mcp/protocol.ts:35` |
| Message viewer display cap | 4 MiB (`VIEW_MAX_BYTES`) | `session.ts:117` |
| Sensitivity scan window (body) | 8192 chars | `session.ts:626-629` |
| AI `maxActiveRequestsPerRun` | 50 (normalize cap 100 000) | `ai.ts:217`, `:269-275` |
| AI `MAX_ITERATIONS_PER_ROLE` / `MAX_ROUNDS` / `MAX_STEPS` / `MAX_RETAINED_RUNS` | 24 / 3 / 1000 / 20 | `orchestrator.ts:71`, `:53`, `:52`, `:72` |
| AI role output tokens | 32 000 / 64 000 (deep) | `orchestrator.ts:68-69` |
| Redaction decompression cap | 8 MiB | `redactor.ts:242` |
| Extension child heap | 256 MB | `host.ts:129` |
| Extension `vm` top-level timeout | 2000 ms | `subprocessRuntime.ts:91` |
| Extension host RPC timeout | 5000 ms | `host.ts:233` |
| Node requirement | `>=22.12.0` | `package.json:11` |

### 14.4 The 19 transforms

`src/engine/transforms/codec.ts:161-211`. Available in the Encoder/Decoder panel, over MCP
(`apply_transform`), and to the AI mesh.

| id | Label | Category | Implementation |
|---|---|---|---|
| `url.encode` | URL encode | encode | `encodeURIComponent` (`:27-29`) |
| `url.encode-all` | URL encode (all bytes) | encode | Percent-encodes **every** UTF-8 byte (`:34-36`) |
| `url.decode` | URL decode | decode | `decodeURIComponent` (`:30-32`); transforms "Throw on invalid input (callers surface the error)" (`:22`) |
| `base64.encode` | Base64 encode | encode | Node `Buffer` base64 (`:39-41`) |
| `base64.decode` | Base64 decode | decode | (`:42-44`) |
| `base64url.encode` | Base64URL encode | encode | Node `base64url` (`:45-47`) |
| `base64url.decode` | Base64URL decode | decode | (`:48-50`) |
| `hex.encode` | Hex encode | encode | (`:53-55`) |
| `hex.decode` | Hex decode | decode | Strips whitespace; **throws** on odd length or non-hex (`:56-62`) |
| `html.encode` | HTML entity encode | encode | Only `& < > " '` (`:65-74`) |
| `html.decode` | HTML entity decode | decode | **Single left-to-right pass** (`:82-102`) |
| `gzip.compress` | Gzip → Base64 | compress | Output is base64, not raw bytes (`:110-112`) |
| `gzip.decompress` | Base64 → Gunzip | compress | Input must be base64 (`:113-115`) |
| `hash.md5` | MD5 | hash | Hex digest of the UTF-8 bytes (`:105-107`) |
| `hash.sha1` | SHA-1 | hash | as above |
| `hash.sha256` | SHA-256 | hash | as above |
| `hash.sha512` | SHA-512 | hash | as above |
| `time.epoch-to-iso` | Epoch → ISO 8601 | inspect | ≤ 11 chars = seconds, longer = ms (`:118-124`) |
| `time.iso-to-epoch` | ISO 8601 → Epoch (ms) | inspect | `Date.parse`; throws if unparseable (`:125-129`) |

### 14.5 The 8 MCP tools

All read-only, all zero-traffic, all zero-disk. Registry order (`src/mcp/tools.ts:172-315`).

| Tool | Input | Result shape | Details |
|---|---|---|---|
| `inspect_jwt` | `{token}` | object, 5 fields | [10.5](#105-tool-reference) |
| `analyze_tokens` | `{samples[], encoding?}` | object, 20 fields | [10.5](#105-tool-reference), [7.4](#74-sequencer) |
| `list_transforms` | `{}` | array of 19 `{id,label,category}` | [14.4](#144-the-19-transforms) |
| `apply_transform` | `{id, input}` | `{id, output}` | [10.5](#105-tool-reference) |
| `diff_text` | `{a, b}` | array of `{type, text}` | [7.6](#76-compare) |
| `diff_json` | `{a, b}` | array of `{path, kind, left?, right?}` | [7.6](#76-compare) |
| `diff_bytes` | `{a_base64, b_base64}` | object, 5 fields | [7.6](#76-compare) |
| `evaluate_scope` | `{url, scope}` | object — 6 fields on a parseable URL, 3 on an unparseable one | [10.5](#105-tool-reference) |

### 14.6 The 30 AI mesh tools

`buildTools(session, grants)` — `ai/tools.ts:493-715`. `#` is the actual array order produced by the
builder: two fixed entries, then `...workspaceTools`, `...certificateTools`, `...analysisTools`,
`...proofTools` (`:514-517`), then the remainder inline. **Address specs by name, never by index** —
with both grants off, six entries disappear and every later index shifts.

| # | Tool | `effect` | `mutates` | `requestCost` | Grant | Line |
|---|---|---|---|---|---|---|
| 1 | `get_preflight` | read | false | — | always | 497 |
| 2 | `get_engagement_profile` | read | false | — | always | 506 |
| 3 | `list_workspace` | read | false | — | `workspaceAccess` | 188 |
| 4 | `read_workspace_file` | read | false | — | `workspaceAccess` | 201 |
| 5 | `propose_scope_from_workspace` | read | false | — | `workspaceAccess` | 220 |
| 6 | `search_workspace` | read | false | — | `workspaceAccess` | 229 |
| 7 | `get_ca_status` | read | false | — | always | 253 |
| 8 | `issue_ca` | **environment** | false | — | `allowCertOps` | 265 |
| 9 | `revoke_ca` | **environment** | false | — | `allowCertOps` | 274 |
| 10 | `inspect_jwt` | read | false | — | always | 406 |
| 11 | `analyze_tokens` | read | false | — | always | 415 |
| 12 | `diff_text` | read | false | — | always | 436 |
| 13 | `diff_json` | read | false | — | always | 445 |
| 14 | `list_transforms` | read | false | — | always | 454 |
| 15 | `apply_transform` | read | false | — | always | 463 |
| 16 | `rank_attack_surface` | read | false | — | always | 296 |
| 17 | `prove_finding` | read | false | — | always | 306 |
| 18 | `recall_prior_hunts` | read | false | — | always | 336 |
| 19 | `record_hunt_outcome` | **local-write** | false | — | always | 358 |
| 20 | `note_exchange` | **local-write** | false | — | always | 519 |
| 21 | `list_ws_messages` | read | false | — | always | 554 |
| 22 | `get_target_map` | read | false | — | always | 563 |
| 23 | `query_history` | read | false | — | always | 572 |
| 24 | `get_exchange_detail` | read | false | — | always | 581 |
| 25 | `list_findings` | read | false | — | always | 590 |
| 26 | `evaluate_scope` | read | false | — | always | 598 |
| 27 | `send_repeater` | **target-traffic** | **true** | `() => 1` | always | 611 / 634 |
| 28 | `create_variation_job` | **target-traffic** | **true** | `() => 0` | always | 684 / 690 |
| 29 | `run_variation_job` | **target-traffic** | **true** | job's `total ?? 1` | always | 694 / 701-702 |
| 30 | `get_variation_results` | read | false | — | always | 706 |

Totals: 30 `name:` entries — 23 `read`, 2 `local-write`, 2 `environment`, 3 `target-traffic`. There is
**no mesh `diff_bytes`**.

### 14.7 The 11 passive checks

Registration order (`checks.ts:497-509`). All version `1.0.0`. `README.md:145` records the same count.

| # | `module` | Fires when | Severity | Confidence |
|---|---|---|---|---|
| 1 | `security-headers` | Response present and status < 400 (`:27`). **HSTS:** scheme https and `Strict-Transport-Security` absent — fires on *any* content type (`:66-84`). **HTML-only** (`text/html` or `application/xhtml+xml`, `:19-22`, `:85-101`): missing `Content-Security-Policy`, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy` | HSTS `low` (`:70`); CSP `medium` (`:41`); XCTO `low` (`:48`); XFO `low` (`:54`); Referrer-Policy `info` (`:60`) | `firm` (`:71`, `:92`) |
| 2 | `insecure-cookies` | A `Set-Cookie` lacks `Secure` (https only, `:117`), `HttpOnly` (`:118`), or `SameSite=` (`:119`) — one finding per cookie | `medium` if `Secure` is among them, else `low` (`:124`) | `firm` (`:125`) |
| 3 | `cors` | `Access-Control-Allow-Origin` present (`:146-147`). Four **mutually exclusive** branches: `*` + credentials (`:156`); ACAO **reflecting the request `Origin`** + credentials (`:174`); `null` + credentials (`:196`); bare `*` (`:215`) | first three `high`, bare `*` `info` (`:160`, `:182`, `:202`, `:219`) | `firm` |
| 4 | `mixed-content` | https + HTML response (`:241`) whose body matches `(?:src\|href)\s*=\s*["']?(http:\/\/…)` (`:244`); up to 5 matches as evidence (`:245`) | `medium` (`:251`) | `firm` (`:252`) |
| 5 | `sensitive-in-url` | A query-parameter **name** matches `access_?token\|id_?token\|refresh_?token\|api[_-]?key\|apikey\|secret\|password\|passwd\|pwd\|auth\|session\|sig\|signature` (`:277-278`) | `medium` (`:284`) | `firm` (`:285`) |
| 6 | `cache-control` | Request carries `Authorization` **or** response sets a cookie (`:306-308`), and `Cache-Control` contains neither `no-store` nor `private` (`:310-311`) | `low` (`:316`) | `tentative` (`:317`) |
| 7 | `verbose-errors` | Response body matches a stack-trace marker set: `stack trace`, `stacktrace`, `Exception in`, `Traceback (most recent call last)`, `NullReferenceException`, a JS frame `at x(y:1:1)`, `SQLSTATE[`, `ORA-#####`, `Warning: fn() ` (`:340-341`) | `medium` (`:349`) | `firm` (`:350`) |
| 8 | `banner-disclosure` | `server`, `x-powered-by`, `x-aspnet-version`, or `x-generator` present **and containing a digit** — one finding per header (`:372-374`) | `info` (`:378`) | `firm` (`:379`) |
| 9 | `secrets-in-response` | Body matches an AWS access key (`AKIA`+16), a JWT, a `-----BEGIN … PRIVATE KEY-----` block, or a Google API key (`AIza`+35) (`:397-402`). The matched value is **never** placed in evidence — the excerpt reads `"<kind> pattern matched (value redacted)"` (`:414`) | `high` (`:409`) | `tentative` (`:410`) |
| 10 | `cleartext-credentials` | Scheme is `http` (`:426`) **and** the request carried `Authorization` or `Cookie` (`:429-431`) | `high` (`:436`) | `firm` (`:437`) |
| 11 | `reflected-input` | HTML or JSON response (`:457-459`) containing, verbatim, the value of a query parameter of length ≥ 4 (`:472-473`); capped at 5 findings per exchange (`:490`) | `info` (`:477`) | `tentative` (`:478`) |

`checks.ts:1-5` sets the policy for the module: conservative, reports only what is observable without
traffic.

### 14.8 IPC and event surface

The renderer gets exactly two capabilities from the preload bridge — `invoke(method, ...args)` and
`onEvent(handler)` (`src/preload/index.ts:10-23`). Everything the UI can do is one of the **90 names
in `INVOKE_METHODS`** (`src/shared/ipc.ts:74-167` — counted programmatically, 90 entries).
`registerIpc` throws `IPC registry drift — …` at startup if that allowlist and the main-process
`handlers` table diverge (`main/ipc.ts:311-325`, message `:318`), so the two can never drift silently.
Renderer wrappers are in `src/renderer/src/api.ts`.

**Seventeen event types** are pushed main → renderer over `tacnoc:event` (`main/ipc.ts:342-358`):

```
exchange            finding             intercept-request   intercept-response
intercept-pending   intercept-state     proxy-state         job-progress
job-done            scope-changed       emergency-stop      ws-message
project-open        mesh-step           mesh-progress       ca-changed
engagement-changed
```

Selected channel names cited elsewhere in this manual: `getTargetMap` (`:212`), `listFindings` /
`setFindingSuppressed` / `addSuppression` / `removeSuppression` / `listSuppressions` /
`scannerModules` (`:214-219`), `sendRepeater` (`:221`), `listCookies` / `clearCookies` (`:222-223`),
`saveRequest` / `listSavedRequests` (`:224-225`), `applyTransform` (`:227`), `listTransforms` (`:228`),
`inspectJwt` (`:229`), `diffText` / `diffJson` / `diffBytes` (`:230-232`), `analyzeTokenSamples`
(`:234`), variation lifecycle (`:237-243`), `emergencyStop` (`:244`), `listExtensions` /
`loadExampleExtension` (`shared/ipc.ts:155-156`), `setScope` (`:194`), `getPreflight` (`:263`),
`clearHistory` (`:210`), `window:usesCustomControls` (`:191`).

> There is **no evaluate-scope IPC channel** — the Scope panel has `setScope` only.
> There is **no `loadExtension` IPC channel.**
> **There are no keyboard shortcuts** anywhere in the renderer.

### 14.9 Environment variables

| Variable | Read at | Set by | Notes |
|---|---|---|---|
| `ELECTRON_RENDERER_URL` | `src/main/index.ts:94`, `:99` | electron-vite in `dev` — **never by this tree** | Decides `loadURL` vs `loadFile` and gates the `will-navigate` allowlist |
| `TACNOC_PACKAGE_DIR` | `test/e2e/packaged.spec.ts:35` | the operator | The **only environment variable this repo defines for its own build/test tooling**. Points the packaged E2E spec at a specific build |
| `PATH`, `SystemRoot`, `windir`, `TEMP`, `TMP`, `HOME`, `USERPROFILE`, `LANG`, `TZ` | `src/sdk/host.ts:34-47` | the OS | The allowlist copied into the scrubbed extension-host child environment, alongside `ELECTRON_RUN_AS_NODE: '1'` (`:32`) |
| `WINDOWS_CSC_LINK`, `WINDOWS_CSC_KEY_PASSWORD`, `APPLE_ID`, `APPLE_APP_SPECIFIC_PASSWORD`, `APPLE_TEAM_ID`, `RUNNER_OS` | `release.yml:53-72`, in shell | GitHub Actions secrets | Consumed in shell, not via `process.env` in JS. See [2.8](#28-the-release-pipeline-and-its-gates) |

> **Methodology note, because it cost a wrong claim once.** A grep for `process\.env\.` (with a
> trailing dot) misses bracket access such as `process.env['NAME']` and returns one hit where three
> exist. Any "this is the only X" claim built on a grep needs the loosest pattern that can still match.

### 14.10 File and directory map

```
GreyNOC Belcher/
├─ src/
│  ├─ main/          584 ln, 3 files — Electron main, IPC registry, ElectronSecretStore
│  ├─ preload/       contextBridge: invoke + onEvent only, emitted as .cjs
│  ├─ renderer/      5,505 ln, 23 files — React UI, 16 views
│  ├─ shared/        types shared across main/renderer/engine (model, scope, ai, ipc, …)
│  ├─ engine/        14,600 ln, 50 files — Electron-free:
│  │   ├─ proxy/     proxyServer, proxyUtil, interceptor, wsFrame
│  │   ├─ ca/        certificateAuthority, secretStore, installInstructions
│  │   ├─ scope/     scope.ts — the single evaluator
│  │   ├─ repeater/  repeater, rawHttp, cookieJar
│  │   ├─ variation/ variationEngine, payloads
│  │   ├─ scanner/   types, passiveScanner, checks
│  │   ├─ analysis/  sequencer, surface, proof, huntMemory
│  │   ├─ transforms/codec
│  │   ├─ compare/   compare
│  │   ├─ target/    siteMap
│  │   ├─ storage/   database, migrations, historyRepo, metaRepo, findingsRepo,
│  │   │             auditRepo, wsRepo, blobStore, bodyCollector
│  │   ├─ crypto/    contentCipher
│  │   ├─ project/   projectStore
│  │   ├─ engagement/preflight, identity, scopeProposal
│  │   ├─ workspace/ workspace.ts — the read gate
│  │   ├─ redaction/ redactor
│  │   ├─ logging/   logger (console sink only)
│  │   ├─ net/       httpClient
│  │   ├─ util/      rateLimit (TokenBucket, Semaphore)
│  │   └─ ai/        orchestrator, tools, prompts, provider, providers/anthropic
│  ├─ sdk/           808 ln, 3 files — api, host, subprocessRuntime
│  └─ mcp/           637 ln, 3 files — index, protocol, tools
├─ test/             8,179 ln; 28 *.test.ts + 7 e2e specs (10 tests)
├─ scripts/          checksums, generate-sbom, package-linux, package-windows,
│                    reseal-project-secrets (.mjs) + secret-helper.cjs — all outside every gate
├─ examples/extensions/header-hygiene/   the one bundled extension
├─ docs/             this manual + 9 focused docs + 6 ADRs
├─ .claude-plugin/plugin.json  ·  .mcp.json   the MCP plugin declaration
└─ out/  dist/  release/  sbom.json          build outputs (gitignored except sbom.json's absence)
```

---

## 15. Troubleshooting

Symptom → cause → fix. Grouped by where you were when it happened.

### 15.1 Capture and interception

| Symptom | Cause | Fix |
|---|---|---|
| Browser shows a certificate error; history is empty | The client does not trust the project CA. `tlsClientError` is an explicit no-op (`proxyServer.ts:164-166`) — no exchange, no error, no UI signal | Run the four `CA Certificate` steps. If already run: restart the browser; check whether it keeps its own store (Firefox/Tor); confirm the CA was not rotated since |
| HTTPS is passing through and nothing is captured at all, with no certificate error | The CA is **revoked** — CONNECTs become blind TCP relays that capture nothing (`:321-347`). The counter that tracks this is read by no code | `Engagement → Interception certificate → Issue new CA`, then reinstall it in the browser |
| Only `http://` traffic appears | The browser's HTTPS proxy is unset — without it no `CONNECT` is ever sent | Set **both** HTTP and HTTPS proxy to the listener address (`CertificateView.tsx:297-302`) |
| Chip says `HTTPS interception working` but nothing is being captured now | The check is a **lifetime count** over the whole project (`historyRepo.ts:219-224`), not live state | Verify on the wire: browse and watch HTTP History. Issuing a new CA does not reset the count |
| A WebSocket connection produces no history row at all | `Capture WebSocket frames` is off — the tunnel degrades to a raw pipe and no handshake exchange is recorded (`:855-859`, `:944`) | Enable it in `Settings → Capture & body limits`, then restart the proxy |
| WebSocket frames stop appearing mid-session while traffic continues | 5000-message-per-connection cap (`:62`, `:889`), or a frame-protocol violation set `broken` (`wsFrame.ts:56-80`). No UI signal either way | Compile-time constants; nothing to configure. Reconnect the socket to start a new capture |
| Large upload fails with `413` only while interception is on | An intercepted request body over `maxCapturedBytes` is answered `413` and **not forwarded** (`:440-458`) | Turn interception off for that request, or raise `Max captured / body (MB)` and restart the proxy |
| Connections reset under load, with no proxy error | `maxProxyConnections` (default 512) destroys the socket with no response (`:281-285`) | Raise it in Settings and restart the proxy |
| A proxied exchange never completes | The proxy has only an **inactivity** timeout; a slow-drip origin holds it open indefinitely (`:561`) | Use the Repeater, which has a hard wall-clock deadline (`httpClient.ts:78`) |
| Intercepted edit lost a header | A header line with no colon is **silently dropped** (`InterceptView.tsx:27-30`) | Check the colon; edits are re-parsed on every forward |
| Intercepted edit ignored the status you typed | An unparseable status line leaves the original status untouched — headers and body still apply (`:89`) | Match `HTTP/1.1 <code> <reason>` |
| Held messages vanished | Emergency stop and stopping the proxy both release as **drop**; only un-ticking the checkbox forwards | Know which control you pressed ([9.3](#93-intercept)) |
| Request smuggling probe never reaches the wire | `content-length` and `transfer-encoding` are stripped and Node recomputes framing (`proxyUtil.ts:19`, `:40`) | Not expressible in TACNOC. Use a different tool for CL.TE / TE.CL |

### 15.2 Scope and findings

| Symptom | Cause | Fix |
|---|---|---|
| A `*.host` rule matches nothing and nothing warns | `hostMatch` was left at the default `exact`, where `*` is literal (`scope.ts:48-51`) | Set match to `wildcard`, or use `subdomain` |
| `*.example.com` does not match `example.com` | Neither `*` nor `**` matches the apex | Add a second rule, or use `subdomain` |
| `*.example.com` does not match `a.b.example.com` | `*` is exactly one label; `**` is one or more | Use `**.example.com` |
| A rule created via MCP behaves differently from the same text typed in the UI | MCP infers `wildcard` from a `*` (`mcp/tools.ts:79-85`); the UI does not | Set `hostMatch` explicitly on both surfaces |
| Everything is out of scope after editing a project file by hand | A rule has `enabled` absent. `evaluateScope` requires it truthy; preflight and the mesh gate count `!== false` | Add `"enabled": true` to every rule |
| An exclude rule stopped protecting a path, with no error | Its regex is invalid and therefore matches nothing (`scope.ts:78`) | Test the regex; remember it is **unanchored** |
| An IPv6 rule works on one surface and not another | `targetFromUrl` yields a bracketed host, the proxy's `parseAuthority` strips brackets | Write rules for the form the surface you care about produces |
| History and Target Map disagree about scope | History stamps `in_scope` once at ingest; Target Map re-evaluates live | Both are correct. Scope edits are not retroactive |
| Findings from a host you never authorized | The passive scanner is not scope-filtered and a `Finding` carries no scope field | Check the linked exchange's scope before acting |
| Twenty copies of the same header finding | Dedupe is `(exchange_id, dedupe_key)` — there is no cross-exchange dedupe | Use `Suppress this type (rule)`. Note the finding is still written, just not announced |
| A finding you suppressed still appears | Host-scoped rules fail safe: with no host supplied the rule does not match | Suppress on `module` + `dedupeKey` instead |
| `secrets-in-response` missed an obvious secret | Bodies are truncated to 1 MiB, and non-textual bodies over 4096 bytes reach checks as an empty string | Inspect the exchange by hand |
| A CORS endpoint reports only one issue | The check is an if/else-if chain and reports the first matching branch only | Read the raw headers |
| `reflected-input` reported — is it XSS? | No. It is `info`/`tentative` and its own description says it does not test for injection | Prove it with a differential; do not report as-is |

### 15.3 Automation and the AI mesh

| Symptom | Cause | Fix |
|---|---|---|
| A target sees ~3× the rate you configured | Rate limiting is **per job**; three jobs at 8 rps deliver 24 rps | Run one job at a time, or divide the rate yourself |
| The Variation form ignored your Settings values | `Settings → Automation limits` is inert; the form hardcodes 4 / 8 / 500 / 20000 | Set pacing in the Variation form for every job |
| `Run` is enabled but throws `job <id> already <status>` | The button disables only on `running`; the engine requires `created` | Press **Prepare** to build a new job |
| Job creation refused | One of three layered checks: 0 requests, over `ABSOLUTE_MAX` (100,000), or over your per-job max | Narrow the payloads or raise the per-job limit deliberately |
| Requests counted as `skip` in results | Per-request scope re-check found the rendered **path** out of scope; audited as `request.skipped-out-of-scope` | Expected. Adjust scope or the payload |
| The job froze and pause/stop do nothing | A catastrophic response regex is running on the engine's event loop; the structural ReDoS check does not model every shape | Restart. Keep response regexes simple |
| Emergency stop did not stop the browser traffic | It does not stop the proxy | Toggle the Proxy chip |
| A mesh run refuses to start | One of: `enabled` false, `egressAcknowledged` false, no enabled include rule, no API key, empty objective, another run active | The thrown message names which |
| A mesh role produced nothing and the run continued | The model declined the turn — recorded as an error step plus a `mesh.refused` audit row; recon/planner fall back to the engine briefing | Check the Audit Log and the run steps |
| A mesh run reached the provider even though egress is off | `Test connection` is not gated by `enabled`/`egressAcknowledged` — it calls `countTokens` with `'ping'` | Expected; it sends no captured or project data |
| A role configured for `openai` behaved like Claude | There is no OpenAI provider; `AnthropicProvider` is constructed unconditionally | Use Anthropic model ids |
| Reasoning effort appears to have no effect | Model-capability lists are id-**prefix** matched and fail silently | Use a model id whose family prefix is in `ADAPTIVE_THINKING` (`anthropic.ts:53-62`) |
| `autonomy: "approve"` did not queue anything | It is inert — `mayCall` only branches on `'readonly'` | Use `readonly`, or supervise |

### 15.4 Projects, storage and secrets

| Symptom | Cause | Fix |
|---|---|---|
| "This project cannot be opened" naming a `userData` path | The project was sealed under a different app identity — usually a different **build** of the same app on the same machine | `node scripts/reseal-project-secrets.mjs <projectDir> <oldUserDataDir>` |
| A script opened the project fine, then every read threw `JSON.parse` errors | A headless caller got `FileSecretStore`, found no key, and opened the project **unencrypted** | Inject the right `SecretStore`, or work on a copy. **Check `ca.pem` — it may already have been overwritten** |
| Browsers stopped trusting the CA after a script touched the project | `loadOrCreate` regenerated and overwrote `ca.pem`, and nothing verifies that a loaded key matches a loaded certificate | Restore the project directory from backup, or issue a new CA and reinstall it |
| Clearing history also deleted every finding | `DELETE FROM exchanges` cascades to `findings` and `ws_messages` | There is no undo and no confirmation dialog. Export first |
| The project directory keeps growing after clearing history | Blobs are never deleted; there is no GC | Manual cleanup only, and only if you can prove which blobs are unreferenced |
| A re-imported project has thousands of blob files | Import uses a hardcoded 64 KiB inline/blob threshold, not your 5 MiB spill setting | Cosmetic; content is preserved |
| The imported project's CA is not trusted | Export does not carry the CA. Import generates a new one | Reinstall the new CA in the browser |
| Engagement profile / AI settings / CA history missing after import | Those three `project_meta` keys are not in the export document | Re-enter them. Engine config *is* carried |
| Two app windows corrupted a project | There is no lock, no `busy_timeout`, no single-instance guard | One writer per project directory, enforced by you |
| An older build opened a newer project without complaint | `applyMigrations` has no future-version guard | Do not downgrade across a schema bump |
| A folder copy of a project will not open on another machine | The safeStorage master key lives in `<userData>/Local State`, outside the folder | Use the export for machine-independent transfer |

### 15.5 Build, packaging and release

| Symptom | Cause | Fix |
|---|---|---|
| `format:check` fails on every file on a Windows checkout | CRLF checkout against `endOfLine: lf` | Ensure `.gitattributes` (`* text=auto eol=lf`) is present and re-checkout |
| Build fails on a single `any` | `--max-warnings 0` with `no-explicit-any: 'warn'` | Type it, or change the rule deliberately |
| `npm run test:e2e` fails on a missing `out/main/index.js` | Nine of ten specs launch the dev bundle | `npm run build` first |
| The packaged E2E test "passed" but you never packaged | It searches `$TACNOC_PACKAGE_DIR`, then `dist/`, then `release/`, and silently uses the first hit | `npm run dist:win` (which wipes `dist/`) or set `TACNOC_PACKAGE_DIR` |
| The Linux tar.gz disappeared after packaging Windows | `dist:win` deletes all of `dist/` first, and rewrites the manifest without it | Build Windows **first**, Linux second |
| `./tacnoc: No such file or directory` after extracting the Linux archive | The executable is `greynoc-tacnoc`; `electron-builder.yml:71` still says `./tacnoc` | Run `./greynoc-tacnoc` |
| AppImage build dies with `EPERM` on Windows | AppImage creates symlinks Windows refuses without Developer Mode/elevation | Build `tar.gz` (cross-builds fine) or use a Linux host |
| `package.json` lost its `scripts` and `devDependencies` after packaging | electron-builder rewrote it; only `dist:win`/`dist:linux` snapshot and restore it | Restore from git. Prefer the per-OS scripts over bare `npm run dist` |
| macOS release leg fails with `<projectDir> not a file` | An unset GitHub secret is the empty string, and electron-builder reads `CSC_LINK` as a path | Keep the per-OS `if [ -n … ]` shell guards in `release.yml:61-72` |
| No `SHA256SUMS-linux.txt` after a cross-build | The `<os>` names the **build host**, not the target | The Linux archive is listed inside `SHA256SUMS-windows.txt` |
| Two builds of the same commit have different hashes | Builds are not bit-reproducible — electron-builder embeds build-time metadata | A hash identifies one build, not one commit |
| The SBOM disagrees with `package.json` | It is regenerated only by `npm run sbom`, and deliberately carries no timestamp | Run `npm run sbom` at cut time; check `metadata.component.version` |
| The MCP client cannot spawn the server | `out/` is gitignored; a fresh clone has no build | `npm run build:mcp` |
| `build:mcp` breaks though CI was green | It never runs in CI, and typecheck uses `Bundler` resolution while emission uses `NodeNext` | Run `build:mcp` locally before tagging |

### 15.6 MCP and extensions

| Symptom | Cause | Fix |
|---|---|---|
| `error: unknown transform: base64-decode` | Transform ids use dots | `base64.decode` |
| `analyze_tokens` gave a confident but wrong answer | An unrecognised `encoding` silently falls back to `text` | Spell it `hex`, `base64`, `base64url` exactly |
| `diff_bytes` returned numbers for input that was not base64 | No validation; Node's decoder skips invalid characters | Validate your base64 first |
| `diff_text` returned the entire body | It returns every line, including `equal` ones, and truncates at 100k chars | Slice before diffing |
| A diff of two large responses is useless | Above 5,000 lines the LCS is skipped, with no marker in the output | Slice below 5,000 lines |
| Code reading `result.target` from `evaluate_scope` crashed | An unparseable URL returns only three keys | Check `inScope`/`reason` first |
| `TypeError: tacnoc.registerX is not a function` | The permission was not granted; ungranted methods are **absent** | Guard every registration with `if (tacnoc.registerX)` |
| `setTimeout is not defined` inside an extension | Node globals are not in the `vm` context | No timers, `Buffer`, `URL`, `TextEncoder`/`Decoder`, `fetch`, `structuredClone`, `crypto`, `atob`/`btoa`, `AbortController` |
| `console.debug is not a function` | The shim defines only `log`, `warn`, `error` | Use those three |
| `EvalError: Code generation from strings disallowed` | `codeGeneration: {strings:false, wasm:false}` | Do not use `eval` / `new Function` |
| Extension loaded, then every scan times out | A long or infinite `activate()` — it runs **outside** the 2 s `vm` timeout | Fix `activate`; restart the app |
| All extensions stopped working at once | The single child crashed; the host fails closed and does not re-fork | Restart the app |
| `TypeError` inside `host.load()` before any RPC | The manifest has no `permissions` array | Add one; the child's `|| []` fallback never runs |
| A `createFinding` finding never appears | Missing/unknown `exchangeId` violates the FK, and the throw is caught and logged at **warn** to main-process stdout; or no project is open | Always set `exchangeId` (from `event.id` in an `onTraffic` handler) |
| An extension finding ignores a host-scoped suppression rule | `createFinding` findings are upserted without the host | Prefer a passive check when you want normal suppression semantics |
| Redaction disappeared inside an extension check | `ctx.redactor` is a no-op shim typed as a real `Redactor` | Do not rely on it for anything you emit |

---

## 16. Unverified, absent, and contradictory

Marked plainly so you can tell which half of this manual to trust.

### 16.1 Verified absences

Each searched for and not found. Their consequences are already stated in the relevant sections.

- No `PRAGMA busy_timeout` anywhere under `src/`, `test/`, `scripts/` or `docs/`.
- No `app.requestSingleInstanceLock()` or single-instance guard anywhere under `src/`.
- No lock file, advisory lock, or open-project registry.
- No blob garbage collector, prune, vacuum, orphan sweep or delete path in the storage layer.
- No check that a loaded CA private key matches the loaded CA certificate (`certificateAuthority.ts`
  contains `publicKey`/`verify` only at certificate-generation sites `:71`, `:320`, `:378`).
- No guard against opening a database whose `user_version` exceeds `CURRENT_SCHEMA_VERSION`.
- No npm script wrapping `scripts/reseal-project-secrets.mjs`, and no documentation of it outside
  `CHANGELOG.md:361` and the script's own header.
- No backup procedure documented beyond the phrase "for sharing/backup"
  (`docs/project-format.md:4`). [4.11](#411-backup-and-handling) is derived and labelled as such.
- No report-export, sanitized-report or findings-export code path anywhere in `src/`.
- No `Send to Variation` or `Send to Sequencer` handoff — `seedRepeater` is the only seed in the tree.
- No evaluate-scope IPC channel; no `loadExtension` IPC channel; no extension approval UI; no
  extension-related MCP tool; no manifest schema validation beyond the duplicate-id check.
- No host method that sends the child's `invokeAction` message; no caller of
  `ExtensionHost.renderTab()` or `getContextMenuActions()`; no read of `manifest.sdkVersion`.
- No file log sink or in-app log viewer; no validation of `evidence[].location`.
- No re-fork or recovery path after an unexpected extension-host child exit
  (`host.ts:164-166` states it is future work).
- No keyboard shortcuts in the renderer; no `localStorage`/`sessionStorage` use.
- No OpenAI provider file; no environment-variable path for the AI API key in TACNOC's own code.
- No per-payload egress audit record; no sanitizer between a captured response body and the model
  context.
- No rate limiter anywhere in `src/engine/repeater/`.
- No consumer anywhere in `src/` or `test/` for `ProxyServer.passthroughTunnels`.
- No config key, setting or UI control for `WS_MAX_MESSAGES`, `WS_MAX_MESSAGE_BYTES` or
  `MAX_HANDSHAKE_BYTES` outside `proxyServer.ts`.
- No `build/` directory for electron-builder's `buildResources`, and nothing documenting what it falls
  back to for icons in its absence.
- No `bin` key in `package.json` — no CLI.

### 16.2 Claims this manual could not verify

Stated here rather than presented as fact.

- **Whether `npm run typecheck` catches a NodeNext-only module-resolution break in `src/mcp`.** The
  root tsconfig does include `src/**/*.ts` but uses `moduleResolution: "Bundler"` while the emit
  config uses `NodeNext`. The tree states the two differ and why, but never what the difference does or
  does not catch.
- **electron-builder's default macOS `artifactName` pattern.** No `artifactName` is configured under
  `mac:` and the default is not written down anywhere in the repo.
- **The unit-test count of 368.** Documented at `RELEASE.md:180` and `README.md:120`; not measured by
  this pass, which ran no builds or test suites. The 28 test-file and 10 Playwright-test counts *are*
  measured by enumerating the tree.
- **What `npm run dev` writes to disk.** Determining it requires running the app.
- **Which of `artifactBuildCompleted: null` and the comment above it (`electron-builder.yml:74-75`) was
  intended.** Nothing in the tree resolves the contradiction — do not rely on that hook firing.
- **Whether the `./tacnoc` line at `electron-builder.yml:71` is a deliberate exception or an
  un-updated comment.** The script and `RELEASE.md` both say `greynoc-tacnoc`; the YAML was evidently
  missed, but the tree does not say so.
- **Whether `SECURITY.md:57`'s "production dependencies" wording ever matched an earlier `audit`
  script.** Git history was not consulted; this pass read the working tree only.
- **The exact set of files `npm run start` (electron-vite preview) reads or writes.**
- **That `Http2SecureServer` genuinely lacks `closeAllConnections()`** — asserted only by the code
  comment at `proxyServer.ts:185-190`; no runtime check was performed.
- **How often real clients omit SNI**, which decides how often the default `localhost` leaf is served.
  Not a question the tree answers.
- **The rendered MCP stderr startup banner.** The format string, version and tool order are read from
  the tree; the banner was not re-observed by spawning the built binary.
- **The MCP `0.0.0-dev` version fallback.** Code-read only; not exercised.
- **`enabledPlugins`, `${CLAUDE_PLUGIN_ROOT}` expansion, and plugin-root auto-discovery.** All asserted
  by `docs/mcp-server.md` and `.mcp.json`'s own comments; no code in this repo performs or validates
  them.
- **That the Electron app never starts or supervises the MCP server.** Stated on the basis of a
  negative grep plus the absence of any spawn of `out/mcpsrv`.
- **The `evaluate_scope` row "`example.com` vs `*.example.com` → false"** — a code-read of the generated
  regex; the other rows in that table were measured live.
- **That a `createFinding` with an empty or unknown `exchangeId` is rejected by the foreign key.**
  Reasoned from `migrations.ts:93` plus the `PRAGMA` at `database.ts:39`/`:47`; not executed. The test
  suite uses a plain collector sink with no project, so the constraint is never exercised there.
- **Windows NTFS-ACL behaviour of Node's `{ mode: 0o600 }`.** General Node knowledge, not a statement in
  this tree.
- **`decodeURIComponent` throwing on a malformed `%` sequence.** True of the JavaScript runtime, but
  the tree says only that transforms "Throw on invalid input" (`codec.ts:22`).
- **The `SIGNALS` vocabularies in `surface.ts:43-260`** were not read entry by entry — the block bounds
  and the scoring arithmetic that consumes it were.
- **The AI mesh handler bodies** for `rank_attack_surface`, `prove_finding`, `recall_prior_hunts`,
  `record_hunt_outcome`, `get_target_map`, `list_findings` and `evaluate_scope` were not read
  line-by-line; [14.6](#146-the-30-ai-mesh-tools) cites their registration lines.
- **What the Anthropic SDK does internally when `apiKey` is omitted** — unreachable here, because
  TACNOC always passes it explicitly.

### 16.3 In-tree statements that are wrong

Each of these is in the repository today and would cost you time or a wrong belief.

| Statement | Location | Reality |
|---|---|---|
| "`npm run audit` runs `npm audit` on production dependencies" | `SECURITY.md:57` | `package.json:27` has no `--omit`; `RELEASE.md:13-15` and `ci.yml:81-84` deliberately require the full tree because Electron is a devDependency that ships |
| "extract and run `./tacnoc`" | `electron-builder.yml:71` | The executable is `greynoc-tacnoc`; `package-linux.mjs:95-98` exists to correct exactly this |
| "Emit a per-build metadata file listing produced artifacts." above `artifactBuildCompleted: null` | `electron-builder.yml:74-75` | The value disables the hook |
| Client socket "wrapped in a `tls.TLSSocket`", decrypted stream "handed to an inner `http.Server`" | `ARCHITECTURE.md:80-83` | `http2.createSecureServer` with `allowHTTP1` (`proxyServer.ts:138`, `:141`) |
| Blobs "stored by SHA-256 of their PLAINTEXT bytes"; layout `<root>/<aa>/<bb>/<sha256-of-plaintext>` | `blobStore.ts:4`, `:10`; `docs/project-format.md:12` | HMAC-SHA256 under a DEK-derived subkey in any encrypted project (`contentCipher.ts:27`, `:36-38`). `blobStore.ts:46-47` and `docs/project-format.md:20-24` are correct |
| Reseal transfer described as "stdout -> parent -> stdin" | `scripts/secret-helper.cjs:10`, `:14-15` | The same file (`:42-43`) says stdin does not work on Electron's Windows binary; a one-shot loopback socket (`:39-58`) is what runs |
| `variation_jobs` listed as a live table | `docs/project-format.md:40` | The identifier appears only in the `CREATE TABLE` at `migrations.ts:133`; nothing reads or writes it |
| Redaction masks secrets "in logs, findings evidence, and **exports**" | `SettingsView.tsx:229-232`; `redactor.ts:5-6` | `ProjectStore.export()` never constructs or calls a `Redactor` |
| "Use the sanitized report export when sharing findings externally" / "Prefer sanitized report export" | `docs/project-format.md:79`; `SECURITY.md:44` | No such feature exists anywhere in `src/`; `capability-matrix.md:44-45` lists Reporting as planned |
| `inspect_jwt` reports "expiry state" | `src/mcp/tools.ts:177` | `JwtInspection` has no expiry field; `exp` is passed through inside `payload` |
| `diff_bytes` returns "common prefix and suffix length" | `src/mcp/tools.ts:266`; `docs/mcp-server.md:22` | Five fields, neither of them a prefix or suffix measure |
| `ByteDiff.differingBytes` counts differences "within the overlapping region" | `compare.ts:135` | The implementation adds the absolute length delta on top (`:155`) |
| `diff_text` returns "the changed lines with their kind" | `src/mcp/tools.ts:244` | It returns every line including `equal` ones, and the field is `type`, not `kind` |
| "the user approves them" (extension permissions) | `api.ts:4-7`; `ExtensionsView.tsx:37` | No approval UI exists; the shipped caller grants the manifest's own list |
| Five "host getters" including `drainCreatedFindings` and `getScannerChecks` | `docs/extension-sdk.md:125-126` | Neither symbol exists; the real method is `getCheckModules` |
| "Passive checks, transforms, tab renders and context-menu actions are invoked over an async RPC bridge" | `adr/0006:36-38` | Context-menu actions have no sender; tab renders have a sender with no caller |
| Extensions rated "Implemented" | `capability-matrix.md:23` | Fair for the engine, overstates the product surface (two dead permissions, no loader UI, no approval UI) |
| "scope is gated in code, rate limits are real, the audit log is written on every request" | `prompts.ts:13` | In the file's own header comment, not in the `PREAMBLE` a model sees — and true for Variation, not for `send_repeater` |
| "immutable automation audit" | `capability-matrix.md:26` | Append-only by API; plaintext SQLite columns in a directory the operator owns |
| Export format tag `greynoc-belcher-project` | `projectStore.ts:217` | Correct, but intentionally stale relative to the product name — tooling matching on "TACNOC" will miss it |

---

## Appendix A: Documentation map

| Document | What it is for | Relationship to this manual |
|---|---|---|
| [`../README.md`](../README.md) | Product overview, quick start, capability claims | Does not mention MCP at all; several "not implemented" lists are accurate |
| [`../ARCHITECTURE.md`](../ARCHITECTURE.md) | Module layout and data flow | Accurate except the TLS-interception object (§16.3) |
| [`../SECURITY.md`](../SECURITY.md) | Security posture, reporting, handling rules | `:57` and `:44` are stale (§16.3) |
| [`../THREAT_MODEL.md`](../THREAT_MODEL.md) | Assets, boundaries, residual risks | The authority for what is and is not a defended boundary |
| [`../RELEASE.md`](../RELEASE.md) | The release procedure and its recorded failures | The authority for packaging order and signing |
| [`../CONTRIBUTING.md`](../CONTRIBUTING.md) | PR workflow and the quality gate | — |
| [`../CHANGELOG.md`](../CHANGELOG.md) | Version history, including the rename and the identity pin | Source for several "why" explanations |
| [`authorization-and-scope.md`](authorization-and-scope.md) | Operator-facing scope semantics | [5](#5-scope-and-authorization) documents the code behind it |
| [`capability-matrix.md`](capability-matrix.md) | What is built, partial, and planned | Cited throughout for verified absences |
| [`certificate-management.md`](certificate-management.md) | CA internals and browser trust stores | [6.5](#65-the-project-ca)–[6.8](#68-how-interception-is-verified) |
| [`engagement-and-hunting.md`](engagement-and-hunting.md) | Preflight, proof gate, hunt memory, surface ranking | [5.8](#58-preflight), [7.8](#78-analysis-surface-ranking-proof-hunt-memory) |
| [`extension-sdk.md`](extension-sdk.md) | The isolation model | Accurate on isolation; [12](#12-the-extension-sdk) covers what it omits |
| [`mcp-server.md`](mcp-server.md) | MCP registration and the add-a-tool rules | [10](#10-the-mcp-server) |
| [`project-format.md`](project-format.md) | On-disk layout and the export document | [4](#4-projects-and-storage); two stale lines noted in §16.3 |
| [`testing.md`](testing.md) | Test layers and the offline guarantee | [2.10](#210-tests) |
| [`PLAN.md`](PLAN.md) | Roadmap | — |
| [`adr/`](adr/) | Six architecture decision records | 0003 (SQLite WASM) and 0006 (subprocess extension host) are load-bearing here |

## Appendix B: Audit action catalogue

Complete list, from a grep of `action:` across `src/` including ternaries. Written by
`AuditRepo.append` into `audit_log(id, ts, actor, action, target, detail, job_id)`
(`migrations.ts:109-120`); `detail` is JSON text and both `detail` and `target` are redacted on write
with a hardcoded all-on redactor (`auditRepo.ts:11-15`, `:22`, `:30`).

| Action | Actor | Site |
|---|---|---|
| `job.create` | `variation-engine` | `variationEngine.ts:181` |
| `job.pause` / `job.resume` / `job.stop` | `user` | `:205`, `:215`, `:223` |
| `emergency-stop` | `user` | `:232` |
| `job.start` | `variation-engine` | `:253` |
| `job.complete` / `job.stopped` | `variation-engine` | `:289` (ternary `:292`) |
| `request.skipped-out-of-scope` | `variation-engine` | `:357` |
| `mesh.start` | `ai-mesh` | `orchestrator.ts:198` |
| `mesh.refused` | `ai-mesh:<role>` | `:485` |
| `mesh.request` | `ai-mesh:<role>` | `:540` |
| `mesh.done` / `mesh.stopped` (template `` `mesh.${status}` ``) | `ai-mesh` | `:604` |
| `mesh.error` | `ai-mesh` | `:626` |
| `ca.rotated` / `ca.revoked` | `user` or `ai-mesh` | `session.ts:490`, `:512` |
| `engagement.profile-updated` | `user` | `:774` |
| `proof.confirmed` / `proof.refuted` / `proof.inconclusive` | `ai-mesh` | `:1035` |
| `project.adopted-folder` / `project.opened-folder` | `user` | `:1230` |
| `hunt-memory.cleared` | `user` | `:1270` |
| `ai.egress-enabled` / `ai.egress-disabled` | `user` | `:1374` |

`mesh.<status>` can render as `planning`, `running`, `paused`, `done`, `error` or `stopped`
(`shared/ai.ts:120`), though only terminal statuses are written at `:604`.

Not audited: any Repeater send, any proxied request, any interception forward/drop/edit,
`note_exchange`, `record_hunt_outcome`, and `create_variation_job` as a `mesh.request` row. See
[13.6](#136-the-audit-log).

## Appendix C: Verification method

This manual was assembled from nine independent source-mining passes over the v0.6.1 working tree on
2026-09-15. Rules applied:

1. **Nothing was written that was not read out of the tree.** Every command, flag, path, key, symbol,
   default, label and limit carries a `file:line` citation or is quoted exactly.
2. **Absence is a result.** Where something was searched for and not found, it is recorded as such —
   [16.1](#161-verified-absences) — rather than omitted or softened.
3. **Marketing phrasing in `README.md` was not copied forward.** Claims were traced to the code that
   implements them; where the code does less, the difference is stated.
4. **Where a repo document and the code disagree, the code wins and the disagreement is named** —
   [16.3](#163-in-tree-statements-that-are-wrong).
5. **No network traffic was generated.** The proxy was not started, the app was not launched, no
   request was sent. `npm install`, `npm run dev` and every build were deliberately not run — the tree
   is an operator working copy.
6. **What was executed:** read-only inspection (file reads, greps, directory enumeration), a
   standalone Node script reconstructing the extension `vm` context from
   `subprocessRuntime.ts:76-90` to probe which globals exist, offline evaluation of `globToRegExp` and
   `targetFromUrl` to produce the scope-matching tables, and calls to the already-registered
   `mcp__tacnoc__*` tools (which are offline and traffic-free by construction) to capture the worked
   examples in [10.5](#105-tool-reference).
7. **Counts were re-derived, not remembered.** `INVOKE_METHODS` is 90 entries, `SAFE_STRUCTURAL` is 17
   values, the transform registry is 19, the mesh registry is 30, the passive checks are 11, the MCP
   tools are 8, the test files are 28 and the Playwright tests are 10 — each parsed or enumerated
   rather than quoted from prose.

Citations drift with the code. When one does not match, re-read the file; do not assume the behaviour
changed.




