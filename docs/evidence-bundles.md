# Evidence bundles and the agent handoff

An evidence bundle is everything the project holds about **one target host**,
written as a ZIP a recipient can open with no tooling and read with no context:
the captured exchanges, the passive findings, the audit rows, the scope that was
in force, and a handoff brief for whoever picks the work up next — a triager, a
colleague, or an AI agent.

It is exported from the **Targets** view, where you select the origin. The
diagnostic log is exported separately from **Engagement → Diagnostics**.

## What is in a bundle

| Path | Contents |
|---|---|
| `README.md` | Orientation, and whether this bundle is redacted or raw. |
| `HANDOFF.md` | The state of play and the rules that bind anyone continuing. |
| `handoff.json` | The same facts, for a program or an agent to parse. |
| `FINDINGS.md`, `findings.json` | Passive findings for this host, highest severity first. |
| `exchanges/NNNN-METHOD-path.http` | Each captured exchange as request/response text, newest first. |
| `engagement.json` | Program, authorization reference, user-agent policy, and the scope rules. |
| `audit.json` | Audited actions whose target resolves to this host. |
| `logs/tacnoc.log.jsonl` | The session's structured log tail (optional). |
| `manifest.json` | SHA-256 and byte length of every other file. |

The bundle's own SHA-256 is reported when it is written. `manifest.json` cannot
hash itself, so that figure is the only integrity check covering the whole
archive — and it only means anything if the recipient gets it over a channel
other than the archive.

## Redaction

**Bundles are redacted by default.** Headers, bodies and URLs pass through the
same `Redactor` that protects logs and findings: `Authorization`, `Cookie`,
`Set-Cookie`, `X-API-Key` and friends are masked, sensitive query parameters
(`access_token`, `code`, `session`, …) are masked in URLs, and secret-shaped
strings in bodies (JWTs, PEM blocks, cloud keys, `password=`) are replaced with
`[REDACTED]`.

The project keeps captured traffic verbatim — that is what a proxy is for. A
bundle is a *derived* artifact that gets mailed to a triager, attached to a
ticket, or pasted into a model, and `SECURITY.md` already draws that line for
every other derived artifact.

Ticking **raw captures** turns redaction off. Do it deliberately, for a triager
who needs the exact bytes:

- the file is named `…-RAW.zip` and the save dialog says so;
- `README.md`, `HANDOFF.md` and `manifest.json` all announce it;
- the export is written to the audit log with `redacted: false`.

Treat a raw bundle as a secret: it contains live session cookies, bearer tokens
and whatever personal data was in the traffic.

## What is never in a bundle

No CA private key, no project data-encryption key, no secret store, no provider
API key, and no database file. The builder is handed exchanges, findings and
audit rows and has no route to any of those. A test asserts the absence by
filename pattern, and the CA private key never leaves the OS secure store at all
(see `THREAT_MODEL.md`).

## Exact host matching

`HistoryRepo`'s host filter is `LIKE '%host%'`. A bundle built on that alone
would match `notacme-corp.test.evil.example` when you asked for
`acme-corp.test` — and ship one program's traffic to another program's triager.

The history filter is therefore used only to narrow the scan; every row is then
matched on an exact, normalized host, and the bundle builder re-checks
independently. `evidenceBundle.test.ts` tests this first, because it is the
worst thing this feature could plausibly do.

## The handoff

`HANDOFF.md` and `handoff.json` are assembled from the project by pure
functions. **No model writes any of it**, which is the property that matters: a
handoff cannot claim a finding the scanner did not produce, an endpoint that was
never captured, or an authorization that is not in the engagement profile.

It contains the authorization (program, platform, handle, reference), the scope
rules the engine enforces, whether the target is in scope *right now*, the
endpoint map, the findings with a pointer to the exchange file that evidences
each, what the audit log says has already been done, open questions derived from
the evidence, the verbatim engine briefing, and a suggested starting objective.

### A handoff is not an authorization

The scope block is there so an agent can see what the gate will allow and stop
early when the answer is "nothing". It is reported, never granted. The
fail-closed gate in `src/engine/scope/scope.ts` remains the only thing that
decides whether a request leaves, and no text in a handoff widens it.

Two stop conditions are written at the top of the constraints, ahead of
everything else:

- **no enabled include rule** — the gate would refuse every request, so nothing
  should be tested at all;
- **this target is not in scope** — evidence captured through the proxy does not
  imply authorization now.

The rest of the constraints are the rules of engagement: least-impact and
read-only where possible, no fabrication, minimal proof, respect the request
budget (availability impact and denial-of-wallet are real harm), coordinated
disclosure only.

## Handing a target to the mesh

**Targets → Hand to mesh** starts an AI mesh run on the selected host, seeded
with that host's handoff as the objective.

It goes through `startMeshRun`, deliberately, so every gate a manual run passes
applies unchanged:

- the fail-closed scope check (and the handoff refuses earlier, with a clearer
  message, if the target is out of scope);
- the provider API key;
- the **egress acknowledgement** — running the mesh sends captured traffic to
  the model provider.

A handoff that bypassed those would be a way to start an unacknowledged run
under another name. The hand-off is recorded in the audit log as
`evidence.handoff-to-mesh` with the run id.

## Logs

There is **no log file on disk**. `Logger`'s only sink was the console, which in
a packaged Electron app goes somewhere no operator can reach, so the session now
also keeps a bounded in-memory tail (`LogBuffer`, 5000 records, oldest dropped).

A ring buffer rather than a file is deliberate: a log file would be a second
copy of redacted-but-still-sensitive engagement data with its own lifetime, its
own permissions and nothing that ever deletes it — it would outlive the project
it describes. The buffer dies with the process.

Records are redacted by `Logger` *before* they reach any sink, so the buffer
holds redacted records, not raw ones. An export says how many records it
contains and how many older ones had already been dropped, so a tail is never
mistaken for a complete log.

## The archive format

The ZIP writer is ours (`src/engine/evidence/zip.ts`): PKZIP APPNOTE 6.3, store
and deflate, UTF-8 names, no ZIP64, no encryption. Nothing in the runtime
dependency tree writes archives, and taking a dependency for two dozen lines of
header layout is a worse trade than owning them — this is a container format,
not a primitive, and the compression itself is `node:zlib`.

Every bundle is **read back and CRC-checked before the app reports success**, so
an archive that cannot be opened fails here rather than on a triager's desk. The
tests additionally extract bundles with an extractor this project did not write
(`Expand-Archive` on Windows, `unzip` elsewhere).
