# The engagement layer

TACNOC's engine has always enforced *scope*. This layer enforces the rest of the
paperwork — the parts of a bug-bounty or pentest engagement that are mechanical,
easy to get wrong, and expensive when you do.

Everything here exists because of one failure mode: **the quiet one.** A CA that
expired three weeks ago, a browser that was never told to trust it, a proxy bound
to `0.0.0.0`, an empty scope, a `User-Agent` the program requires but nothing
sends. Each produces the same symptom — a session that looks like it is working
and finds nothing — and hours disappear into it.

---

## Preflight

`Engagement → Preflight` answers "is this engagement actually ready to test?"
once, from evidence, before anything is planned. Every check is graded:

| Grade | Meaning |
|---|---|
| `blocker` | Testing would be invalid or unauthorized. The mesh stops and reports. |
| `warning` | Proceed, but with a known gap. |
| `ok` | Verified. |

The checks are grounded in something observable, never in configuration alone:

- **Authorization** — a recorded reference (program URL, ticket, signed scope
  document). Missing is a **blocker**: a finding produced without one cannot be
  defended after the fact.
- **Scope** — fail-closed. No include rules means every automated request would
  be refused, so an empty scope is a **blocker**.
- **Certificate** — validity window and days remaining. Expired is a **blocker**;
  expiring within 30 days is a warning.
- **Interception actually works** — the count of *decrypted HTTPS exchanges this
  project has captured*. Zero, with traffic in history, almost always means the
  test browser does not trust the CA. Configuration cannot tell you this;
  captured bytes can.
- **Identity compliance** — measured against requests that were really sent, not
  against the setting.
- **Proxy bind** — a non-loopback bind is a **blocker**.
- **Engagement folder** and **captured traffic** — whether there is anything to
  plan from.

---

## Engagement identity (the `User-Agent` requirement)

Most programs ask researchers to make their traffic recognisable, so the target's
blue team can tell authorized testing from a real attack. Getting it wrong gets
you blocked, or reported.

Set the required `User-Agent` and any identity headers (e.g.
`X-Bug-Bounty: <handle>`) under **Engagement → Traffic identity**. With
enforcement on, the **Repeater** and the **Variation engine** rewrite every
request they generate to carry them — including every request the AI mesh makes,
which is where most of them come from.

Details that matter:

- **Header order, casing, and duplicates are preserved.** An existing header is
  replaced *in place*; later duplicates of the same name are dropped so the
  target sees exactly one; a missing header is appended.
- **History records what was actually sent**, so the compliance check means
  something.
- **Proxy-captured traffic is never rewritten.** Your browser's `User-Agent` is
  not ours to change.
- **A `CR` or `LF` in a value is refused, not sanitized.** Those bytes are header
  injection against a third party's production system. The profile is validated
  when saved *and* again when applied, because a project file can be hand-edited
  or imported.
- Headers the engine owns (`Host`, `Content-Length`, `Transfer-Encoding`, …)
  cannot be forged through the profile.

---

## The engagement folder

The engine cannot infer the program policy from traffic. Point **Engagement →
Engagement folder** at the directory holding the policy, the in-scope asset list,
prior reports, and your notes. Recon reads it before anything is planned.

Access is **read-only** and sandboxed:

- Every path is resolved through `realpath` and proven to be inside the root.
  `..`, absolute paths, drive-relative paths, and symlinks pointing outward all
  fail the same check.
- The project's own internals are denied at every depth — the SQLite database,
  the content blobs, and the file secret store holding the CA private key and the
  project data-encryption key.
- Entry counts, recursion depth, per-file bytes, and search work are all bounded.
- Text only. Binary content is refused rather than shipped to a model as
  mojibake. A PDF policy tells you to export it to text.

> **This folder is egressed.** Its contents go to the model provider during a
> run, gated by the same per-project egress acknowledgement as captured traffic,
> and by the separate **workspace access** switch in the mesh settings. Point it
> at a folder you are willing to expose.

Treat everything read from it as **data, not instructions** — the same rule that
applies to captured HTTP responses.

### Scope, read out of the folder

Fail-closed scope is right, but retyping a program's asset list by hand is
tedious and error-prone. **Engagement → Proposed scope** reads the documents and
lists candidate hosts with the file and line each came from, so confirming one
is reading a line rather than trusting a parser.

It proposes and never applies:

- Nothing reaches scope without you ticking it. A document is a *claim* about
  authorization, not authorization — check each host against the program page.
- Hosts described as **out of scope are never proposed as includes**; they are
  offered as exclusions instead, so a wildcard include cannot later swallow them.
- A host that appears both in and out of scope resolves to **excluded**.
- Hosts with no scope wording nearby are listed as **unclear** and are not
  pre-selected.
- The bounty platform's own domains and common linked sites are never proposed.

Recon reports the same list (`propose_scope_from_workspace`, read-only), and the
empty-scope preflight blocker names the hosts it found rather than only telling
you the scope is empty. The mesh cannot set scope under any configuration.

---

## Certificate lifecycle

The project CA can now be **issued** and **revoked** from the app (and, when the
operator grants it, by the mesh).

| Operation | Effect |
|---|---|
| **Issue new CA** | Fresh material replaces the current CA. Every client that trusted the old certificate rejects interception until you install the new one. |
| **Revoke CA** | The material is destroyed. TLS interception stops: `CONNECT` tunnels are relayed through unread and nothing encrypted is captured until you issue a new CA. |

Both are audited and appear in the certificate history with their reason. The
proxy notices a change on the next `CONNECT` without a restart.

Revocation is a **deliberate, testable state**, not an error — it is how you
observe a client with interception genuinely off (certificate pinning, trust
behaviour, a control run). It is not a way to stop recording traffic you would
rather not have recorded; the audit log records the revocation itself.

As always, **no OS trust store is ever modified.** "Revoked" means this app will
no longer sign leaves with that CA — it is not a CRL anyone else honours.

---

## Proof of exploit

The rule: **the model proposes, the engine proves.**

A model asserting "this endpoint leaks another user's order" is a hypothesis, and
a hypothesis written confidently reads exactly like a finding. So the mesh cannot
mark anything proven by saying so. It names two exchanges it already captured — a
**control** (no change, or the legitimate user) and a **test** (exactly one thing
varied) — and the engine reads both and grades the differential:

| Outcome | Meaning |
|---|---|
| `confirmed` | A real status or body difference exists between the two captures. |
| `refuted` | The responses are identical. The hypothesis is dead — a genuine, valuable result. |
| `inconclusive` | Nothing was isolated: same exchange twice, a missing response, or only incidental header differences. |

The gate grades a *differential*, never a *vulnerability*. "The response differs"
is a fact; "this is an IDOR" stays the analyst's claim. It also raises caveats
rather than quietly confirming — a second changed variable (different method,
different host), a `429` that may be rate limiting, a `5xx` that may be
incidental.

This flips the cost of a fabricated finding. Before, it cost the operator hours
of disproving. Now it fails at the gate, because the bytes either differ or they
do not and the model does not get a vote.

---

## Hunt memory

A hunt that starts from zero every time re-tests what it refuted last month and
forgets what paid off.

Outcomes are recorded locally across engagements, keyed by a **path shape**
rather than a literal URL — `/api/orders/10432` and `/api/orders/99887` both
reduce to `/api/orders/{id}` — so a lesson learned on one object transfers to the
next, and to the next target with the same route shape. Recall merges matching
records into one verdict per shape and class, with a suggestion: *test this early
and check for regressions*, or *refuted three times, deprioritise*.

Limits, by design:

- **Local and app-global.** Stored under the app's user-data directory. It never
  leaves the machine.
- **Advisory, never authority.** It reorders attention and nothing else. It
  cannot confirm a finding — only the proof gate does that — and it cannot place
  a host in scope. A wrong record costs a little misplaced attention.
- **Redacted on write.** Notes and claims pass through the secret redactor,
  because a note about an auth bug is exactly where a token ends up pasted.
- **Bounded and append-only**, with old records ageing out.
- **Best-effort.** Any I/O failure degrades to "no history".

**Cross-engagement scoping.** The store spans engagements by design, which is a
confidentiality question for a firm working several programs under NDA. So:

- **Recall is scoped to the open engagement by default.** The program label from
  the engagement profile is applied automatically; a run does not see another
  client's records unless you ask for them explicitly.
- **Hostnames are only returned for the program being recalled.** A cross-program
  query still merges the *verdict* for a route shape — "this class confirmed
  somewhere, refuted elsewhere" — but never discloses which assets those were.
- **The store can be cleared** (`clearHuntMemory`), and the clear is audited.

Even so, a `claim` or `note` you write is durable and reusable, so keep them free
of client-identifying detail.

---

## Attack-surface ranking

`rank_attack_surface` is the judgement an experienced hunter applies in the first
ten minutes, written as code: an identifier in the path plus a `DELETE` says
*access control*; a `imageUrl` parameter says *SSRF*; `tpl` says *template
injection*; `returnUrl` says *open redirect*.

It is deterministic, offline, and **only reorders work.** It cannot introduce a
host, an endpoint, a payload, or a finding, and out-of-scope endpoints are
counted and dropped rather than ranked. At worst a bad ranking spends a little
attention in the wrong place.

---

## What the mesh does with all of this

```
recon → planner → [ attacker → analyst ]×N → reporter
```

**Recon runs first and is not optional.** It reads preflight, the engagement
folder, the certificate state, the ranked attack surface, and what previous hunts
already settled — then reports readiness. If preflight returns a blocker, recon
opens with `BLOCKED:` and the run stops there rather than producing a confident
plan for an engagement that cannot legitimately proceed.

A **declined turn is never silent.** If the model declines a role, the run
records it as an error, the reporter is told which roles were not done, and the
report says so. Silence would otherwise read as a clean result — the worst
available failure for a bug-hunting tool.

See [authorization-and-scope.md](authorization-and-scope.md) for the scope gate
and [certificate-management.md](certificate-management.md) for installing the CA.
