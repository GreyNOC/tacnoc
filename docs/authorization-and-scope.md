# Authorization and scope

TACNOC is for **authorized** testing. Two mechanisms make that
operational rather than aspirational: an authorization reference recorded on the
project, and a fail-closed **scope** that gates all automated request
generation.

## Before you start

- Have written authorization (signed SOW, engagement letter, bug-bounty program
  scope, or your ownership of the system).
- Record an **authorization reference** when creating the project (free-text,
  stored in project metadata) so the artifact is self-describing.
- Prefer least-impact, read-only interactions; avoid destructive actions.

## What scope controls

Scope is a set of **include** and **exclude** rules. A destination
(`scheme://host:port/path`) is **in scope** iff it matches at least one enabled
include rule **and** no enabled exclude rule.

- With **no include rules, nothing is in scope** (fail-closed). This is
  deliberate.
- Scope is evaluated in the **engine**, not just the UI. The variation
  (automated) engine:
  - **refuses to create a job** whose base destination is out of scope, and
  - **re-checks every generated request** and **skips** (and audits) any that a
    payload pushes out of scope.
- The proxy still **captures** all traffic you route through it (passive
  observation is allowed and useful), but **marks** each exchange in/out of
  scope. Manual tools (Repeater) are single-shot and not scope-gated, but the
  resulting exchange records its scope status.

## Rule types

Each rule specifies:

- **Host match**:
  - `exact` — host must equal the pattern.
  - `subdomain` — host equals the pattern **or** ends with `.` + pattern
    (so `example.test` matches `api.example.test` but **not** `evilexample.test`).
  - `wildcard` — glob where `*` matches one label and `**` matches many
    (e.g. `*.example.test`, `**.example.test`).
- **Schemes** — `http`, `https`, or empty for any.
- **Ports** — a list, or empty for any.
- **Path** — optional `prefix:<value>` or `regex:<value>` applied to the request
  path. An invalid regex matches nothing (never everything).

## Recommended workflow

1. Create the project and record your authorization reference.
2. Add **include** rules for exactly the hosts/paths you may test.
3. Add **exclude** rules for anything sensitive within those (e.g. `^/admin`,
   payment endpoints, logout).
4. Confirm the **Scope** column in HTTP History shows `in` for your target and
   `out` for everything else before running any automated variation.
5. Keep the **Emergency stop** in reach; it halts all automated work instantly.

## Hard stops

Stop immediately and reassess if you observe: destructive side effects, access
to data outside the authorization, signs of a production incident, or any
condition your rules of engagement define as a stop condition.
