# ADR 0001 — Record architecture decisions

- Status: Accepted
- Date: 2026-07-15

## Context

TACNOC is a long-lived security-research tool. Architectural choices
(stack, storage, trust boundaries, TLS interception design) have safety and
maintenance consequences that outlive any single change. We need a durable,
reviewable record of *why* decisions were made, not just *what* the code does.

## Decision

We keep Architecture Decision Records (ADRs) in `docs/adr/`, one Markdown file
per decision, numbered sequentially. Each ADR states context, the decision, and
consequences. Superseded ADRs are kept and marked, not deleted.

## Consequences

- Reviewers and future maintainers can audit the reasoning behind trust
  boundaries and safety controls — this is part of how GreyNOC keeps its
  broad in-scope grant credible and auditable.
- A small amount of process overhead per significant decision.
