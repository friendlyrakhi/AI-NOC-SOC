# ADR-0014: Temporal for workflows

- Status: accepted
- Date: 2026-11-16
- Decision ID: D14 (docs/10-decisions-for-approval.md)

## Context
Approvals need durable timers, signals and expiry.

## Decision
Temporal (Python SDK) is introduced in P5.

## Alternatives considered
A Postgres job queue.

## Consequences
Adds about 1 GB RAM in the `workflow` profile.
