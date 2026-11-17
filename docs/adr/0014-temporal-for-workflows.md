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

## Note (2026-11-17, P5 as built)
Development runs the Temporal CLI dev server (`temporalio/temporal` 1.4.1, pinned by digest) with SQLite persisted to a volume. It does not use the auto-setup image on Postgres. Measured memory is about 100 MB for Temporal and about 60 MB for the worker. A production deployment needs a Temporal cluster on its own database; that is tracked for P8.
