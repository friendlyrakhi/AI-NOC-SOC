# ADR-0006: Defer OpenSearch to P6

- Status: accepted
- Date: 2026-11-16
- Decision ID: D6 (docs/10-decisions-for-approval.md)

## Context
OpenSearch costs about 2 GB RAM. Hunting is only needed in P6.

## Decision
Use Postgres full-text search until P6, then add the `search` profile.

## Alternatives considered
OpenSearch from P2; ClickHouse-only search.

## Consequences
The global-search API is designed behind a façade so the backend can switch.

## Note (2026-11-17, P6 as built)
OpenSearch 3.8.0 now runs in the `search` profile, at about 1.2 GB with a 512 MB heap. Global search uses it when it runs and falls back to Postgres FTS otherwise, so the `core` profile keeps working without it.
