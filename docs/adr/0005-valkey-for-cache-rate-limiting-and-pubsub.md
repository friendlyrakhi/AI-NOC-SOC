# ADR-0005: Valkey for cache, rate limiting and pub/sub

- Status: accepted
- Date: 2026-11-16
- Decision ID: D5 (docs/10-decisions-for-approval.md)

## Context
Redis licensing changed in 2024-2025.

## Decision
Valkey 8.1 (BSD-3), pinned by digest, password-protected (config written to tmpfs, not argv), no persistence in dev.

## Alternatives considered
Redis.

## Consequences
Any Redis-protocol client works (the API uses redis-py).
