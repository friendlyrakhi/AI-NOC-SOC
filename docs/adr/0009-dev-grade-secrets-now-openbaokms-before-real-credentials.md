# ADR-0009: Dev-grade secrets now, OpenBao/KMS before real credentials

- Status: accepted
- Date: 2026-11-16
- Decision ID: D9 (docs/10-decisions-for-approval.md)

## Context
Only mock data exists until P8.

## Decision
P0 uses generated secrets in `infrastructure/secrets/` (git-ignored, ACL restricted to the current user), delivered to containers as Docker secret files and never as env values. P1 adds envelope encryption behind `SecretsProvider`.

## Alternatives considered
OpenBao from P0.

## Consequences
Hard gate: OpenBao/KMS is mandatory before any real credential is stored (P8).
