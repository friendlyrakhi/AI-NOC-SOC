# ADR-0011: OCSF and OTel-aligned normalized schemas

- Status: accepted
- Date: 2026-11-16
- Decision ID: D11 (docs/10-decisions-for-approval.md)

## Context
Fifteen vendors need one model.

## Decision
OCSF-aligned for security events, OTel-aligned for operations, plus internal `alert@1`.

## Alternatives considered
Custom schema; ECS.

## Consequences
Mappings are golden-tested per connector.
