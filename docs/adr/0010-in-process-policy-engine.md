# ADR-0010: In-process policy engine

- Status: accepted
- Date: 2026-11-16
- Decision ID: D10 (docs/10-decisions-for-approval.md)

## Context
Authorization must be fast and testable. OPA adds a sidecar.

## Decision
A Python RBAC+ABAC policy engine with an OPA-compatible interface.

## Alternatives considered
OPA sidecar; Cedar.

## Consequences
Swappable later.
