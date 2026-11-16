# ADR-0001: Modular monolith with isolated runtimes

- Status: accepted
- Date: 2026-11-16
- Decision ID: D1 (docs/10-decisions-for-approval.md)

## Context
One developer, one 16 GB PC. A microservice split would add deployment, networking and debugging cost without benefit at this scale, but some components need isolation for security.

## Decision
The API is a FastAPI modular monolith. connector-runner, ingest-worker, ai-gateway, workflow-worker and web are separate runtimes because they need isolation (credentials, egress, execution) or independent scaling. Module boundaries are enforced with import-linter contracts in `pyproject.toml`.

## Alternatives considered
Microservices per domain.

## Consequences
Modules can be extracted later. Import-linter contracts must grow with each module (CI gate `imports`).
