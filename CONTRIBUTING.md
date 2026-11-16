# Contributing

## Workflow

- Branch from `main`. Use [Conventional Commits](https://www.conventionalcommits.org/) (`feat(api): …`, `fix(web): …`, `docs: …`).
- One commit or PR per phase slice (ADR-0013). Phases follow [docs/08-implementation-plan.md](docs/08-implementation-plan.md), and each one ends with an exit review.
- Significant decisions need an ADR ([docs/adr/0000-template.md](docs/adr/0000-template.md)).
- Run `scripts\ci.ps1` (or `scripts/ci.sh`) before pushing. Optional: `uv run pre-commit install`.

## Definition of Done (every feature)

1. Code plus tests (unit; integration with real stores where it touches them).
2. Every endpoint declares its permission; the tenant-isolation suite is updated (from P1).
3. Security-relevant operations emit audit events (from P1).
4. OpenAPI updated; TypeScript client regenerated (from P1).
5. UI has loading, empty and error states and passes accessibility checks.
6. Docs or ADR updated.
7. No secrets in code, logs, fixtures or test output.

## Non-negotiable guardrails

- **No live integrations.** Connectors run in `sandbox` mode with synthetic fixtures until a connector is verified against a real account you supply (P8, separately approved).
- **No real remediation.** `NOCSOC_EXECUTION_MODE` accepts only `dry_run` and `simulate`. Do not weaken `nocsoc_connector_sdk.execution.assert_execution_allowed` or its tests.
- **The AI never executes.** The `ai_gateway` package may not import `workflow_worker` or `connector_runner` (import-linter contract).
- **Secrets** live only in `infrastructure/secrets/` (git-ignored) and reach containers as files, never as env values. `scripts/check-compose.py` enforces this.
- **Containers** publish ports on `127.0.0.1` only, with no privileged mode and no Docker socket mounts.
