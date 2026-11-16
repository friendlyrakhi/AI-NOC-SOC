# Unified AI NOC & SOC Operations Platform

A multi-tenant platform with separate **AI NOC** and **AI SOC** portals, a shared evidence-grounded AI engine, a universal connector framework, incident management, approval-gated automation and an executive command center.

> **Status: Phase 0 (foundations).** Development build with **mock data and sandbox connectors only**. No live integrations exist, and remediation is simulated (`NOCSOC_EXECUTION_MODE=live` is rejected at startup).

Design docs: [docs/](docs/README.md) · Decisions: [docs/adr/](docs/adr/README.md) · Plan: [docs/08-implementation-plan.md](docs/08-implementation-plan.md)

## Prerequisites

| Tool | Version |
|------|---------|
| Docker Desktop (WSL2) | 29+, Compose v5 |
| Node.js | 26 (`.nvmrc`) |
| pnpm | 12.21 (`npm i -g pnpm@12.21.0`) |
| Python | 3.12 |
| uv | 0.13 (`python -m pip install --user uv`) |

Run `scripts\doctor.ps1` to check your machine.

## Quick start (Windows PowerShell)

```powershell
scripts\bootstrap.ps1          # dev secrets, .env, build CA bundle, uv sync, pnpm install
scripts\dev.ps1 up -Build      # core profile: postgres, valkey, mailpit, api, web
scripts\dev.ps1 status         # containers + memory
scripts\ci.ps1                 # all CI gates locally
scripts\dev.ps1 down
```

On Linux or macOS, use `scripts/bootstrap.sh`, `scripts/dev.sh` and `scripts/ci.sh`.

| URL | What |
|-----|------|
| http://127.0.0.1:3000 | Web (portal shell) |
| http://127.0.0.1:8100/api/v1/docs | API docs (OpenAPI) |
| http://127.0.0.1:8025 | Mailpit (dev email sink) |

All ports bind to `127.0.0.1` and can be changed in `.env`.

## Frontend development with hot reload

```powershell
pnpm --filter frontend dev     # http://localhost:3000, faster than the container on Windows
```

## Layout

| Path | Contents |
|------|----------|
| `frontend/` | Next.js 16 app (NOC, SOC, Command, Admin portals) |
| `backend/` | FastAPI modular monolith (`app/core`, `app/modules`) |
| `connectors/` | Connector SDK, runner, catalog |
| `ai-engine/` | AI gateway, prompts, evals |
| `automation/` | Temporal worker, playbooks |
| `infrastructure/` | Compose, Dockerfiles, service config, secrets (git-ignored) |
| `scripts/` | bootstrap / dev / doctor / ci |
| `tests/` | Cross-cutting tests (security, e2e) |

## Troubleshooting

- **`invalid peer certificate: UnknownIssuer`** means antivirus or a proxy is inspecting TLS. See [infrastructure/certs/README.md](infrastructure/certs/README.md). `scripts\bootstrap.ps1` handles it automatically.
- **`port is already allocated`** means another program uses that port. Change it in `.env`.
- **Rotating secrets** after Postgres has initialized requires `scripts\dev.ps1 reset` (this deletes local data).
