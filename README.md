# Unified AI NOC & SOC Operations Platform

A multi-tenant platform with separate **AI NOC** and **AI SOC** portals, a shared evidence-grounded AI engine, a universal connector framework, incident management, approval-gated automation and an executive command center.

> **Status: Phase 1 (platform core: identity, MSP tenancy, RBAC, audit, portal shell).** Development build with **mock data only**. No live integrations exist, and remediation is simulated (`NOCSOC_EXECUTION_MODE=live` is rejected at startup).

Design docs: [docs/](docs/README.md) · Decisions: [docs/adr/](docs/adr/README.md) · Plan: [docs/08-implementation-plan.md](docs/08-implementation-plan.md) · Frontend guide: [frontend/README.md](frontend/README.md)

> The full operations UI (Command Center, NOC, SOC, incidents, automation, connectors, reports) is built and runs on clearly labelled **DEMO** data until phases P2–P6 deliver real data. See [docs/reports/frontend-demo-ui.md](docs/reports/frontend-demo-ui.md).

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
scripts\dev.ps1 up -Build      # core profile: postgres, migrate, valkey, mailpit, api, web
scripts\dev.ps1 seed           # mock MSP + 2 customers + users -> infrastructure/secrets/dev-users.json
scripts\dev.ps1 totp admin@globex.example   # current MFA code for a seeded user
scripts\dev.ps1 status         # containers + memory
scripts\ci.ps1                 # all CI gates locally (integration tests need Docker)
pnpm e2e                       # browser journeys against the running stack (uses installed Edge)
scripts\dev.ps1 down
```

On Linux or macOS, use `scripts/bootstrap.sh`, `scripts/dev.sh` and `scripts/ci.sh`.

| URL | What |
|-----|------|
| http://127.0.0.1:3000 | Web (portal shell) |
| http://127.0.0.1:8100/api/v1/docs | API docs (OpenAPI) |
| http://127.0.0.1:8025 | Mailpit (dev email sink; invitations land here) |

All ports bind to `127.0.0.1` and can be changed in `.env`.

### Seeded accounts (after `scripts\dev.ps1 seed`)

| Tenant | Accounts | Notes |
|--------|----------|-------|
| Acme Managed Services (MSP) | `msp.admin@`, `msp.noc@`, `msp.soc@`, `msp.exec@acme.example` | Reach customers only through delegations. MSP members get the read-only "All customers" view. |
| Globex Corporation (customer) | `admin@`, `noc@`, `auditor@globex.example` | |
| Initech (customer) | `admin@`, `soc@initech.example` | |
| Platform | `platform.admin@nocsoc.example` | Manages tenants; cannot read tenant data. |

Passwords and TOTP secrets are random for each seed run and are stored only in `infrastructure/secrets/dev-users.json` (git-ignored). Privileged roles require MFA.

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
