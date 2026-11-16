# Unified AI NOC & SOC Operations Platform

A multi-tenant platform with separate **AI NOC** and **AI SOC** portals, a shared evidence-grounded AI engine, a universal connector framework, incident management, approval-gated automation and an executive command center.

> **Status: Phase 2 (connector SDK, 16 sandbox connectors, ingestion pipeline, canonical events).** Development build: every connector runs in **sandbox mode** against a vendor simulator. No live system is contacted, and remediation is simulated (`NOCSOC_EXECUTION_MODE=live` is rejected at startup; connector `mode` can only be `sandbox`).

Design docs: [docs/](docs/README.md) · Decisions: [docs/adr/](docs/adr/README.md) · Plan: [docs/08-implementation-plan.md](docs/08-implementation-plan.md) · Frontend guide: [frontend/README.md](frontend/README.md) · Latest phase report: [docs/reports/P2-exit-review.md](docs/reports/P2-exit-review.md)

> Two labels tell you where data comes from. **SANDBOX**: ingested by the real pipeline from sandbox connectors (alert queues, vulnerabilities, connectors). **DEMO**: generated in the UI for screens whose backend arrives in later phases (correlation, incidents, AI, automation, command center). See [docs/reports/frontend-demo-ui.md](docs/reports/frontend-demo-ui.md).

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
scripts\dev.ps1 up -Build      # core + stream: postgres, valkey, mailpit, api, web, redpanda, clickhouse,
                               #   ingest-worker, connector-runner (~1.1 GB in use, 5.5 GB limits;
                               #   -Profiles core for less)
scripts\dev.ps1 seed           # mock MSP + 2 customers + users + DEMO sandbox integrations
                               #   -> infrastructure/secrets/dev-users.json
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
| http://127.0.0.1:8123 | ClickHouse HTTP (telemetry; users and row policies created by `migrate-stream`) |
| 127.0.0.1:19092 | Redpanda Kafka API (for local tools) |

All ports bind to `127.0.0.1` and can be changed in `.env`.

### Seeing the pipeline work

After `seed`, the connector runner starts polling the DEMO sandbox integrations within seconds. Then:

1. Sign in as `admin@initech.example` and open **Connectors**: instances move from "Awaiting first run" to "Healthy" as real runs are reported.
2. Replay a scenario (e.g. *Phishing to credential misuse*, 10×) and open **AI SOC → SIEM events → Sandbox pipeline alerts**: repeats raise occurrence counts instead of adding alerts.
3. Open an instance and use **Sandbox fault injection** (reject credentials, 503s, 429s, schema drift) to watch health change to Failing or Degraded and back.

| Service | Role |
|---------|------|
| `connector-runner` | Polls the API for work, runs sandbox connectors, publishes raw records to Redpanda. Has only a runner token: no database credentials, and no network route to Postgres, Valkey or ClickHouse. |
| `ingest-worker` | Verifies ownership, normalizes, de-duplicates, resolves assets, writes Postgres (as the RLS-bound `nocsoc_worker` role) and ClickHouse (INSERT-only user). |
| `migrate-stream` | One-shot: topics, ClickHouse tables, users and row policies. |

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
| `connectors/` | Connector SDK (`sdk/`), 16 sandbox connectors (`catalog/`), runner (`runner/`) |
| `ai-engine/` | AI gateway, prompts, evals |
| `automation/` | Temporal worker, playbooks |
| `infrastructure/` | Compose, Dockerfiles, service config, secrets (git-ignored) |
| `scripts/` | bootstrap / dev / doctor / ci |
| `tests/` | Cross-cutting tests (security, e2e) |

## Troubleshooting

- **`invalid peer certificate: UnknownIssuer`** means antivirus or a proxy is inspecting TLS. See [infrastructure/certs/README.md](infrastructure/certs/README.md). `scripts\bootstrap.ps1` handles it automatically.
- **`port is already allocated`** means another program uses that port. Change it in `.env`.
- **Rotating secrets** after Postgres has initialized requires `scripts\dev.ps1 reset` (this deletes local data).
- **Alert queues show only DEMO data** means the stream profile is not running, or you are in the read-only "All customers" view (ingested data is shown per customer).
- **Low memory:** `scripts\dev.ps1 up -Profiles core` runs without Redpanda and ClickHouse; ingestion endpoints then answer `503`.
