# 00 — Workspace Assessment

Inspected: 2026-11-16

## Repository state

| Item | Finding |
|------|---------|
| Path | `C:\AI-NOC-SOC` |
| Git | Initialized; branch `master`; **no commits**. Note: tooling reports `main` as the intended main branch. Recommend renaming `master` → `main` on first commit. |
| Directories | `ai-engine/`, `automation/`, `backend/`, `connectors/`, `docs/`, `frontend/`, `infrastructure/`, `scripts/`, `tests/` — **all empty** |
| Existing code/config | None (no `package.json`, `pyproject.toml`, compose files, `.gitignore`, CI) |

The existing folder names are kept as the top-level module layout (see [02-architecture.md §9](02-architecture.md#9-repository-layout)).

## Toolchain

| Tool | Version | Notes |
|------|---------|-------|
| Node.js | 26.13.1 | Next.js should be run on an LTS line; Phase 0 verifies Next.js compatibility and pins via `.nvmrc`/`engines`. |
| Python | 3.12.10 | Good target for FastAPI / Temporal Python SDK / ClickHouse & Kafka clients. |
| Docker | 29.9.3, Compose v5.7.0 | WSL2 backend (`docker-desktop` distro). |
| Git | 2.56 (Windows) | Set `core.autocrlf=input` + `.gitattributes` to avoid CRLF breaking shell scripts in containers. |

## Hardware constraints (drive key architecture decisions)

| Resource | Value | Implication |
|----------|-------|-------------|
| CPU | Intel i5-1335U, 12 logical cores (mobile, power-limited) | Fine for dev; avoid running all JVM services concurrently. |
| RAM | **15.6 GB total** | Full stack estimate (Postgres, ClickHouse, OpenSearch, Redpanda, Temporal+its DB, Valkey, OTel collector, API, workers, Next.js dev, Docker Desktop VM, IDE, browser) exceeds what is comfortable. **→ Compose profiles** (`core`, `stream`, `analytics`, `search`, `workflow`, `observability`) with documented memory caps. |
| Disk | 40 GB free on C: | ClickHouse/OpenSearch/Kafka data must have retention limits and a `scripts/reset` command. Images alone ≈ 8–12 GB. |

## Found during P0

| Item | Finding | Handling |
|------|---------|----------|
| TLS inspection | Norton Antivirus re-signs HTTPS ("Norton Web/Mail Shield Root"). Containers and uv's bundled certificates reject it. | uv `system-certs = true`; build-only CA bundle via BuildKit secret (`infrastructure/certs/README.md`). |
| Port 8000 | Used by another local container (`admin-assist`) | API host port defaults to 8100 |
| Docker VM memory | 7.6 GiB available to Docker | Adequate for core + stream + analytics |
| Tools | uv and pnpm were missing; installed at user level. Node 26 has no Corepack. | `scripts/doctor.ps1` checks them |

## Recommendations from the assessment

1. Keep source in the Windows filesystem for IDE use, but if bind-mount performance hurts (Next.js hot reload / Python reload), move the working copy into the WSL2 filesystem.
2. Cap the WSL2 VM via `%UserProfile%\.wslconfig` (e.g. `memory=10GB`, `swap=4GB`) so Windows stays responsive.
3. All container ports bind to `127.0.0.1` only — never `0.0.0.0` — on a personal PC.
4. Do not run the `search` (OpenSearch) and `analytics` (ClickHouse) profiles together with the Next.js dev server unless needed; the plan stages them.
