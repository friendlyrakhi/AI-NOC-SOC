# P0 Exit Review: Foundations

Date: 2026-11-16 · Status: **ready for your review**

## Exit criteria (docs/08-implementation-plan.md §P0)

| Criterion | Result | Evidence |
|-----------|--------|----------|
| `bootstrap` + `dev up core` works on this PC | **Pass** | `scripts\bootstrap.ps1` then `scripts\dev.ps1 up -Build`. All 5 containers report healthy; `/api/v1/health/ready` returns 200 (Postgres + Valkey reachable with secrets). |
| CI green | **Pass (local)** | `scripts\ci.ps1`: 13/13 gates (ruff, mypy strict, import-linter, bandit, pytest 41 tests, pip-audit, eslint, typecheck, vitest, npm audit, next build, compose policy, gitleaks). GitHub Actions workflow is written but **not yet run** (no remote). |
| Fake committed secret is caught by gitleaks | **Pass** | A generated `ghp_…` token committed to a throwaway repo gave `leaks found: 1`, exit 1. Done outside this repo so no secret entered its history. |
| `core` profile ≤ 3.5 GB | **Pass** | Idle: api 52 MiB, web 44 MiB, postgres 44 MiB, valkey 5 MiB, mailpit 9 MiB (≈150 MiB). Caps total 2.4 GiB. |

## Delivered

- **Repo hygiene:** branch `main`, `.gitignore`, `.gitattributes` (LF; CRLF for `.ps1`), `.editorconfig`, `.dockerignore`, `.env.example`, `README.md`, `CONTRIBUTING.md`, ADR template plus ADR-0001…0015.
- **Python uv workspace:** `backend` (FastAPI `/api/v1/health/{live,ready}`, settings, OTel bootstrap), `connectors/sdk` (execution-mode guard), plus stub packages for runner, ai-gateway and workflow-worker.
- **Frontend:** Next.js 16.4.6 standalone build, dark-first theme tokens, SANDBOX banner, portal registry, health route, security headers.
- **Compose `core` profile:** Postgres 17.12 + pgvector 0.8.7 + citext, Valkey 8.1.11, Mailpit 1.33.1, api, web. Images are pinned by digest, use secret files, publish on localhost only, and have memory caps. App containers are read-only, run as non-root, and drop all capabilities.
- **Scripts:** `bootstrap`, `dev`, `ci` (PowerShell + POSIX), `doctor.ps1`, `check-compose.py`.
- **CI/CD:** `.github/workflows/ci.yml`, `dependabot.yml`, `.pre-commit-config.yaml` (local hooks only), `.gitleaks.toml`.

## Guardrails already enforced by tests

| Guardrail | Test |
|-----------|------|
| `execution_mode=live` rejected at startup | `backend/tests/test_guardrails.py` |
| SDK blocks live execution unless all gates are open (exhaustive) | `connectors/sdk/tests/test_execution_guard.py` |
| AI gateway cannot import executors | import-linter contract |
| Readiness probe leaks no dependency details | `backend/tests/test_health.py` |
| Compose: loopback ports, no privileged/socket/cap_add, no secret env, memory caps | `tests/security/test_compose_policy.py` + `compose` gate |

## Findings and deviations (please note)

1. **Norton Antivirus intercepts HTTPS** ("Norton Web/Mail Shield Root"). Builds inside containers failed with `UnknownIssuer`. Fix: `bootstrap` exports the root CA the host sees into `infrastructure/certs/extra-ca.pem` (git-ignored), which builds use **only as a BuildKit secret** and never copy into images. uv on the host uses `system-certs = true`. The alternative is to exclude Docker/WSL from Norton's HTTPS scanning.
2. **Port 8000 is used by your `admin-assist` container**, so the API host port is now **8100** (configurable in `.env`). I didn't touch that container.
3. **Installed on your machine (user level):** `uv` 0.13.8 (pip `--user`, at `%APPDATA%\Python\Python312\Scripts`, which is **not on PATH**; the scripts find it anyway) and `pnpm` 12.21.0 (npm global). Docker Desktop was started.
4. **API image runs from source**, without a wheel build, to avoid fetching build tools at image-build time.
5. **Node 26** is LTS as of 2026-10, so risk R15 is closed. Next.js 16.4.6 builds and runs on it.
6. **Starlette deprecation warning:** the TestClient suggests `httpx2`. This is harmless now; P1 will revisit it when test dependencies are set.
7. **No LICENSE file** has been added; that's your choice.
8. GitHub Actions are pinned by major tag. Dependabot is configured; SHA-pinning comes with the first remote push.

## Still open (from docs/10)

The five questions (MSP need, cloud LLM provider, commercial intent, GitHub remote, vendor accounts) still use their defaults. **Q1 (MSP) affects P1 scope**, so please answer it before P1 starts.

## Next: P1 Platform core

Identity (Argon2id, TOTP, BFF sessions), tenancy with MSP hierarchy, RBAC and policy engine, RLS on all tenant tables, the hash-chained audit log, envelope-encrypted secrets, the portal shell with NOC/SOC/Command/Admin layouts, and seed tenants and users. **Awaiting your go-ahead.**
