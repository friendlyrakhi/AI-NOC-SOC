# Platform runbook

How to run, check and recover the platform itself. This is not the SOC/NOC runbooks that tenants publish in the knowledge base. Commands are PowerShell. `scripts/*.sh` and `python scripts/...` behave the same on Linux and macOS.

## 1. The stack at a glance

| Profile | Services | Needed for |
|---------|----------|------------|
| `core` | postgres, valkey, mailpit, migrate, api, web, audit-anchor | Sign-in, tenants, incidents, audit |
| `stream` | redpanda, clickhouse, migrate-stream, ingest-worker, connector-runner | Connectors, ingestion, KPIs |
| `ai` | ai-gateway (mock model by default) | Copilot, summaries, briefing |
| `workflow` | temporal, workflow-worker | Action requests and playbooks (simulate or dry-run only) |
| `search` | opensearch, opensearch-setup | Event search, hunting, fast global search |
| `observability` | otel-lgtm | Dashboards, SLO alerts, traces ([slos.md](slos.md)) |
| `sso` | keycloak | Optional single sign-on ([onboarding.md](onboarding.md) §5) |
| `tools` | audit-verify | One-shot audit verification |
| hardened override | openbao, openbao-setup, edge, plus TLS on every store | [hardened.md](hardened.md) |

**Commands.**
- `scripts\dev.ps1 up` starts the default profiles; `up -Profiles ...` picks your own.
- `status` shows containers and memory; `logs <service>`; `down`.
- Data survives `down`. Only `reset` deletes volumes, and it asks first.

**Health.** `GET /api/v1/health/ready` checks Postgres and Valkey. The Command Center shows which optional stores answer. Every service has a compose healthcheck; `dev.ps1 status` lists unhealthy ones.

## 2. Alerts and what to do

### API errors
`ApiErrorBudgetFastBurn` / `ApiErrorBudgetSlowBurn`.
1. Grafana dashboard → "API requests by status class". Is it one route or all?
2. `scripts\dev.ps1 logs api` and look for `"level": "ERROR"`. Each error line has a `trace_id`; open it in Tempo.
3. **All routes failing:** check Postgres and Valkey (`dev.ps1 status`). The API answers 503 `*.disabled` for profiles that are not running. These count as errors, so start the profile or stop calling the feature.
4. **One route failing:** treat it as a bug. Capture the trace and request id, and file it with the response's problem `code`.

### Slow API
`ApiReadLatencyHigh`.
1. Find the route in "API GET p95 by route".
2. For list endpoints, look at the query plan:
   ```powershell
   docker exec -it nocsoc-postgres-1 psql -U postgres nocsoc
   ```
   then run `EXPLAIN ANALYZE` on the statement from the trace.
3. Check memory pressure (`dev.ps1 status`). Postgres has a 1 GB limit.
4. Re-run the load test (`python scripts\loadtest.py api`) to confirm a fix.

### Ingest lag
`IngestLatencyHigh`.
1. "Ingest throughput by result". Is it `stored`, or a spike in `dead_letter` / `failed`?
2. **Dead letters:** Connectors → the integration → dead letters show the reason (drift, quota, size).
   - `quota_exceeded` means a tenant exceeded its per-minute quota (`NOCSOC_TENANT_INGEST_RECORDS_PER_MINUTE`, default 6,000). The records are kept and can be replayed.
3. **Throughput:** each worker runs two consumer groups: `nocsoc-ingest` for ordered topics (`raw.*`: alerts, assets, findings, tickets) and `nocsoc-ingest-telemetry` for telemetry topics (`rawt.*`, batched). One worker sustains about 1,450 telemetry events/s. Alerts are slower, because each one is correlated. Check lag per group with `docker exec nocsoc-redpanda-1 rpk group describe nocsoc-ingest` (and `...-telemetry`). For more throughput, run more workers:
   ```powershell
   docker compose ... up -d --scale ingest-worker=2
   ```
   The consumer group spreads partitions across them.
4. **Bus:** check the Redpanda container. Raw topics keep 24 h, so nothing is lost while the worker catches up.

### Outbox backlog
`TelemetryOutboxBacklog`. ClickHouse or OpenSearch has not accepted telemetry for 15 minutes.
1. The ingest worker log says which sink fails (`telemetry insert failed` / `search indexing failed`).
2. Bring the store back. The relay retries every 5 s, per tenant and per sink.
3. Rows older than 72 h (`NOCSOC_TELEMETRY_OUTBOX_MAX_AGE_HOURS`) are dropped with a warning. To recover them, re-run the connectors' scenarios or wait for the next pulls.

### Projector
`ProjectorFailing`. KPIs or search are going stale.
1. The ingest worker log shows `projection failed (stream=... sink=...)`.
2. When the store is back, projection resumes from its watermark. A full resync runs every 15 minutes.
3. **Forcing a rebuild:** delete that tenant's rows in `projection_state` (superuser). The next pass re-projects everything. This is idempotent.

### Audit anchor mismatch
`AuditAnchorMismatch` (page). The audit log no longer contains what was anchored, meaning entries were removed or rewritten.
1. **Do not restart or "fix" anything first.** Preserve evidence:
   ```powershell
   python scripts\backup.py backup
   ```
   This includes the anchor file.
2. Run `scripts\dev.ps1 verify-audit`. It names the chain and the sequence numbers.
3. Compare with the newest backup's audit (`pg_restore` into a scratch database). Treat it as a security incident: database superuser access is the only way to bypass the append-only trigger.
4. `AuditAnchorStalled`: the audit-anchor container is down or cannot reach Postgres. See `logs audit-anchor`.

## 3. Backup and restore

| Command | What it does |
|---------|--------------|
| `python scripts\backup.py backup` | Writes `backups\<UTC>\`: audit anchors (taken first), Postgres (`pg_dump`), ClickHouse (native BACKUP), OpenSearch snapshot of the tenant indices, and a manifest with counts, checksums and the master-key fingerprint |
| `python scripts\backup.py restore backups\<UTC> --yes` | Stops the writers, restores every store, restarts the writers, then verifies counts, the audit chains and anchors, and an API sign-in |
| `python scripts\backup.py drill` | Backup, then restore into a separate, empty stack (`nocsoc-drill`), verify it, and remove it. Your stack is stopped (not changed) while the drill runs. |

**Not in the backup:**
- **Secrets.** Copy `infrastructure\secrets` to protected storage separately.
  - Without the same `master_key`, connector credentials and MFA secrets are unrecoverable.
  - Without the same `audit_anchor_key`, the anchors cannot be checked.
  - Restore refuses a backup whose master-key fingerprint differs.
- **Redpanda (24 h buffer) and the Temporal dev server's history.** Action requests themselves are in Postgres.
- **Anchors kept off the host.** Copy `audit-anchors.tar` from each backup somewhere the database administrators cannot write. That is what makes truncation detectable after a host compromise.

## 4. Secrets and keys

| Secret | Rotation |
|--------|----------|
| Database, Valkey, ClickHouse, OpenSearch, service tokens | `bootstrap.ps1 -RotateSecrets`, then `dev.ps1 up` (roles and store users are re-synced at start) |
| `master_key` | Do **not** rotate with bootstrap: existing encrypted values would become unreadable. Move to OpenBao instead (hardened profile, `app.tools.rewrap_secrets`), where Transit keys rotate with `transit/keys/nocsoc-master/rotate` without re-encrypting. |
| `audit_anchor_key` | Archive the current anchor file with the old key first. A new key starts a new anchor chain. |
| TLS certificates | `python scripts\certs.py --rotate`, then `dev.ps1 up -Hardened` |
| Grafana, Keycloak admin and SSO demo passwords | Bootstrap rotation, then recreate the container |

## 5. Safety switches

- **Kill switch.**
  - **Per tenant:** Automation → Kill switch, needs step-up.
  - **Platform:** Admin → Platform.
  - Engaging it stops new action executions immediately. Running workflows check it before every step.
- **Live execution** is impossible by configuration: `NOCSOC_EXECUTION_MODE` only accepts `simulate` and `dry_run`. Changing that is a P8+ decision.
- **AI cloud egress** is off. Turning it on needs three deliberate switches (docs/reports/P4-exit-review.md).

## 6. Security testing

| Command | Notes |
|---------|-------|
| `uv run pytest -m fuzz backend/tests/fuzz` | Schemathesis over every API operation, plus the anonymous-access sweep (CI gate `fuzz`) |
| `python scripts\dast.py` | OWASP ZAP: web baseline (anonymous and signed in) plus an active API scan with a temporary API key in the Initech DEMO tenant. Reports go to `reports\dast\`. Accepted alerts are listed in `scripts\dast-accepted.json` with a reason. |
| `python scripts\loadtest.py api` / `ingest` | NFR-1 / NFR-2 load tests ([P7 exit review](../reports/P7-exit-review.md)) |

## 7. Known behaviours

- **After a restart, the first OIDC sign-in can take a few seconds.** Discovery and JWKS are cached for an hour.
- **The hardened profile needs certificates.** `scripts\certs.py` runs automatically from bootstrap and `up -Hardened`.
- **Hardened-mode browsing** goes through https://127.0.0.1:3443 only; port 3000 is closed.
- **Development tools use http://127.0.0.1:8100.** `scripts\dast.py`, `loadtest.py` and the backup smoke check expect the default (non-hardened) stack.
