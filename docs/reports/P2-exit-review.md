# P2 Exit Review: Connector SDK, sandbox connectors, ingestion pipeline

Date: 2026-11-16 · Status: **ready for your review**

Everything in this phase is **sandbox-only**. No connector can reach a real vendor. Connector instances are constrained to `mode = 'sandbox'` by a database CHECK, the runner refuses any other mode, and connector code cannot import networking libraries (the contract suite checks this). Data produced by the pipeline is labelled **SANDBOX** in the UI. The P1 front-end mock data stays labelled **DEMO**.

## Exit criteria (docs/08-implementation-plan.md §P2)

| Criterion | Result | Evidence |
|-----------|--------|----------|
| All 16 connectors pass the ContractSuite; each shows "SANDBOX" in the UI | **Pass** | `connectors/catalog/tests/test_contract.py` runs `run_contract` for all 16 (manifest, forbidden imports, deterministic normalize, checkpoint monotonicity, pagination equivalence, guarded actions). Golden files in `tests/golden/`. E2E: connectors page. |
| Scenario replay yields the expected alerts, with de-duplication | **Pass** | `test_ingestion.py`: core-switch golden alerts, noise scenario (14 alerts fold into 2), KEV findings. All of them go through the real path: API → Redpanda → ingest worker → Postgres/ClickHouse → API. |
| Fault injection drives the correct health transitions | **Pass** | `connectors/runner/tests/test_scheduler.py` covers each transition: auth failure goes straight to *failing* with the circuit open; transient errors go to *degraded*, then *failing* after 3; rate limiting and schema drift go to *degraded*; clearing the fault recovers to *healthy*; a bus outage never blames the source. E2E: injecting a fault into a live instance drives it to *failing*, and clearing it recovers. |
| 10× burst replay without loss | **Pass** | `test_burst_10x_replay_completes_without_loss`: every published record is processed, and occurrence counts add up exactly. `test_redelivery_has_no_second_effect` shows at-least-once delivery has exactly-once effect. |
| SEC-CON-01..05, SEC-SEC-01/02, SEC-ISO-03/05 | **Pass, two partial** (see below) | Table below. |

### Security tests

| ID | Threat | Result | Evidence |
|----|--------|--------|----------|
| SEC-CON-01 | SSRF via connector URL (T12) | Pass | `test_transport_security.py`: loopback, private, link-local, cloud-metadata and IPv4-mapped IPv6 destinations are blocked, as is any hostname whose DNS answer includes a private address (rebinding). |
| SEC-CON-02 | Malicious connector code (T13) | Pass | The contract suite rejects connectors importing `httpx`, `socket`, `subprocess` and others. The runner container is read-only, drops all capabilities, has no database credentials and sits only on the bus network (compose policy check). `normalize` runs in the worker as a pure function. |
| SEC-CON-03 | Webhook spoofing/replay (T14) | Pass | `test_webhook_hmac_replay_and_limits`: a bad signature, stale timestamp or unknown instance all get the same 401. A reused nonce gets 409, and oversized bodies get 413. |
| SEC-CON-04 | Poisoned/oversized payloads (T15) | **Partial** | Size (256 KB per record), depth (32), schema validation and dead-lettering are tested. Per-tenant **ingest** quotas are not implemented. What exists: a per-instance webhook rate limit and per-tenant budgets for replay and event search. Scheduled for P3. |
| SEC-CON-05 | Log/CSV injection (T16) | **Partial** | Logs are structured JSON with field encoding (`test_logging.py`). CSV export does not exist yet; formula escaping lands with exports (P7). |
| SEC-SEC-01 | Credential leakage via logs/errors (T17) | Pass | The secret scrubber masks known secret values and token shapes (`nss_`, `nsk_`, `whs_`, bearer, `password=`) in messages and tracebacks. Runner error details are sanitized. |
| SEC-SEC-02 | Secrets readable from the API (T18) | Pass | `test_credentials_are_write_only`: credentials are never returned, the stored ciphertext does not contain the plaintext, and the audit log records field names only. The webhook secret is shown once. |
| SEC-ISO-03 | Analytics query without tenant filter (T8) | Pass | `test_clickhouse_row_policy_isolates_tenants`: the reader user only sees rows for `SQL_tenant_id`; with no setting the query fails. `/events` search is tenant-isolated. |
| SEC-ISO-05 | Bus message claims another tenant (T10) | Pass | `test_tenant_mismatch_is_dead_lettered`: ownership is looked up from the instance record. A mismatch is dead-lettered with no tenant attached, so the claimed tenant never sees it. |

Database classification was extended to the 10 new tables (`test_db_security.py`). The new `nocsoc_worker` role is tested to see nothing without a tenant context, to be unable to write another tenant's rows, and to have no access to secrets, users, sessions or audit tables.

## Test results (all green)

| Suite | Count | Runs against |
|-------|-------|--------------|
| Backend unit + integration (`pytest backend`) | 128 | Disposable Postgres 17, Valkey, Redpanda and ClickHouse containers; real migrations and seed |
| Connector SDK, catalog, runner | 35 + 71 + 16 | In-process sandbox simulators |
| Compose policy (`tests/security`) | 11 | — |
| Frontend unit (`vitest`) | 47 | — |
| Browser journeys (`pnpm e2e`) | 22 | Live dev stack (core + stream + analytics profiles) in Microsoft Edge, including axe WCAG 2.1 AA checks |
| CI gates (`scripts\ci.ps1`) | 14/14 | ruff, mypy strict, import-linter (5 contracts), bandit, pytest, OpenAPI drift, pip-audit, eslint, typecheck, vitest, npm audit, next build, compose policy, gitleaks |

## Delivered

**Connector SDK v1.0 (`connectors/sdk`).** This covers:
- the manifest and normalized record types (Alert, Asset, VulnFinding, OCSF-aligned SecurityEvent, MetricPoint, Ticket)
- an error taxonomy that maps to health states
- a sandbox transport with fault injection (latency, errors, rate limits, auth failure, schema drift)
- an SSRF-guarded HTTP transport, reserved for later live use
- webhook signing, guarded actions that cannot run live, and the ContractSuite

**16 sandbox connectors (`connectors/catalog`).** SolarWinds, Datadog, Prometheus, Grafana, CloudWatch, Azure Monitor, Google Cloud Ops, Sentinel, Splunk, Wazuh, CrowdStrike, Defender, Qualys, Tenable, ServiceNow, plus a generic webhook. Each has a deterministic vendor-shaped simulator, normalize, scenario records and golden tests.

**Seven scenario packs.** Core switch failure, database saturation, phishing to credential misuse, ransomware precursor (joint NOC/SOC), KEV exposure, flapping/duplicate noise, and adversarial prompt-injection text.

**Connector runner (`connectors/runner`).** It works as follows:
- polls the API's internal work endpoint (shared runner token)
- fetches due streams and publishes CloudEvents-shaped envelopes
- advances checkpoints only past published records
- keeps a breaker per stream with exponential backoff and a token bucket per source
- reports health as the worst of the instance's streams
- resets the breaker when an instance's configuration changes

**Ingest worker (`app.workers.ingest`).** Each message goes through these steps:
- consumed with manual commits
- size and depth limits applied
- ownership verified
- normalized
- recorded in the idempotency ledger, which the worker prunes hourly (7-day retention)
- stored: alerts de-duplicated by fingerprint, assets resolved by identifiers (with advisory locks), vulnerability findings, then telemetry in ClickHouse
- `alerts.upserted` published

**Data stores.**
- Migration `0002` adds ten tables, all with FORCE RLS, plus narrow SECURITY DEFINER functions for cross-tenant lookups.
- ClickHouse has `raw_events` (7-day TTL), `security_events` (30 days) and `metrics` (14 days). Users are split into INSERT-only and SELECT-only, with tenant row policies.
- There are 16 raw topics plus `alerts.upserted` and `dlq.raw`.

**API (22 new operations).**
- Connector definitions, instances (CRUD with optimistic concurrency), write-only credentials and webhook secret rotation (both step-up), connection test, sync, runs, dead letters, scenarios and replay.
- Alerts (list, filter, summary, triage transitions, raw evidence), assets and vulnerabilities.
- Canonical events search.
- Runner endpoints and HMAC webhook ingress.
- Operator dependency status.

**Cross-cutting additions** (from your backend brief): structured JSON logging with request IDs and a secret scrubber, a tenant-scoped Valkey cache for alert summaries (invalidated on writes), per-tenant budgets for heavy endpoints, and DEMO sandbox integrations in the seed.

**Frontend.**
- The Integrations page shows the catalog, instance configuration, write-only secrets, runner-reported health, runs and scenario replay.
- NOC alerts, SIEM and vulnerability screens read pipeline data when it exists, with a SANDBOX provenance badge, and fall back to the labelled DEMO data otherwise.
- No instance is ever shown as healthy until the runner has reported a real run.

**Infrastructure.**
- Compose `stream` and `analytics` profiles with pinned Redpanda and ClickHouse images, plus migrate-stream, ingest-worker and connector-runner, all with memory caps and localhost-only ports.
- `dev.ps1 up` now starts core, stream and analytics.
- Bootstrap generates the five new secrets.

## Issues found and fixed during the phase

- The worker role had no `CONNECT` grant on the database. Integration tests caught it.
- A shared per-instance breaker counted two failures per tick (one per stream). It is now per stream, and the instance reports its worst state.
- Schema drift did not affect health because fetches still succeed. The runner now pre-checks records with the pure normalizer and reports *degraded*. Drifted records are still published so the worker dead-letters them as evidence.
- jsonschema error messages can quote the value, so credential validation errors now name only the field and the failed rule.
- The idempotency ledger had a cleanup function that nothing called. The worker now prunes it hourly.

## Residual risks and follow-ups

1. **Per-tenant ingest quotas** are missing (SEC-CON-04, partial). One noisy tenant can consume worker throughput. Target: P3.
2. **Runner credentials over the internal network.** The runner fetches decrypted sandbox credentials over plain HTTP on the compose network with a shared token. That is acceptable for sandbox data. Before any live connector (P8 gate), this needs mTLS or per-instance short-lived tokens, plus OpenBao/KMS.
3. **Telemetry is best effort.** A ClickHouse outage is logged, and those telemetry rows are skipped. Alerts, assets and findings in Postgres are unaffected. Raw records stay on the bus for 24 hours, so they can be replayed.
4. **Ownership-mismatch dead letters have no tenant**, so only platform operators can see them. That is intended, so that a forged message cannot plant entries in a victim's view.
5. **CSV export escaping** (SEC-CON-05) is pending until exports exist (P7).

## Running it

```powershell
scripts\bootstrap.ps1          # generates new secrets (kept if they exist)
scripts\dev.ps1 up             # core + stream + analytics
scripts\dev.ps1 seed           # includes DEMO sandbox integrations
```

Then go to **Integrations** and replay a scenario. Alerts appear in the NOC and SOC queues within a few seconds. To inject a fault, edit an instance's `sandbox_faults` (for example `{"error_rate": 1}`) and watch its health change.

## Next: P3 (needs your go-ahead)

P3 covers incident management, correlation and the core portal workflows. It will also carry the per-tenant ingest quota from residual risk 1. Problems, changes, AI investigations, automation workflows and approvals from your backend brief follow in P3–P6, as in the approved plan.
