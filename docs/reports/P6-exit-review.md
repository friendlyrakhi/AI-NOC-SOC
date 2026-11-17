# P6 Exit Review: Executive Command Center, analytics, search and hunting

Date: 2026-11-17 · Status: **ready for your review**

The Command Center, Reports, Threat hunting and Investigate pages now run on real data. That data is the platform's own processing of sandbox connector data and DEMO seed content; no production system is connected. Every KPI links to the exact records it was computed from. Search and hunting use OpenSearch with per-tenant indices, and the store's security plugin is on. The AI daily briefing is cited like every other AI output.

## Exit criteria (docs/08-implementation-plan.md §P6)

| Criterion | Result | Evidence |
|-----------|--------|----------|
| Every KPI drillable to records; KPI values match a reference calculation in tests | **Pass** | `test_kpis_match_reference_calculation` compares all 9 KPIs with an independent Postgres calculation (P3's `compute_metrics` plus plain counts) for all, NOC and SOC. `test_every_kpi_drills_to_its_records` checks, for every KPI, that the drill-down lists exactly its basis and that the flagged records equal its numerator. MTTA and MTTR are re-derived from the listed durations. `test_drill_records_are_the_reference_records` shows the record ids are exactly the reference ids. E2E: a KPI tile opens the same number of records. |
| SEC-ISO-03 extended to OpenSearch | **Pass** | See "Isolation" below: 6 OpenSearch tests, a ClickHouse test, unit tests on the query façade, compose-policy rules and the extended route isolation suite. |
| Full profile memory within budget (≤ 10 GB) | **Pass** | Measured with all default profiles (core, stream, ai, workflow, search) running: **about 3.3 GB** of container memory. Largest: OpenSearch about 1.2 GB (512 MB heap), ClickHouse about 1.0 GB. |

## What was built

| Area | What it does |
|------|--------------|
| **Analytics facts** | ClickHouse `alert_facts`, `incident_facts` and `action_facts` (ReplacingMergeTree) are projected from Postgres, which stays authoritative. The **projector** runs in the ingest worker as the RLS-bound worker role. It visits each tenant only inside that tenant's context, with change capture on `updated_at`. Triggers keep `updated_at` current; moving an alert between incidents also counts as a change. Each sink (facts, search) keeps its own watermark per tenant and stream, so one store being down never stalls the other (tested). Each pass re-reads a 10-second overlap, and a resync every 15 minutes catches transactions that commit late. |
| **KPIs** | `GET /analytics/kpis`, `/analytics/kpis/{key}/records`, `/analytics/timeseries`, `/command-center/overview`, and `/command-center/customers` (MSP aggregate, read-only). The 9 KPIs: incidents opened, still open, MTTA, MTTR, acknowledge SLA, resolve SLA, automation rate, alert volume, noise ratio. Each returns its value, numerator and basis. |
| **Search** | OpenSearch 3.8.0, digest-pinned, security plugin on. Indices are `t-{tenant}-events-YYYY.MM` (canonical events, written by the ingest worker) and `t-{tenant}-entities` (alerts, incidents and assets, written by the projector). Retention: events are deleted after 30 days by an Index State Management policy. Global search uses OpenSearch when available and falls back to Postgres; the response says which engine answered. `POST /search/events` serves the Investigate page, with facets. |
| **Hunting** | Saved hunts are constrained event queries. Runs execute asynchronously and keep up to 200 hits plus facets. Per tenant, at most 2 run at once and 60 per hour. Results can be attached to an incident timeline. |
| **Reports** | Saved definitions: KPI summary, incident register, SLA report. Exports are computed fresh as CSV or PDF, audited, and downloaded through the web server so the session token never reaches the browser. CSV cells that look like formulas are neutralised. The PDF writer is dependency-free and escapes all text. New permission `report:create`; `report:read` can export. |
| **AI daily briefing** | New task `daily_briefing`, built from the last 24 hours' KPIs, open P1/P2 incidents and unescalated notable alerts. It goes through the same validator, citations, audit and budget as other AI output. Numbers cite the KPI they come from, and KPI evidence links to its drill-down. Executives can read the latest briefing; generating one needs `ai:use`. Eval: 2 new golden cases, one grounded and one degrading to insufficient evidence. |
| **UI** | Command Center with period switch, All/NOC/SOC KPI tabs, trend charts, major incidents and the briefing. KPI record pages. MSP customer comparison. Reports. Threat hunting. Investigate with facet pivots. Pages fall back to clearly labelled DEMO content only when the real source is unavailable. CSV downloads of real tables are now labelled `-SANDBOX` instead of `-DEMO`. |

## Isolation (SEC-ISO-03, threat model T8)

- **Index names come only from the authenticated tenant.** Clients never send an index, pattern or query DSL. `EventQuery` rejects unknown fields (`index`, `tenant_id`, `script`, ...), bad ATT&CK ids, invalid IPs and windows over 30 days (6 API tests, 7 unit tests).
- **Every query also filters on `tenant_id`.** A document planted in Globex's index claiming Initech is not returned to either tenant (`test_tampered_tenant_field_in_index_is_still_filtered`).
- **Least-privilege store users** (`test_opensearch_store_users_are_least_privilege`):
  - The API reads as `nocsoc_reader`, which has read on `t-*` only and cannot write.
  - The ingest worker writes as `nocsoc_indexer`, which has write on `t-*` only and cannot read.
  - Neither user can list indices, read the security index or touch other indices. Anonymous requests get 401.
  - Only the one-shot setup job holds the admin password.
- **Real cross-tenant data.** Both tenants replay the same scenario. Event search and global search return only the caller's tenant, verified against ClickHouse tenant ids.
- **ClickHouse.** The row policy now accepts a list of tenants for the MSP view. A query without the setting fails, and an empty list matches nothing (`test_clickhouse_facts_are_tenant_bound`).
- **Network and credentials (compose policy, 3 new tests).**
  - OpenSearch sits only on the internal `search` network, with no published ports.
  - Only `opensearch`, `opensearch-setup`, `api` and `ingest-worker` may join that network.
  - Each OpenSearch secret is held only by the services that need it. Connector runtimes cannot reach OpenSearch.
- **Route isolation.** The suite now covers hunts, hunt runs, reports and KPI keys. Four new tables are classified FORCE RLS; `projection_state` is worker-only.

## Test results

| Suite | Count | Notes |
|-------|-------|-------|
| P6 integration | 35 | Real Postgres, Valkey, Redpanda, ClickHouse and OpenSearch (security plugin on), the real ingest worker and projector |
| P6 unit | 24 | Query façade, index naming, ClickHouse tenant setting, KPI arithmetic, CSV neutralisation, PDF output |
| Compose policy | 27 | 3 new for search isolation |
| AI gateway and evals | 18 | Briefing task added to every gateway test; 13 golden cases |
| Browser journeys | 41 | 6 new P6 journeys with axe checks |
| Full CI | 13/13 gates green | 486 Python tests (all suites), 51 frontend unit tests; mypy, import-linter (7 contracts), bandit, OpenAPI drift, pip-audit, npm-audit, build, compose policy, gitleaks |

Accessibility fixes found by the new axe checks (pre-existing, now fixed): the "All customers · read-only" badge contrast, and underlines on inline links in the copilot's evidence list and suggested-action citations.

## Deviations from the plan

1. **One event index family.** docs/03 sketched separate `secevents` and `opslogs` indices. P6 indexes the canonical event model (P2) into one `events` family per tenant, with `domain` and `class` fields.
2. **Endpoint shapes.** `POST /search/events` (constrained `EventQuery`) and `GET /search` (global, now OpenSearch-backed) replace the single `POST /search` in docs/05. Hunting uses `/hunts` and `/hunt/queries`. Events need `search:read`; the planned `events:read` permission was not needed.
3. **Metrics query API.** `/metrics/query` is deferred: no P6 screen needs it yet.
4. **Telemetry outbox.** Event writes to ClickHouse and OpenSearch remain best effort after the Postgres commit (P2 residual risk). Facts and entities do not have this gap, because the projector re-reads Postgres. The outbox is moved to P7 hardening.

## Residual risks and follow-ups

1. **Dev-grade OpenSearch TLS.** The security plugin authenticates and authorises every call, but node transport uses the image's demo certificates and HTTP is plain inside the internal network. Real certificates come with P7's `hardened` profile (TLS between services, OpenBao).
2. **Projector freshness.** KPIs lag Postgres by up to about 5 seconds, plus the projector's pass time. The resync window (1 day, every 15 minutes) bounds the worst case for transactions that commit late.
3. **Hunt runs are in-process.** An API restart marks running hunts "Interrupted" after 5 minutes. A dedicated worker can take them over if hunting grows.
4. **Facts are not reconciled nightly.** Re-projection is idempotent, so a full resync is safe; scheduling one is a P7 operability item.
5. **Startup ordering.** The ingest worker may log a few search projection warnings until `opensearch-setup` has created its user. It recovers without intervention.

## Next: P7 (needs your go-ahead)

P7 covers hardening and operability:
- a threat-model re-review, DAST (OWASP ZAP) and API fuzzing (Schemathesis);
- an optional OIDC login, and a `hardened` profile with TLS between services and OpenBao;
- observability dashboards and SLOs;
- tested backup and restore, a k6 load test, operator docs, and the telemetry outbox.
