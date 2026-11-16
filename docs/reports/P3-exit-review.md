# P3 Exit Review: Incident management, correlation, core portal workflows

Date: 2026-11-16 · Status: **ready for your review**

All data in this phase still comes from **sandbox** connectors. The ServiceNow integration is a simulated action through the sandbox connector: nothing leaves the platform.

## Exit criteria (docs/08-implementation-plan.md §P3)

| Criterion | Result | Evidence |
|-----------|--------|----------|
| Scenario 1 → a single NOC incident with the correct impacted services | **Pass** | `test_incidents.py::test_scenario_1…`, run through the real pipeline (replay → Redpanda → worker → Postgres). Result: one NOC incident, P1, all 8 alerts, impacted services **Payments** and **Order Management** (the services behind the core switch). |
| Scenario 4 → a **joint** incident visible in both portals | **Pass** | `test_scenario_4…`: domain `joint`, impacted service File Services, present in both the `portal=noc` and `portal=soc` views, with an escalation entry on the timeline. E2E: the same incident number appears in both views, and the analyst works it through the UI. |
| Correlation precision ≥ 0.9 / recall ≥ 0.8 on the seeded scenarios | **Pass (1.0 / 1.0)** | `test_correlation.py` replays all 7 scenario packs as independent events. It also replays them in 40 shuffled arrival orders, because partitions deliver alerts in any order, and asserts the same result every time. |
| MTTA/MTTR computed correctly | **Pass** | An exact hand-computed case (`test_mtta_mttr_and_sla_attainment_are_exact`). The lifecycle test checks acknowledged and resolved timestamps, including that a reopen clears the resolution. The API metrics match SQL over controlled timestamps. |
| Alert-to-UI latency < 5 s | **Pass** | E2E: a signed webhook alert appears in an already-open NOC alert view via SSE within the 5 s assertion. That covers the API, Redpanda, the worker, Postgres, Valkey pub/sub, the SSE proxy and the page refresh. |
| Queue smooth at 10k rows | **Not verified** | Lists are paginated on the server (at most 200 rows per page, with a total count) and the indexes support the list query. **No 10k-row load test was run.** This is scheduled with the P6 performance work. |
| axe: no serious or critical violations on P3 pages | **Pass** | E2E axe checks on incident detail, incidents, topology, service detail and maintenance, plus the existing light and dark checks. |

## Correlation design

The rules are deterministic and explainable (`app/incidents/correlation.py`):
1. **Same asset** (any domain, 60 min). If the alert comes from the other domain, the incident becomes **joint**.
2. **Service topology** (NOC alerts, 30 min). The alert's asset runs, or supports, a service the incident already impacts. The topology comes from the ServiceNow sandbox CMDB stream (new SDK type `ServiceV1`, SDK 1.1).
3. **Shared observable** (SOC alerts, 60 min). The alert shares a user, IP, hash or host with the incident.

A medium, low or info alert never opens an incident on its own, which is why the noise scenario opens none.

Making correlation order-independent took two additions. Both were found when the real pipeline produced two incidents for scenario 1:
- **Merging.** An alert that bridges several open correlation-created incidents merges them into the oldest one. The merged incident is closed and marked `merged_into_id`, so it does not count in KPIs. Both timelines record the merge, and analyst-declared incidents are never merged automatically.
- **Absorption.** When an incident opens or grows, recent unlinked alerts that now match it are pulled in. This covers medium alerts that arrived before any incident existed.

Every link records its rule and a reason sentence, which the incident's Alerts tab and timeline show. Per-tenant overrides (enable/disable and window) need step-up.

**Limitation (measured):** when all seven scenarios fire at the *same moment* in one tenant, pairwise precision drops to **0.63** (recall stays 1.0). Two things cause this:
- Core switch and database saturation share Order Management infrastructure, so they merge.
- The adversarial-injection alert shares the user `j.doe` with phishing, so it joins that incident.

Both merges can be argued for in practice, but they are not what the scenario labels expect. Improving this (for example root-cause scoring, or limiting topology joins to a shorter window) is a candidate for P4, when the AI engine can weigh evidence.

## Test results (all green)

| Suite | Count | Runs against |
|-------|-------|--------------|
| Backend unit (`pytest backend/tests`) | 34 | Pure correlation engine, SLA and MTTA/MTTR, logging, guardrails |
| Backend integration | 137 | Disposable Postgres, Valkey, Redpanda and ClickHouse. New tests cover the real-pipeline scenarios, the lifecycle, maintenance and suppression, ServiceNow two-way sync, live events, SSE tenant isolation, the ingest quota, search and RBAC |
| Connector SDK, catalog, runner | 35 + 71 + 16 | In-process sandbox simulators (ServiceNow CMDB golden file regenerated) |
| Compose policy | 11 | — |
| Frontend unit (`vitest`) | 50 | — |
| Browser journeys (`pnpm e2e`) | 26 | Live dev stack in Microsoft Edge |
| CI gates (`scripts\ci.ps1`) | 14/14 | Includes bandit, gitleaks and OpenAPI drift |

## Security

- **Isolation.** The generated cross-tenant suite now has Initech-owned incidents, tasks, services, assets, maintenance windows and suppression rules. Every ID-taking route refuses Globex, and Initech's rows are unchanged afterwards. All 12 new tables are FORCE RLS and classified in `test_db_security.py`.
- **Append-only timeline.** No role, app or worker, has UPDATE or DELETE on `timeline_entries`, and a test proves it.
- **Live updates.** Live updates use a per-tenant Valkey channel, and the SSE endpoint subscribes only to the caller's tenant. Events carry only ids and types, and the browser reads them through a BFF proxy, so the session token never reaches client code. A test shows that another tenant's events never arrive.
- **Content as data.** Comments and alert text render as plain text, and a test stores a `<script>` comment and gets it back verbatim.
- **Assignees.** Assignees must be active members of the tenant.
- **Step-up.** Changing correlation rules or the SLA policy needs a recent step-up. Escalation and ITSM sync have their own permissions (`incident:escalate`, `incident:sync`).
- **ServiceNow loop prevention.** The platform remembers the state it last pushed. An inbound update with that state is an echo: it is recorded but changes nothing. A genuine change in ServiceNow (for example, resolved there) is applied exactly once.
- **Per-tenant ingest quota** (P2 residual risk 1, closed). Over-quota records go to the dead-letter queue as `quota_exceeded`, where the tenant can see and replay them. The default is 6,000 records per minute. If Valkey is down, the quota check fails open and logs it.

## Delivered

**Backend**
- Migration `0003`.
- The correlation engine, run inside the ingest transaction under a per-tenant advisory lock.
- The incidents API: lifecycle, timeline, tasks, alert links, escalation, the ServiceNow ticket, metrics, correlation rules and SLA policy.
- Services and topology, maintenance windows, suppression rules, full-text search, and SSE `/stream`.
- The worker now publishes live events and enforces the ingest quota.

**Frontend**
- **Incidents.** Real incidents appear first, with MTTA, MTTR and SLA KPIs, a NOC/SOC/all filter and a "Declare incident" form. DEMO incidents keep their own labelled tab.
- **Incident detail.** Timeline, alerts with the rule that linked each one, tasks, SLA clocks, status changes, assign to me, escalation, comments, and the ServiceNow ticket.
- **New NOC pages.** *Services & topology* (with service detail) and *Maintenance & noise control* (windows, suppression, correlation rules).
- **Navigation.** New entries: NOC Incidents, SOC Cases, Services & topology, Maintenance.
- **Alert queues.** These show the incident and service for each alert.
- **Live updates.** A "Live" status indicator on incidents, alerts and topology.
- **Global search.** Includes ingested data (SANDBOX).

**Connectors.** SDK 1.1 adds `ServiceV1`. The ServiceNow sandbox gains a `cmdb_services` stream and per-incident simulated ITSM actions.

## Residual risks and follow-ups

1. **No 10k-row queue load test.** Target: P6 performance work.
2. **Concurrent-scenario precision is 0.63.** See the correlation design above. Target: P4 evidence weighting.
3. **No SSE connection limit per tenant.** Streams are capped at 30 minutes each, but nothing bounds how many a tenant opens. Add a per-tenant concurrent-stream budget before multi-tenant load testing.
4. **No asset-to-asset topology.** Service dependencies stand in for a general `asset_relations` graph. Add the graph when a CMDB source provides relations beyond services.
5. **Endpoints still deferred:** incident merge by an analyst and the PIR endpoints (P4), and the vulnerability triage endpoints (`PATCH /vulnerabilities/findings/{id}` and the summary). The findings list from P2 is unchanged.

## Next: P4 (needs your go-ahead)

P4 is the AI intelligence engine: a model-agnostic gateway, alert and incident summaries grounded in evidence with citations, RCA drafts, and prompt-injection defenses. The adversarial-injection scenario pack is already in place for testing it.
