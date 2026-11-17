# Platform SLOs and observability

The `observability` profile (P7) runs Grafana LGTM: an OpenTelemetry collector, Prometheus, Tempo, Loki and Grafana in one container.

| What | Detail |
|------|--------|
| Start | `scripts\dev.ps1 up -Profiles core,stream,ai,workflow,search,observability`. The script switches telemetry export on in the services. |
| Grafana | http://127.0.0.1:3001. Anonymous visitors are read-only. The admin password is in `infrastructure/secrets/grafana_admin_password`. |
| Dashboard | **NOC/SOC platform → service health and SLOs**. Generated from `infrastructure/observability/make_dashboard.py`. |
| Rules | `infrastructure/observability/rules.yaml`, evaluated by Prometheus every 30 s and checked with `promtool` |
| Traces | Tempo (Grafana → Explore → Tempo). Every API request, ingest message, workflow and activity is a span. |
| Footprint | About 1.2 GB (limit 2 GB) |

## What is instrumented

| Service | Traces | Metrics |
|---------|--------|---------|
| API | Every request (FastAPI instrumentation, stable HTTP conventions). Outgoing Kafka messages carry `traceparent`. | `http.server.request.duration` (route, method, status) |
| Ingest worker | `ingest.process` span per raw message, continuing the producer's trace from the Kafka headers | `nocsoc.ingest.messages{result}`, `nocsoc.ingest.duration`, `nocsoc.ingest.latency` (connector emitted to stored), `nocsoc.outbox.pending`, `nocsoc.projector.rows/failures{sink,stream}` |
| Audit anchor | — | `nocsoc.audit_anchor.runs`, `nocsoc.audit_anchor.problems` |
| Workflow worker | Workflow and activity spans through the Temporal tracing interceptor (trace context in Temporal headers). Its calls back to the API carry `traceparent`. | — |

Log lines are JSON on stdout and carry `trace_id` when a span is active, so a log line can be matched to its trace.

## Objectives

| SLO | Objective | Indicator (Prometheus) | Alerts |
|-----|-----------|------------------------|--------|
| API availability | 99.5 % of requests are not server errors (30 days) | `1 - nocsoc:api_error_ratio:rate1h` | `ApiErrorBudgetFastBurn`: 14.4× burn over 1 h **and** 5 m (pages). `ApiErrorBudgetSlowBurn`: 6× over 6 h (ticket). |
| API read latency (NFR-1) | p95 of GET requests < 300 ms | `nocsoc:api_read_latency_seconds:p95_5m` | `ApiReadLatencyHigh` after 15 min |
| Ingest freshness (NFR-1) | p95 connector-to-stored < 5 s | `nocsoc:ingest_latency_seconds:p95_5m` | `IngestLatencyHigh` after 10 min (pages) |
| Telemetry delivery | No outbox row waits longer than 15 min | `max(nocsoc_outbox_pending)` | `TelemetryOutboxBacklog` |
| KPI and search freshness | Projection batches succeed | `nocsoc_projector_failures_total` | `ProjectorFailing` |
| Audit integrity | Zero mismatches between the audit log and its external anchors | `nocsoc_audit_anchor_problems_total` | `AuditAnchorMismatch` (pages immediately). `AuditAnchorStalled` if no check ran for 30 min. |

**Severity labels.** `page` means act now; `ticket` means within a working day. There is no Alertmanager in the dev stack: firing alerts are visible in Grafana (Alerting → Alert rules, data source Prometheus) and in Prometheus. Routing them to email or chat is a deployment decision.

**Error budget.** The 30-day budget panel shows how much of the 0.5 % allowance is left. When the budget is spent, reliability work takes priority over feature work.

## Notes

- 503 answers with a `*.disabled` code (a profile that is not running) count as server errors in the availability indicator. Run the profiles you rely on.
- Metrics are exported every 15 s, so a dashboard lags reality by up to about 30 s.
- Retention is whatever the LGTM container keeps in its `lgtmdata` volume. It is a development backend, not long-term storage.
