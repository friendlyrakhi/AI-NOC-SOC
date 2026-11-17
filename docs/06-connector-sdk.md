# 06 — Connector SDK Specification

Package: `nocsoc-connector-sdk` (Python 3.12, in `connectors/sdk/`). SDK version is semver. Connectors declare the SDK range they support.

## 1. Design principles

1. **One contract for all vendors.** A connector is a manifest, a config schema, a client, mappers and fixtures. Core code never special-cases a vendor.
2. **Sandbox first.** Every connector must ship a `SandboxTransport` backed by fixtures. The real HTTP transport can be added later without changing the connector logic.
3. **Pure normalization.** `normalize()` is deterministic and side-effect-free, so it can run with a time limit inside the ingest-worker and be golden-tested.
4. **Least privilege.** The manifest declares the vendor API scopes needed per capability. Read and act capabilities are declared separately so tenants can grant read-only.
5. **No fabricated live behavior.** Live transports are written against public vendor API docs, marked `certification: sandbox` until they are proven against a real endpoint, and are never presented as working before that.

## 2. Package layout per connector

```
connectors/catalog/crowdstrike_falcon/
├─ manifest.yaml
├─ config.schema.json          # non-secret config (JSON Schema 2020-12)
├─ secrets.schema.json         # secret fields (client_id/secret, api key…)
├─ connector.py                # class CrowdStrikeFalcon(Connector)
├─ mappers/
│  ├─ detection_to_ocsf.py
│  └─ host_to_asset.py
├─ actions.py                  # declared actions (simulate implementation required)
├─ fixtures/
│  ├─ detections_page1.json    # synthetic, vendor-shaped records (no real customer data)
│  └─ scenarios/ransomware_precursor.yaml
└─ tests/
   ├─ test_contract.py         # uses sdk.testing.ContractSuite
   └─ golden/                  # input → expected normalized output
```

## 3. Manifest

```yaml
id: crowdstrike.falcon
name: CrowdStrike Falcon
vendor: CrowdStrike
category: edr                     # observability | siem | edr | vuln | itsm | cloud_monitoring
version: 0.1.0
sdk: ">=1.0,<2.0"
certification: sandbox            # sandbox | contract-tested | live-verified
docs_reference: "Vendor public API documentation (link recorded at implementation time)"
auth:
  types: [oauth2_client_credentials]
streams:                          # pull capabilities
  - name: alerts
    domain: soc
    cursor: { type: timestamp, field: updated_timestamp }
    default_interval: 60s
    output: ocsf.detection_finding@1
  - name: assets
    cursor: { type: timestamp }
    default_interval: 1h
    output: asset@1
push:
  webhook: { supported: false }
actions:
  - key: edr.isolate_host
    tier: T3
    reversible: true
    reverse: edr.release_host
    params_schema: { $ref: actions/isolate_host.schema.json }
    required_scopes: ["hosts:write"]
  - key: edr.release_host
    tier: T2
required_scopes:
  read: ["alerts:read", "hosts:read"]
severity_map: { 1: info, 2: low, 3: medium, 4: high, 5: critical }
rate_limits: { requests_per_minute: 100 }
```

## 4. Python contract

```python
class Connector(ABC):
    manifest: Manifest

    def __init__(self, ctx: ConnectorContext, config: Config, secrets: SecretBundle,
                 transport: Transport): ...

    # Lifecycle
    async def validate_config(self) -> list[ConfigIssue]: ...
    async def test_connection(self) -> ConnectionResult: ...        # auth + minimal read; no side effects
    async def discover(self) -> DiscoveryResult: ...                # optional: available streams/scopes

    # Pull
    async def fetch(self, stream: str, checkpoint: Checkpoint | None,
                    budget: FetchBudget) -> FetchResult: ...        # records + next checkpoint + has_more

    # Push (optional)
    def verify_webhook(self, headers: Mapping[str, str], body: bytes) -> bool: ...
    def parse_webhook(self, headers, body) -> list[RawRecord]: ...

    # Normalization (pure, sync, deterministic)
    @staticmethod
    def normalize(stream: str, record: RawRecord) -> list[NormalizedRecord]: ...

    # Actions (optional)
    async def execute_action(self, action: ActionInvocation) -> ActionResult: ...
        # ActionInvocation.mode in {"dry_run","simulate","live"}; base class enforces policy below
```

Key types:
- `ConnectorContext`: tenant_id, instance_id, logger (secret-scrubbing), tracer, clock, `mode` (`sandbox|live`).
- `Transport`: an abstraction over HTTP with `SandboxTransport` (serves fixtures, can inject faults) and `HttpTransport` (httpx, timeouts, retries with jittered exponential backoff on 429/5xx, honors `Retry-After`, SSRF guard, egress-proxy aware).
- `FetchBudget`: max records, max duration, max bytes, so one connector can't starve others.
- `RawRecord`: `{source_id, observed_at, payload: dict, schema: "crowdstrike.detection@1"}`.
- `NormalizedRecord`: a discriminated union of `AlertV1 | OcsfEvent | OpsEventV1 | MetricPoint | AssetV1 | VulnFindingV1 | TicketV1`.
- `ActionResult`: `{status, mode, simulated: bool, before, after, vendor_ref?, message}`.

### Base-class enforcement (not overridable)
- `execute_action` wrapper: if `mode == "live"` and (`ctx.mode != "live"` **or** `PLATFORM_EXECUTION_MODE != "live"` **or** `certification != "live-verified"`), raise `ExecutionDisabled`. In Phases 0–7 `PLATFORM_EXECUTION_MODE` is fixed to `simulate`.
- `simulate` mode requires a `simulate_<action>()` implementation that returns plausible before/after state from fixtures. It must never touch the network.
- All outbound HTTP goes through `Transport`; the contract suite fails if the connector imports `requests`/`httpx`/`socket` directly.

## 5. Runtime (connector-runner)

- **Scheduler:** for each enabled instance and stream, runs on an interval with jitter; one in-flight fetch per (instance, stream); a global concurrency cap.
- **Checkpointing:** the checkpoint is saved after the Kafka produce succeeds (at-least-once).
- **Resilience:** a per-instance circuit breaker (open after N consecutive failures; half-open probe), and a token-bucket rate limiter per instance, seeded from the manifest's `rate_limits`.
- **Health model:** `healthy` → `degraded` (partial failures, lag > threshold) → `failing` (circuit open/auth errors) → `disabled`. Emits `connector.health` events and `connector_metrics`.
- **Isolation:** non-root container, read-only FS, no data-store network access, egress only via an allowlist proxy (dev: sandbox mode has **no** egress at all). Secrets are fetched per instance from the API's internal endpoint with the runner's service identity and kept only in memory.
- **Error taxonomy:** `AuthError`, `PermissionError`, `RateLimited`, `TransientError`, `SchemaDrift` (vendor payload no longer matches the expected schema, so records go to the DLQ and an alert is raised), `ConfigError`.

## 6. Sandbox mode

- `SandboxTransport` serves vendor-shaped synthetic fixtures with pagination, cursors and realistic timestamps (shifted to "now" on replay).
- **Scenario packs** (`fixtures/scenarios/*.yaml`) describe timed sequences across connectors, e.g. the ransomware precursor that touches CrowdStrike, Wazuh, Datadog and ServiceNow. A scenario orchestrator replays them coherently.
- **Fault injection** settings: latency, 429 bursts, 5xx, auth expiry, malformed records and schema drift, used to test health handling.
- All sandbox data is synthetic. **No real customer data or real vendor credentials go in fixtures**, and fixture payload shapes are modeled on public API documentation.

## 7. Certification levels

| Level | Requirements | Allowed modes |
|-------|--------------|---------------|
| `sandbox` | Manifest valid; ContractSuite passes against `SandboxTransport`; golden normalization tests; simulate implementations for all actions | sandbox |
| `contract-tested` | + `HttpTransport` implemented against public API docs; recorded/replayed HTTP contract tests (VCR-style cassettes built from **documented** example responses); SSRF/timeouts verified | sandbox |
| `live-verified` | + Successfully run against a real vendor tenant/trial **using credentials you provide**, read-only streams first; manifest `live_read: true` with a `fetch_live` over `LiveHttp` (ADR-0019); evidence recorded in `connectors/catalog/verification/<id>.md` (date, API version, scopes, what was tested; enforced by `test_certification_follows_adr_0019`) | sandbox, live (read). Live **actions** need a separate approval per action. |

## 8. Connector catalog (initial targets)

All start at `sandbox`. The vendor API surfaces listed are what the live transport will target. Exact endpoints and auth will be confirmed against vendor docs at implementation time.

| Connector ID | Category | Streams (pull) | Push | Actions (simulate only) |
|--------------|----------|----------------|------|-------------------------|
| `solarwinds.orion` | observability | alerts, nodes (assets), interface status | — | `nms.ack_alert` (T1), `nms.unmanage_node` (T2) |
| `datadog` | observability | monitors/events, metrics (query), hosts | webhook | `dd.mute_monitor` (T1) |
| `prometheus` | observability | alerts (Alertmanager), metrics (PromQL range) | Alertmanager webhook | `am.create_silence` (T1) |
| `grafana` | observability | alert instances, annotations | webhook (contact point) | `grafana.silence` (T1), `grafana.annotate` (T1) |
| `aws.cloudwatch` | cloud_monitoring | alarms, metrics, resource inventory | SNS → webhook | `aws.reboot_instance` (T2, sandbox) |
| `azure.monitor` | cloud_monitoring | alerts, metrics, resources | action group webhook | `azure.restart_vm` (T2) |
| `gcp.cloud_ops` | cloud_monitoring | incidents/alert policies, metrics, assets | Pub/Sub push → webhook | `gcp.restart_instance` (T2) |
| `microsoft.sentinel` | siem | incidents, alerts, entities | — | `sentinel.update_incident` (T1) |
| `splunk` | siem | notable events/alerts, saved-search results | HEC-style webhook | `splunk.update_notable` (T1) |
| `wazuh` | siem/xdr | alerts, agents | webhook (integration) | `wazuh.active_response` (T3) |
| `crowdstrike.falcon` | edr | detections/alerts, hosts | streaming (later) | `edr.isolate_host` (T3), `edr.release_host` (T2) |
| `microsoft.defender` | edr/xdr | alerts/incidents, devices | — | `mde.isolate_device` (T3), `mde.run_av_scan` (T2) |
| `qualys.vmdr` | vuln | detections (host vulns), assets | — | — |
| `tenable` | vuln | findings, assets | — | — |
| `servicenow.itsm` | itsm | incidents (bi-directional), CMDB CIs (read) | business-rule webhook | `itsm.create_incident` (T1), `itsm.update_incident` (T1), `itsm.create_change` (T1) |

Also included: **`generic.webhook`** (JSONPath-configurable mapping) and **`generic.syslog`** (later), so tools outside the list can be integrated without code.

## 9. Testing kit (`sdk.testing`)

- `ContractSuite`: generic pytest suite (manifest schema, config schema, fetch pagination/checkpoint monotonicity, normalize purity/determinism via Hypothesis, no direct network imports, action simulate coverage, secret non-leakage in logs).
- `GoldenRunner`: `fixtures/*.json` → `tests/golden/*.expected.json`.
- `FaultHarness`: run fetch under injected faults; assert health transitions and retry behavior.
- `ScenarioPlayer`: drives multi-connector scenarios for end-to-end tests.

## 10. Versioning & compatibility

- Normalized schemas are versioned (`alert@1`, `ocsf.detection_finding@1`). Additive changes are minor; breaking changes add `@2`, and the ingest-worker supports N and N-1.
- The connector version is recorded on every raw record for reproducibility.
