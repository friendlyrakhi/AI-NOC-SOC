# Connector authoring guide

How to add a connector to the catalog. The full contract is in [06-connector-sdk.md](../06-connector-sdk.md); this guide is the practical path, using the Prometheus connector (`connectors/catalog/src/nocsoc_connectors/observability.py`) as the worked example.

**Ground rules.** These hold until P8 is approved:
- Every connector starts at certification level `sandbox`. It talks only to its built-in simulator.
- Live calls and live actions are blocked by the SDK; you cannot switch them on from a connector.
- Never fabricate a "live" status.
- Connectors live in this repository. Nothing is installed at runtime.

## 1. What you write

| Piece | Where | Purpose |
|-------|-------|---------|
| Manifest | `nocsoc_connectors/manifests/<id>.yaml` | Identity, streams, auth types, actions and their tiers, severity map, config and secret schemas |
| Simulator | `class <Name>Simulator(Simulator)` | Realistic vendor-shaped payloads for the sandbox, including scenario steps |
| Connector | `class <Name>(Connector)` | `streams` (paging rules), `normalize()`, and optionally `parse_webhook()` |
| Registration | `REGISTRY` in `nocsoc_connectors/__init__.py` | Makes the connector visible to the API, runner and ingest worker |
| Golden file | `connectors/catalog/tests/golden/<id>.json` | Expected normalized output for a fixed sandbox seed |

## 2. Manifest

Copy an existing manifest and change it:

```yaml
id: prometheus                # lower case, dots allowed: vendor.product
name: Prometheus / Alertmanager
category: observability       # observability | security | cloud | itsm | vulnerability | other
certification: sandbox        # never edit by hand to live-verified; that is the P8 process
auth_types: [none, bearer]
streams:
  - {name: alerts, domain: noc, output: alert@1, default_interval_seconds: 60}
  - {name: metrics, output: metric@1, default_interval_seconds: 60}
webhook: true                 # only if parse_webhook() is implemented
actions:
  - {key: am.create_silence, tier: T1, reversible: true}
severity_map: {critical: critical, page: critical, error: high, warning: medium, info: info}
config_schema: {...}          # JSON Schema; validated on every create or update
secrets_schema: {...}         # JSON Schema; values are write-only and envelope-encrypted
```

Rules:
- `secrets_schema` lists every credential. Credentials never go in `config_schema`, which is readable through the API.
- Action tiers follow docs/02 §6:
  - T0 is read-only.
  - T1 is low impact and reversible.
  - T2 needs one approval.
  - T3 needs two approvers.
  - Pick the higher tier when in doubt.

## 3. Normalization

`normalize(stream, record)` is a **pure function**: no I/O, no clock, no randomness. It runs inside the ingest worker on untrusted vendor data, so:
- Use `require(payload, "field", ...)` for fields you depend on. A missing field raises `SchemaDriftError`; the record is then dead-lettered (visible to the tenant, replayable) instead of being half-stored.
- Return canonical records only: `AlertV1`, `AssetV1`, `SecurityEventV1`, `MetricPointV1`, `VulnFindingV1`, `ServiceV1`, `TicketV1`.
- `dedup_key` on alerts must be stable for "the same problem". Repeats then increase the occurrence count instead of creating new alerts.
- Map vendor severities through `manifest.severity_map`, never ad hoc.
- Keep vendor text as data. It is shown escaped in the UI and passed to the AI only as delimited, untrusted evidence. Do not build HTML or queries from it.

## 4. Webhooks

Implement `parse_webhook(body)` if the vendor can push. The platform does the security work before your code runs:
- HMAC-SHA256 signature over `timestamp.nonce.body`;
- 5-minute clock skew and single-use nonces;
- per-instance rate limit, size limit (1 MB) and JSON depth limit.

Your job is to turn the vendor's body into `(stream, RawRecord)` pairs; normalization then runs as usual.

## 5. Simulator and scenarios

The simulator must produce payloads with the vendor's real field names and shapes, taken from the vendor's public API documentation (cite it in `docs_reference`). Scenario steps (`scenario_items`) let the platform replay cross-tool stories such as `core_switch_failure` and `phishing_credential_misuse`. Add your connector to the scenarios where the vendor plays a role.

## 6. Tests you must pass

```powershell
uv run pytest connectors -q
```

| Test | What it proves |
|------|----------------|
| `test_contract[<id>]` | The manifest is valid, every stream pages and checkpoints, and normalize returns canonical records |
| `test_live_mode_needs_a_runner_supplied_transport` | Live mode cannot be reached from the connector |
| `test_actions_are_simulated_and_live_is_blocked` | Actions run only in simulate or dry-run mode |
| `test_schema_drift_is_detected_by_normalize` | Missing fields raise drift instead of storing partial data |
| `test_golden.py` | Output for the fixed seed matches the golden file. After an intended mapping change, regenerate with `uv run python connectors/catalog/tests/test_golden.py --regen` and review the diff |

Then run the integration suite (`uv run pytest backend/tests/integration/test_ingestion.py -q`). It replays scenarios through the real bus and ingest worker.

## 7. Checklist before review

- [ ] Manifest: `certification: sandbox`, `docs_reference` filled in, credentials only in `secrets_schema`.
- [ ] `normalize` is pure and uses `require`. `dedup_key` is stable.
- [ ] Action tiers reviewed (T2 or higher for anything that changes a customer system).
- [ ] Contract, golden and ingestion tests pass. Coverage of the new module is at least 80 %.
- [ ] No vendor credentials or real tenant data in fixtures, golden files or logs.
- [ ] `docs/06-connector-sdk.md` §8 catalog table updated.

Promotion to `live-verified` is a separate, approved activity (P8). It needs vendor sandbox credentials from you, a real transport, and a recorded `VERIFICATION.md`.
