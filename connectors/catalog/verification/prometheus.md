# Live verification: `prometheus` (Prometheus / Alertmanager)

Status: **live-verified** · Date: 2026-11-17 · Procedure: `python scripts/verify_live.py` (ADR-0019)

## Target

| | |
|---|---|
| Vendor software | Prometheus **3.7.3** and Alertmanager **0.29.0** (official open-source images, pinned by digest) |
| Deployment | Real binaries in the compose `verify` profile, on the internal `vendors` network. Prometheus scrapes itself and Alertmanager; one rule always fires and is delivered to Alertmanager. |
| Credentials | None (private network, no authentication), so plain `http` was used with an operator allow-list entry and `allow_http`. Bearer tokens are supported for deployments behind a reverse proxy; they are never sent over `http`. |
| Platform | Throwaway hardened stack: TLS between services, OpenBao with Shamir unseal (3 shares, threshold 2, root token revoked), `NOCSOC_LIVE_READ_ENABLED=true`, allow-list `prometheus-demo,alertmanager-demo` |

## Streams and results

| Stream | Real API | Result |
|--------|----------|--------|
| `alerts` | Alertmanager `GET /api/v2/alerts?active=true&silenced=false&inhibited=false` (JSON array of alert objects) | The real `VerificationAlwaysFiring` alert arrived as a platform alert: title from `alertname` and summary, severity `warning` → `medium` (manifest `severity_map`), status `new`, de-duplication key `prometheus:<fingerprint>` |
| `metrics` | Prometheus `GET /api/v1/query?query=up` (instant vector) | 3 `up` samples stored in ClickHouse `metrics` |

- The runner reported the instance **healthy**.
- There were **no dead letters**: the normaliser accepted every real record, with no schema drift.

## Gates checked in the same run

- A live instance is refused without step-up (`auth.step_up_required`).
- A live instance of a sandbox-only connector is refused (`connector.live_unsupported`).
- Creating a live instance is audited (`connector.create`, `mode: live`).
- The connector never writes: the sandbox transport is closed in live mode, and actions remain simulated (guardrail #2).

## Differences found and handled

- **Response format.** Alertmanager v2 returns a bare JSON array. The sandbox simulator wraps items in `{data: [...]}`, so the live path reads the array directly.
- **Metric values.** Prometheus instant queries return `value` as `[timestamp, "string"]`. The live path converts it to the simulator's `{metric, ts, value: float}` sample shape before normalisation.
- **Resolved alerts.** Alertmanager does not list resolved alerts. The live pull therefore reports active alerts only; resolution arrives through the Alertmanager webhook (`webhook_config`), which the connector already supports.

No credentials, tenant data or customer host names are recorded here.
