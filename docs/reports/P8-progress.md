# P8 progress: live connector verification

Status: **in progress** (approved 2026-11-17). Design: ADR-0019. Hand-over per vendor: `docs/operations/p8-vendor-onboarding.md`.

## Done

| Item | Evidence |
|------|----------|
| Shamir unseal: 3 shares, threshold 2, root token revoked after setup | `scripts/openbao.ps1`, `app/tools/openbao_setup.py`; exercised by `scripts/verify_live.py` |
| Live-read gate: platform switch, vault mode, connector support, step-up, audit, runner re-check | `backend/tests/integration/test_live_read.py`; DB check allows only `sandbox` and `live` |
| Egress control (`LiveHttp`, `check_egress`) | `connectors/catalog/tests/test_live_read.py` (11 tests) |
| Live connectors cannot write; actions stay simulated (guardrail #2) | `test_live_read.py::test_prometheus_live_detects_drift_and_never_writes`, unchanged execution modes |
| Certification rule: `live-verified` needs a verification record | `test_contract.py::test_certification_follows_adr_0019` |
| **Prometheus / Alertmanager live-verified** (3.7.3 / 0.29.0) | `connectors/catalog/verification/prometheus.md`, `reports/live-verification-prometheus.json` (10 of 10 checks) |
| P2 fix: deleting an integration failed (no DELETE grant on `secrets`) | migration 0010 |

## Waiting on you

Each vendor below needs a trial or read-only account that **you** create, with the credentials entered by you in the platform (never in chat). Send only the non-secret details listed in the onboarding table.

| Vendor | Connector | Next step |
|--------|-----------|-----------|
| ServiceNow (Personal Developer Instance) | `servicenow.itsm` | Instance URL; I write `fetch_live` for the Table API |
| SolarWinds Orion | `solarwinds.orion` | Host, version, port 17774 reachability |
| Qualys VMDR | `qualys.vmdr` | API server for your platform |
| Tenable | `tenable` | Cloud or Security Center |
| Rapid7, Securonix, Autotask, ManageEngine | new connectors | Product, edition, region or URL |

No connector is marked `live-verified` until it has run against your real endpoint (guardrail #1).
