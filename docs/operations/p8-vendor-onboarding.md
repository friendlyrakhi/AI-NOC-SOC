# P8 vendor onboarding: what to provide for each live connector

Live connectors only **read** (ADR-0019). Live actions stay disabled. For each vendor, create a dedicated account with the **narrowest read-only role** the product offers, ideally in a trial, sandbox or non-production tenant.

**How to hand over credentials.** Enter them in the platform yourself, so they never pass through chat or files:
1. Connectors → Add integration → choose the connector → mode **Live** (needs a step-up code).
2. Then **Credentials**. Values are write-only, encrypted by OpenBao Transit, and shown nowhere afterwards.

Send me only the non-secret details (product, edition, version, URL pattern, whether it is on-premises) so I can confirm the API and the network path.

**Before the first live credential:** the platform must run the hardened profile with Shamir unseal:

```powershell
# in .env: NOCSOC_OPENBAO_UNSEAL=shamir and NOCSOC_LIVE_READ_ENABLED=true
scripts\dev.ps1 up -Hardened
scripts\openbao.ps1 init      # once; store the 3 shares apart, offline
scripts\openbao.ps1 unseal    # after every restart
```

**On-premises tools** (private addresses) also need their host names in `NOCSOC_EGRESS_PRIVATE_ALLOWLIST` (comma-separated, in `.env`). Public SaaS endpoints need nothing: `https` and public addresses are allowed by default.

| Vendor | Connector | Status | What to create (read-only) | What I need from you (not secret) |
|--------|-----------|--------|-----------------------------|-----------------------------------|
| Prometheus / Alertmanager | `prometheus` | **live-verified** against the real software (`connectors/catalog/verification/prometheus.md`) | Nothing for a local install. For yours: a reverse proxy with a bearer token, or none on a private network. | Alertmanager and Prometheus URLs; allow-list the hosts if private |
| ServiceNow | `servicenow.itsm` | Sandbox; live read to be built against your instance | A Personal Developer Instance (developer.servicenow.com, free). A user with the `snc_read_only` and `itil` roles, basic authentication. | Instance URL (`https://devNNNNN.service-now.com`); which tables (incident, problem, cmdb_ci) |
| SolarWinds Orion / Observability Self-Hosted | `solarwinds.orion` | Sandbox | An Orion account with read-only rights (no node management). The SWIS REST API on port 17774. | Host name; Orion version; confirm port 17774 is reachable from the platform host |
| Qualys VMDR | `qualys.vmdr` | Sandbox | A user with the **Reader** role and API access enabled | Your Qualys platform's API server (e.g. `qualysapi.qg2.apps.qualys.com`) |
| Tenable Vulnerability Management | `tenable` | Sandbox | A user with a read-only role; generate **API keys** (access key + secret key) | Cloud (`cloud.tenable.com`) or Tenable Security Center (on-premises URL)? |
| Rapid7 | new | Not yet in the catalog | **InsightVM** (on-premises console, API v3, basic auth with a read-only user) **or InsightIDR** (cloud, API key with read-only access) | Which product, and its region or console URL |
| Securonix SNYPR | new | Not yet in the catalog | A service account allowed to generate API tokens, with read access to incidents and violations | Tenant URL (`https://<tenant>.securonix.net/Snypr`); version |
| Autotask PSA | new | Not yet in the catalog | An **API-only user** with a read-only security level, plus your **API Integration Code** (tracking identifier) | Your Autotask zone (the `webservicesN` host); which entities (tickets, configuration items) |
| ManageEngine | new | Not yet in the catalog | Depends on the product. **OpManager**: an API key for a read-only user. **ServiceDesk Plus**: a technician API key (on-premises) or OAuth via Zoho (cloud). | **Which ManageEngine product(s)** and on-premises or cloud |

## What happens with each vendor

1. **Write `fetch_live`.** I write it against the vendor's **published** API for your edition, with unit tests on documented response shapes. It stays `contract-tested` until a real run.
2. **You create the live instance and enter the credentials** (above).
3. **First live pull.** I watch it through the integration's health, the dead-letter list and the ingest metrics. Differences from the documented shapes are fixed in the connector.
4. **Record and promote.** I write `connectors/catalog/verification/<id>.md`: date, product and version, streams, record counts, normalisation results and differences found, with no credentials, host names or customer data. The connector is then promoted to `live-verified`.

You can revoke a credential at any time at the vendor. The platform marks the instance as failing (authentication errors) and stops; nothing is retried in a loop.
