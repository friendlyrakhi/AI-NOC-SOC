# 09 — Risks & Dependencies

## 1. Risk register

Likelihood (L) and impact (I) are rated 1–5. Score = L × I.

| ID | Risk | L | I | Score | Mitigation | Owner/Trigger |
|----|------|---|---|-------|------------|---------------|
| R1 | **Scope too large for a single developer/PC.** Fifteen integrations, two portals, AI and workflows add up to a multi-team product. | 5 | 4 | 20 | Strict phase gates; modular monolith; sandbox-first; recommended connector order; defer OpenSearch to P6. | You, at each phase review |
| R2 | **RAM exhaustion** (15.6 GB) when running the full stack plus the IDE and browser. | 4 | 3 | 12 | Compose profiles with memory caps; `.wslconfig` limit; `doctor` script; avoid Ollama together with OpenSearch. | Measured at P0, P2 and P6 |
| R3 | **Tenant data leak** through a missed filter in a new code path. | 3 | 5 | 15 | RLS FORCE, fail-closed context, generated cross-tenant suite as a release gate, tenant-prefixed caches, CH row policies, per-tenant OS indices. | Every PR |
| R4 | **Accidental real-world action** (live remediation). | 1 | 5 | 5 | Hard-disabled `live` mode; SDK base-class enforcement; release-gate test; no real credentials until P8. | SEC-ACT-03 |
| R5 | **AI hallucination or ungrounded RCA** misleads analysts. | 4 | 4 | 16 | Citation validator; "insufficient evidence"; labeled AI content; evals; no autonomous action. | AI-7 evals |
| R6 | **Prompt injection through telemetry.** | 4 | 4 | 16 | Untrusted-data handling, no side-effecting tools, output validation, red-team corpus. | SEC-AI-01 |
| R7 | **Vendor API access.** Several vendors (CrowdStrike, Sentinel/Defender, Splunk Enterprise, Qualys, Tenable, SolarWinds, ServiceNow) need paid or partner accounts. Free trials and developer instances exist for some, but terms vary and change. | 4 | 3 | 12 | Sandbox-first design makes progress independent of access; P8 is scoped to whichever accounts you can obtain (e.g. ServiceNow PDI, cloud free tiers, self-hosted Prometheus/Grafana/Wazuh are the easiest). | P8 planning |
| R8 | **Vendor API drift.** Fixtures modeled on docs may differ from reality. | 3 | 3 | 9 | `SchemaDrift` handling + DLQ; certification levels; `VERIFICATION.md` records the tested API version. | P8 |
| R9 | **Licensing** of infrastructure components (see §3). | 3 | 3 | 9 | Choose permissive or clear licenses (Valkey, OpenSearch, Kafka option); keep the Kafka API abstraction; legal review before commercialization. | D-decisions |
| R10 | **Data egress to cloud LLMs** exposes sensitive telemetry. | 3 | 4 | 12 | Off by default; per-tenant opt-in; redaction; provider data-use terms reviewed by you. | D8 |
| R11 | **Operational complexity** of Temporal, Kafka, ClickHouse and OpenSearch for a small team. | 4 | 3 | 12 | Introduce each only in the phase that needs it; single-node dev configs; runbooks; consider Postgres-only fallbacks. | Phase starts |
| R12 | **Windows dev friction** (CRLF, bind-mount speed, file watching). | 3 | 2 | 6 | `.gitattributes`; optional WSL2 working copy; containerized tooling. | P0 |
| R13 | **Dev master key compromise** on the PC. | 2 | 3 | 6 | Mock data only until P8; OpenBao/KMS mandatory before real credentials. | P8 gate |
| R14 | **Correlation quality.** Rule-based grouping is too noisy or too coarse. | 3 | 3 | 9 | Golden scenarios with precision/recall targets; tunable rules; ML-based correlation deferred. | P3 |
| R15 | ~~Node 26 / Next.js compatibility~~ **Closed in P0:** Node 26 is LTS; Next.js 16.4.6 builds and runs on it. | — | — | — | `.nvmrc` = 26 | P0 |
| R17 | **TLS-inspecting antivirus** (Norton) breaks package downloads in containers. | 5 | 2 | 10 | Build-only CA bundle via BuildKit secret; uv system certs; documented alternative (scan exclusion). | P0 (mitigated) |
| R16 | **Single point of knowledge** (solo developer). | 3 | 3 | 9 | ADRs, docs-as-code, high test coverage, scripts for everything. | Ongoing |

**Top 5 to watch:** R1 (scope), R5/R6 (AI trust), R3 (isolation), R2 (resources), R7 (vendor access).

## 2. Dependencies

### 2.1 Software (all to be pinned to exact versions/digests in P0 after verification)

| Component | Purpose | License (verify at pin time) | Phase |
|-----------|---------|------------------------------|-------|
| PostgreSQL + pgvector | System of record, vectors | PostgreSQL License / PostgreSQL License | P0 |
| Valkey | Cache, rate limit, pub/sub | BSD-3 | P0 |
| Mailpit | Dev email sink | MIT | P0 |
| FastAPI, Pydantic, SQLAlchemy, Alembic, httpx | Backend | MIT/BSD | P0 |
| Next.js, React, Tailwind, Radix/shadcn, TanStack, ECharts | Frontend | MIT / Apache-2.0 | P0 |
| Redpanda (or Apache Kafka KRaft) | Event bus | Redpanda Community: **BSL 1.1** / Kafka: Apache-2.0 | P2 |
| ClickHouse | Analytics | Apache-2.0 | P2 |
| Temporal server + Python SDK | Workflows | MIT | P5 |
| OpenSearch | Search/hunting | Apache-2.0 | P6 |
| OpenTelemetry SDKs/Collector | Observability | Apache-2.0 | P0/P7 |
| Grafana LGTM image | Self-observability (optional) | AGPL-3.0 components (fine for internal use; review if distributing) | P7 |
| Ollama (optional) | Local LLM | MIT (models have their own licenses) | P4 |
| OpenBao (later) | Secrets | MPL-2.0 | P7/P8 |
| Keycloak (optional) | OIDC IdP | Apache-2.0 | P7 |

### 2.2 External / human dependencies

| Dependency | Needed for | Required by |
|------------|-----------|-------------|
| Your approval of architecture and decisions D1–D12 | Starting P0 | Now |
| GitHub (or other) remote, if CI in the cloud is wanted | CI | P0 (optional) |
| LLM provider choice and API keys (optional) | Real-model AI | P4 (optional; `mock` works without) |
| Vendor trial/developer accounts | Live verification | P8 only |
| Production-grade secrets backend | Storing real credentials | P8 only |

### 2.3 Internal dependency chain

`P0 → P1 (auth/tenancy/audit) → P2 (SDK, pipeline) → P3 (incidents need alerts/assets) → P4 (AI needs evidence) → P5 (automation needs incidents + AI proposals) → P6 (analytics needs facts) → P7 → [P8 gated]`

P4 and P5 can be swapped if you'd rather see automation before AI. P6's analytics can start in parallel with P5 if you want the executive view earlier.

## 3. Licensing notes (not legal advice)

- **Redpanda Community Edition** is source-available under BSL 1.1, which restricts offering it as a competing streaming service. Internal use and embedding in your product are generally fine, but verify this before commercializing. Apache Kafka (KRaft mode) is the drop-in Apache-2.0 alternative; the code depends only on the Kafka API.
- **Redis** licensing changed in 2024–2025. **Valkey** (BSD-3, protocol-compatible) avoids the question.
- **OpenSearch** is used instead of Elasticsearch because of its Apache-2.0 license.
- Vendor API terms of use (CrowdStrike, Microsoft, Splunk, etc.) govern live integrations. Review them in P8, along with any partner-program requirements.
