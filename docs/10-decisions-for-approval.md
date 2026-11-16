# 10 — Decisions for Approval

> **Approved 2026-11-16: all decisions D1–D15** ("approve all"). They are recorded as ADR-0001…0015 in [adr/](adr/README.md). The questions below remain open.

Each decision has a recommendation. Reply with "approve all", or name the decisions to change (for example "D4: use Apache Kafka"). Approved decisions are recorded as ADRs in `docs/adr/` during P0.

| ID | Decision | Recommendation | Main alternative(s) | Why recommended |
|----|----------|----------------|---------------------|-----------------|
| **D1** | Overall style | **Modular monolith API** + separate runtimes for connector-runner, ingest-worker, ai-gateway, workflow-worker, web | Microservices per domain | Right size for one PC and one developer; module boundaries enforced so they can be extracted later; isolation only where it adds security. |
| **D2** | Tenancy model | **Shared DB, shared schema, `tenant_id` + Postgres RLS (FORCE)**; per-tenant OpenSearch indices; CH row policies | Schema-per-tenant; DB-per-tenant | Simplest operations, strong DB-enforced isolation, scales to many tenants; dedicated stores possible later for large tenants. |
| **D3** | Portals | **One Next.js app, four route groups** (NOC, SOC, Command, Admin) with distinct layouts and entitlements | Two/three separate Next.js apps | Shared auth/design system/Copilot without duplication; can be split into separate deployables later if needed. |
| **D4** | Event bus | **Redpanda single-node in dev**, Kafka-API-only code | Apache Kafka (KRaft), Apache-2.0 | Lighter on RAM. If you plan to commercialize, choose Kafka now to avoid BSL questions; the code is identical. |
| **D5** | Cache/pub-sub | **Valkey** | Redis | Same protocol, clear BSD license. |
| **D6** | Search | **Defer OpenSearch to P6**; use Postgres FTS until then | OpenSearch from P2; ClickHouse-only search | Saves ~2 GB RAM and complexity early; hunting needs it only in P6. |
| **D7** | Authentication | **Built-in local accounts + TOTP MFA + BFF sessions in P1; OIDC (Keycloak/Entra ID) in P7** | Keycloak from day one | Keycloak costs ~0.7–1 GB RAM and setup time; the design stays OIDC-ready. |
| **D8** | AI providers | **`mock` default; optional local Ollama; cloud providers (e.g. Anthropic Claude, OpenAI/Azure OpenAI) behind per-tenant opt-in with redaction** | Cloud-first | Keeps telemetry on the PC by default; model-agnostic gateway lets you choose later. **Tell me which cloud providers, if any, you want adapters for first.** |
| **D9** | Secrets | **Local envelope encryption (dev-grade) behind `SecretsProvider`; OpenBao/KMS mandatory before real credentials (P8)** | OpenBao from P0 | Fewer moving parts while only mock data exists. |
| **D10** | Authorization engine | **In-process Python policy engine** (RBAC + ABAC conditions) with an OPA-compatible interface | OPA sidecar / Cedar | Lower latency and complexity now; swappable later. |
| **D11** | Normalized schemas | **OCSF-aligned for security, OTel-aligned for operations**, plus internal `alert@1` | Fully custom; ECS | Open standards with good vendor mapping, and future interoperability. |
| **D12** | Tooling | **uv** (Python), **pnpm** (Node), Node LTS pinned via `.nvmrc`, **GitHub Actions** CI (or local `scripts/ci.ps1` if no GitHub) | Poetry/npm; Azure DevOps | Fast, reproducible; widely supported. |
| **D13** | Git | Rename `master` → `main`; conventional commits; one PR or commit per phase slice | Keep `master` | Matches the configured main branch. |
| **D14** | Workflow engine | **Temporal** (as you proposed), introduced in P5 | A simple Postgres-backed job queue | Durable approvals, timers and signals are exactly Temporal's strength. |
| **D15** | Phase order | P4 AI before P5 Automation | Swap P4 and P5 | AI proposals feed the approval flow; swapping is cheap if you prefer. |

## Questions that affect the design

1. ~~**Multi-tenancy purpose**~~ **Answered 2026-11-16: yes, we serve multiple customer organizations (MSP model).** Design: [ADR-0016](adr/0016-msp-tenancy-delegated-access-and-aggregate-views.md). P1 scope is expanded accordingly.
2. **Cloud LLMs:** is sending redacted telemetry to a cloud LLM acceptable for your use case, and which provider(s) first?
3. **Commercial intent:** is this personal/learning, internal to an organization, or intended as a product? (This affects D4 and licensing diligence.)
4. **GitHub:** do you have a remote repository for CI, or should CI run locally?
5. **Vendor access (for P8 planning only):** which vendor accounts do you already have or can get (e.g. a ServiceNow developer instance, AWS/Azure/GCP free tiers, a self-hosted Wazuh/Prometheus/Grafana)?

## What happens after approval

1. I record the approved decisions as ADRs.
2. I implement **P0 only**, then stop for your review against the P0 exit criteria.
3. Every later phase follows the same pattern: a short design check-in, then implementation, a demo, and your go-ahead.

Nothing in any phase will connect to a real vendor endpoint or execute a real remediation.
