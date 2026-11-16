# Unified AI NOC & SOC Operations Platform — Design Docs

Status: **Architecture approved 2026-11-16 (all decisions D1–D15).** Phase 0 complete, see [P0 exit review](reports/P0-exit-review.md). Decisions are recorded in [adr/](adr/README.md).
Date: 2026-11-16

| # | Document | Purpose |
|---|----------|---------|
| 00 | [Workspace Assessment](00-workspace-assessment.md) | What exists today, machine constraints |
| 01 | [PRD](01-prd.md) | Problem, personas, scope, functional/non-functional requirements, acceptance criteria |
| 02 | [Architecture](02-architecture.md) | System context, containers, data flows, deployment profiles, repo layout |
| 03 | [Data Model](03-data-model.md) | PostgreSQL, ClickHouse, OpenSearch, Kafka topics, tenancy enforcement |
| 04 | [Threat Model](04-threat-model.md) | Trust boundaries, STRIDE, AI-specific threats, mitigations, security tests |
| 05 | [API Specification](05-api-specification.md) | REST conventions, endpoints, auth, errors, events |
| 06 | [Connector SDK](06-connector-sdk.md) | Connector contract, lifecycle, normalization, sandbox mode, certification |
| 07 | [UI Navigation](07-ui-navigation.md) | Portals, information architecture, screen inventory |
| 08 | [Implementation Plan](08-implementation-plan.md) | Phases, deliverables, exit criteria |
| 09 | [Risks & Dependencies](09-risks-and-dependencies.md) | Risk register, external dependencies, licensing |
| 10 | [Decisions for Approval](10-decisions-for-approval.md) | Decisions D1–D15 (approved) and open questions |
| — | [ADRs](adr/README.md) | Accepted architecture decision records |
| — | [Phase reports](reports/) | Exit reviews per phase |

## Non-negotiable guardrails (apply to every phase)

1. **No fabricated live integrations.** Every connector ships in `sandbox` mode backed by fixture data. A connector is labelled `live-verified` only after it has been exercised against a real vendor endpoint using credentials you supply.
2. **No production remediation.** Action executors run in `simulate` mode. Real execution is hard-disabled by a server-side setting that the UI or API cannot change. Enabling it later requires a separate, explicit approval and a design review.
3. **AI proposes, humans decide.** The AI has no direct path to execute actions. Every action passes through the policy engine. High-impact actions need human approval, and critical actions need two people.
4. **Evidence-grounded AI.** Every AI claim cites tenant-scoped evidence IDs. If there is no supporting evidence, the AI says "insufficient evidence".
5. **Tenant isolation is enforced in the data layer** (Postgres RLS, ClickHouse row policies, per-tenant OpenSearch indices), not only in application code.
6. **Everything security-relevant is audited** in an append-only, hash-chained audit log.
