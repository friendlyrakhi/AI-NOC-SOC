# 01 — Product Requirements Document (PRD)

## 1. Problem statement

Operations teams run network/infrastructure monitoring (NOC) and security monitoring (SOC) on separate tool stacks: SolarWinds, Datadog, Prometheus, cloud-native monitors, SIEMs, EDRs, vulnerability scanners and ITSM. Analysts swivel between consoles, re-key data into tickets, and correlate by hand. Incidents that are both operational and security-related (e.g. a DDoS, ransomware causing outages, a misconfiguration that exposes data) fall between teams. AI assistants on the market often produce ungrounded answers and, in the worst case, take unreviewed actions.

## 2. Vision

One multi-tenant platform with **two purpose-built portals** (AI NOC, AI SOC) on a **shared core**:
- a universal integration framework,
- a normalized event/alert model,
- shared incident management,
- workflow automation with human approval,
- an evidence-grounded AI engine,
- an executive command center that spans both domains.

## 3. Goals and non-goals

### Goals (for this product line)
- G1. Ingest, normalize and correlate alerts/telemetry from the 15 target tools via a common connector SDK.
- G2. Give NOC and SOC analysts dedicated workflows while sharing incidents, assets, and automation.
- G3. AI that reduces triage and investigation time, and whose every claim can be verified against cited evidence.
- G4. Automation that is safe by construction: policy-checked, approval-gated, simulated until explicitly enabled.
- G5. Strong multi-tenancy suitable for an MSP/MSSP model.
- G6. Run fully on a single Windows PC for development and demos using mock data.

### Non-goals (for the initial build, Phases 0–7)
- NG1. Live connections to real vendor tenants (Phase 8, separately approved, read-only first).
- NG2. Executing remediation against any real system.
- NG3. Replacing a SIEM/APM — the platform aggregates and orchestrates; it is not a long-term log archive.
- NG4. Kubernetes/HA production deployment (architecture stays portable; Compose only for now).
- NG5. Mobile apps, billing/metering, marketplace.
- NG6. Training or fine-tuning AI models.

## 4. Personas

| Persona | Portal | Primary jobs |
|---------|--------|--------------|
| NOC Analyst (L1) | NOC | Watch alert queue, acknowledge, initial triage, escalate, follow runbooks |
| NOC Engineer (L2/L3) | NOC | Root-cause analysis, topology/impact analysis, author runbooks/automation |
| SOC Analyst L1 | SOC | Triage security alerts, close false positives, escalate |
| SOC Analyst L2 / Incident Responder | SOC | Investigate, scope, contain (via approved actions), document |
| Threat Hunter / Detection Engineer | SOC | Hunt across telemetry, tune detections |
| Incident Commander | Both | Coordinate major incidents, comms, approvals |
| Approver (Change/Security manager) | Both | Approve/deny high-impact actions |
| Executive (CIO/CISO) | Command Center | Posture, SLA, MTTA/MTTR, risk trends, major incidents |
| Integration Admin | Admin | Configure connectors, credentials, mappings |
| Tenant Admin | Admin | Users, roles, policies, AI settings for one tenant |
| Platform Admin (MSP operator) | Admin | Manage tenants; no implicit data access to tenants |
| Auditor | Admin (read-only) | Review audit log, approvals, AI decisions |

## 5. Scope by capability

Each requirement has an ID; acceptance criteria (AC) are testable. **P** = target phase (see [08](08-implementation-plan.md)).

### 5.1 Identity, tenancy and access (P1)

| ID | Requirement | Acceptance criteria |
|----|-------------|---------------------|
| IAM-1 | Users authenticate with local accounts (Argon2id + TOTP MFA); OIDC is supported in the design. | Login without MFA is blocked for roles that hold `approve:*` or `admin:*`. Failed logins are rate-limited and audited. |
| IAM-2 | Tenants are hierarchical: an MSP tenant owns customer tenants (one level). | A user can access only tenants where they have an explicit membership or an active delegation. Parent membership grants **no** implicit child access. |
| IAM-2a | MSP staff reach customer tenants through **delegations** (MSP role → customer tenant → role, optional expiry), visible to and revocable by the customer's tenant admin. | Revoking a delegation takes effect on the next request. Every delegated action is also written to the customer tenant's audit chain. |
| IAM-2b | MSP users can open an **"All customers" aggregate view** (queues, incidents, KPIs) across their delegated customers. | Aggregate mode is read-only at the database level. Writes require switching to a single customer. Rows always show the customer. Non-delegated tenants never appear. AI never runs in aggregate mode. |
| IAM-2c | MSP onboarding: create a customer tenant, invite the customer's first admin, and assign delegations. | Covered by an end-to-end test. |
| IAM-3 | RBAC with predefined roles plus custom roles composed from permissions (`resource:action`). | Each API endpoint declares a required permission. An automated test confirms every route has one. |
| IAM-4 | Portal entitlement: access to the NOC portal, SOC portal and Command Center is granted separately. | A user without `portal:soc` gets 403 from SOC APIs and does not see SOC navigation. |
| IAM-5 | Service accounts and API keys are scoped to one tenant and a set of permissions, and have an expiry. | Keys are shown once, stored hashed, revocable; usage is audited. |
| IAM-6 | Tenant isolation is enforced at the DB layer. | Cross-tenant test suite: every list/get/update path returns 404 for another tenant's IDs, including with RLS-bypass attempts. |

### 5.2 Integrations (P2, P3)

| ID | Requirement | Acceptance criteria |
|----|-------------|---------------------|
| INT-1 | Connector SDK with a typed contract (manifest, config schema, capabilities, fetch/stream/normalize/action). | A new sandbox connector can be added without changing core code. SDK contract tests pass. |
| INT-2 | Sandbox connectors for all 15 target tools, emitting realistic, deterministic fixture data. | Each produces normalized events; the UI labels it "SANDBOX". |
| INT-3 | Connector instances per tenant with encrypted credentials (write-only through the API). | Secrets never appear in API responses, logs, AI prompts or audit payloads (automated scan). |
| INT-4 | Health, last-sync, error, lag and rate-limit status for each connector instance. | Health page reflects injected faults (timeouts, 429s, auth failures) within one polling interval. |
| INT-5 | Inbound webhooks with HMAC signature verification and replay protection. | Unsigned, mis-signed, or replayed (>5 min old or duplicate nonce) requests are rejected and audited. |
| INT-6 | ServiceNow bidirectional incident sync (sandbox). | Creating/updating a platform incident creates/updates a mock SN record; SN-side state changes flow back; no infinite loops (sync-origin tagging). |
| INT-7 | Connector certification levels: `sandbox` → `contract-tested` → `live-verified`. | Only `live-verified` connectors can be enabled in `live` mode, and only when the platform setting allows it (off by default). |

### 5.3 Ingestion, normalization, correlation (P2, P3)

| ID | Requirement | Acceptance criteria |
|----|-------------|---------------------|
| ING-1 | All connector output goes onto the event bus, then into normalization, then storage. | Back-pressure: the pipeline survives 10× burst replay without data loss (consumer lag recovers). |
| ING-2 | Security events normalized to an OCSF-aligned schema; operational events to an OTel-aligned schema. | A mapping table per connector, with golden-file tests. |
| ING-3 | Deduplication (fingerprint) and alert lifecycle (new → ack → resolved/closed, with suppression). | Duplicate alerts increment a counter and do not create rows. |
| ING-4 | Correlation of alerts into incidents (rules: same asset/service within a time window, topology adjacency, shared IOC). | Seeded scenarios produce the expected incident grouping (golden tests). |
| ING-5 | Asset/CI inventory merged across sources (identity resolution by hostname/IP/cloud ID/agent ID). | Seeded duplicates merge to one asset carrying source provenance. |
| ING-6 | Maintenance windows suppress alerts for scoped assets. | Alerts in a window are tagged `suppressed` and do not page anyone. |

### 5.4 Incident management (P3)

| ID | Requirement | Acceptance criteria |
|----|-------------|---------------------|
| INC-1 | Incidents with domain (`noc`, `soc`, `joint`), severity, priority, status, assignee, SLA timers. | MTTA/MTTR are computed from timeline events and visible in the UI. |
| INC-2 | Immutable timeline of events, comments, state changes, AI analyses, actions, approvals. | Timeline entries cannot be edited; corrections are new entries. |
| INC-3 | Escalation NOC↔SOC: convert/link an incident to `joint`, keeping history. | Both portals show joint incidents with role-appropriate views. |
| INC-4 | Tasks/checklists per incident; runbook attachment. | — |
| INC-5 | Post-incident review template auto-drafted by AI (with citations), editable by humans. | The draft is marked "AI-generated, unreviewed" until a human approves it. |

### 5.5 AI intelligence engine (P4)

| ID | Requirement | Acceptance criteria |
|----|-------------|---------------------|
| AI-1 | A model-agnostic AI gateway with providers: `mock` (deterministic), `ollama` (local), and cloud providers (e.g. Anthropic, OpenAI, Azure OpenAI) through adapters. | Switching a tenant's provider needs no code change. `mock` is the default. |
| AI-2 | Cloud LLM use is **opt-in per tenant**, with a data-egress notice and field-level redaction policy. | Without opt-in, no request leaves the host (verified by egress test). |
| AI-3 | Evidence-grounded outputs: alert summary, incident summary, triage recommendation, RCA hypotheses, query assistance, PIR drafting. | Every factual statement carries ≥1 citation to an evidence ID retrieved in that request. A validator rejects outputs whose citations are absent or not retrieved, and the UI shows "insufficient evidence" instead. |
| AI-4 | AI outputs have confidence, model/provider/version, prompt template version, and the evidence set stored. | Any AI output can be replayed/inspected from the audit view. |
| AI-5 | The AI may *propose* actions; proposals become `ActionRequest`s subject to policy and approval. | No code path lets the AI module call an executor directly (architecture test). |
| AI-6 | Prompt-injection resilience: telemetry is treated as untrusted data. | The red-team test corpus (injected instructions in alert fields/log lines) does not cause tool misuse or policy bypass. |
| AI-7 | Evaluation harness with golden datasets for each AI task. | CI reports groundedness/citation accuracy. Regressions block a merge once the threshold is set (P4 baseline). |
| AI-8 | Token/cost/latency metering for each tenant, with budget limits. | Requests are rejected with a clear error when the budget is exhausted. |

### 5.6 Workflow automation (P5)

| ID | Requirement | Acceptance criteria |
|----|-------------|---------------------|
| WF-1 | Playbooks as versioned declarative definitions (YAML/JSON) executed by Temporal. | A playbook run survives a worker restart mid-run (durable). |
| WF-2 | Action risk tiers T0–T3 (see §7). The policy engine decides auto/approve/two-person/deny. | T2 requires 1 approval and T3 requires 2 distinct approvers (neither can be the requester). Approvals expire. |
| WF-3 | Execution modes: `dry_run`, `simulate` (default, against the sandbox connector), `live` (hard-disabled). | `live` cannot be enabled by API/UI. The server refuses to start if `live` is enabled without the required config **and** signed approval file (Phase 8+). |
| WF-4 | Every action records before/after state (simulated), the requester, approvers and the policy decision. | Visible in the incident timeline and the audit log. |
| WF-5 | Triggers: manual, on alert/incident match, schedule. | — |
| WF-6 | Kill switch: per tenant and global, halting all automation instantly. | Running workflows pause at the next activity boundary; audited. |

### 5.7 Portals and command center (P3, P6)

| ID | Requirement | Acceptance criteria |
|----|-------------|---------------------|
| UI-1 | A separate NOC portal and SOC portal with distinct navigation, theme accent and default dashboards. | See [07](07-ui-navigation.md). |
| UI-2 | Executive Command Center: cross-domain KPIs, SLA, posture, major incidents, trends. | All KPIs are drillable to the underlying records. |
| UI-3 | Live updates (SSE) for queues and incident timelines. | New alerts appear within 5 s of ingestion in the dev profile. |
| UI-4 | AI Copilot side panel with citations that link to evidence. | Clicking a citation opens the evidence record. |
| UI-5 | Accessibility WCAG 2.2 AA; keyboard-first triage. | Automated axe checks in CI; no serious or critical violations. |

### 5.8 Audit, compliance and administration (P1+)

| ID | Requirement | Acceptance criteria |
|----|-------------|---------------------|
| AUD-1 | Append-only, hash-chained audit log for auth, admin, data access to sensitive objects, AI calls, actions and approvals. | A tamper-verification command detects any modified or deleted row. |
| AUD-2 | Audit export (JSON/CSV) and retention policy per tenant. | — |
| ADM-1 | Admin console: tenants, users, roles, API keys, connectors, AI settings, policies, retention, kill switch. | — |

## 6. Non-functional requirements

| ID | Category | Requirement (dev-profile targets on the reference PC) |
|----|----------|------------------------------------------------------|
| NFR-1 | Performance | API p95 < 300 ms for list/get at 100k alerts per tenant; alert-to-UI latency < 5 s. |
| NFR-2 | Throughput | Sustain 1,000 events/s ingest in the `stream+analytics` profile (synthetic). |
| NFR-3 | Footprint | `core` profile ≤ 4 GB RAM; full profile ≤ 10 GB with caps. |
| NFR-4 | Security | OWASP ASVS 4.0 L2 as the baseline; OWASP Top 10 for LLM Applications addressed in the threat model. |
| NFR-5 | Reliability | At-least-once ingestion with idempotent consumers; no data loss on a container restart. |
| NFR-6 | Observability | OpenTelemetry traces/metrics/logs for every service; trace ID propagated through Kafka headers and Temporal. |
| NFR-7 | Portability | Pure Linux containers; no Windows-only dependencies inside services. |
| NFR-8 | Testability | ≥ 80% line coverage on backend domain/policy modules; contract tests for every connector. |
| NFR-9 | Data protection | Encryption at rest for secrets (envelope encryption); TLS between services in the hardened profile; PII redaction before AI egress. |
| NFR-10 | Maintainability | Modular monolith with enforced module boundaries (import-linter), ADRs for significant decisions. |

## 7. Action risk tiers

| Tier | Examples | Default policy |
|------|----------|----------------|
| T0 Read-only | Enrichment lookups, fetch logs, query metrics | Auto |
| T1 Low | Create/update ticket, add comment, tag alert, notify | Auto (audited); tenant can require approval |
| T2 Medium | Restart service, clear cache, scale a non-prod resource, disable a user session | 1 approver |
| T3 High | Isolate host (EDR), block IP/domain at firewall, disable account, change routing/config, delete data | 2 distinct approvers + justification + time-boxed approval |
| T-X Prohibited | Anything not in the action catalog | Denied |

In Phases 0–7, **all** executions of T1–T3 run in `simulate` mode.

## 8. Success metrics (measured on mock scenarios until live data exists)

- Triage time per alert in a scripted usability test: 30% reduction vs. a baseline with no AI and no correlation.
- AI citation accuracy ≥ 95% on the golden set; "insufficient evidence" returned correctly on ≥ 90% of unanswerable cases.
- Correlation precision/recall on seeded scenarios ≥ 0.9 / 0.8.
- Zero cross-tenant leaks in the isolation test suite (hard gate).

## 9. Open questions (also in [10](10-decisions-for-approval.md))

1. ~~Is the MSP/MSSP model a near-term need?~~ **Yes (answered 2026-11-16).** See IAM-2a–2c and ADR-0016.
2. Which cloud LLM providers (if any) are acceptable for tenant data, and what redaction is required?
3. Which vendor trial/sandbox accounts can you realistically obtain for Phase 8 verification?
