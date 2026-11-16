# 07 — UI Navigation & Screen Inventory

> **Implementation status (2026-11-16):** all screens below are built (see [reports/frontend-demo-ui.md](reports/frontend-demo-ui.md)). Operational screens run on labelled **DEMO** data until their backend phases deliver real data. Administration runs on the real API. The shipped route map is in `frontend/README.md`. Differences from this plan: the NOC portal adds dedicated Servers, Network, Cloud operations, Applications (APM) and Databases screens plus RCA and SLA reporting; the SOC portal adds VAPT and a MITRE ATT&CK matrix; shared areas live under *Operations* (Incidents, Automation, Connectors, Reports).

## 1. Shell

One Next.js application with four route groups and separate layouts: `(noc)`, `(soc)`, `(command)`, `(admin)`. They feel like distinct portals (own navigation, accent color, landing page) and share the shell, design system, auth and Copilot. Splitting into separate apps later is a build change, not a rewrite (see Decision D3).

```
┌────────────────────────────────────────────────────────────────────────────┐
│ [Logo] [Portal: NOC ▾]   🔍 Global search (⌘K)     [Tenant: Globex ▾] 🔔 👤  │
│  SANDBOX DATA banner (always visible while any sandbox connector is active)│
├──────────────┬────────────────────────────────────────────┬────────────────┤
│ Portal nav   │ Page content                               │ AI Copilot     │
│ (collapsible)│                                            │ (toggle, ⌘J)   │
│              │                                            │ evidence-cited │
└──────────────┴────────────────────────────────────────────┴────────────────┘
```

- **Portal switcher** shows only entitled portals (`portal:noc`, `portal:soc`, `portal:command`, `admin`).
- **Tenant switcher** (MSP users) re-issues the token; the page reloads into the same portal. MSP users also get an **"All customers"** entry, a read-only aggregate view where every row shows a customer badge, write actions are hidden, and the Copilot is disabled until a single customer is chosen.
- **Admin → Customers** (MSP admins): onboard a customer tenant, invite its first admin, and manage delegations (role, expiry, aggregate access). Customer admins see **Admin → MSP access**, which lists and can revoke delegations.
- **Global search (⌘K)** covers alerts, incidents, assets, runbooks and commands, scoped to the current tenant.
- **Notifications** include approval requests, assignments and connector failures.
- **Approvals badge** (a count) appears for users with `action:approve`.
- **Accent colors:** NOC teal, SOC violet, Command amber, Admin slate. Dark theme is the default (operations rooms) and light theme is supported.

## 2. NOC Portal (`/noc`)

| Nav item | Route | Key content | Primary roles |
|----------|-------|-------------|---------------|
| Overview | `/noc` | Service health tiles (SLO burn), open incidents by priority, alert volume sparkline, connector health strip, top noisy sources | All NOC |
| Alerts | `/noc/alerts` | Dense, virtualized queue; keyboard triage (j/k, a=ack, e=escalate, x=select); grouping by service/asset; saved views | NOC analyst |
| Alert detail | `/noc/alerts/[id]` | Summary, AI summary (cited), evidence tabs (events, metrics window, raw), asset context, related alerts, actions | |
| Incidents | `/noc/incidents` | Domain `noc` + `joint`; SLA timers; filters | |
| Incident detail | `/noc/incidents/[id]` | Header (sev, status, commander, SLA), **timeline**, linked alerts, impact map, tasks, AI panel (summary/RCA), actions & approvals, ServiceNow link | NOC engineer, IC |
| Topology | `/noc/topology` | Service → asset dependency graph with live status overlay; impact "blast radius" view | NOC engineer |
| Infrastructure | `/noc/assets` | Asset inventory (filters by type/env/criticality/source), asset detail with metrics, alerts, vulns, changes | |
| Metrics | `/noc/metrics` | Constrained metric explorer (pick metric/asset/service/range); compare windows | NOC engineer |
| Maintenance | `/noc/maintenance` | Calendar of maintenance windows; create with scope | NOC engineer |
| Runbooks & Automation | `/noc/automation` | NOC playbooks, runs, simulated results | NOC engineer |
| Reports | `/noc/reports` | Availability, MTTA/MTTR, noise reduction | |

## 3. SOC Portal (`/soc`)

| Nav item | Route | Key content | Primary roles |
|----------|-------|-------------|---------------|
| Overview | `/soc` | Open cases by severity, MITRE ATT&CK heat strip, alert funnel (ingested → triaged → escalated), top targeted assets/identities, KEV exposure | All SOC |
| Triage Queue | `/soc/alerts` | Security alert queue with AI triage verdict suggestion (`likely_true_positive/likely_benign/needs_investigation` + cited rationale), entity chips (user/host/IP/hash), bulk close with reason codes | SOC L1 |
| Alert detail | `/soc/alerts/[id]` | Detection info, OCSF fields, observables with enrichment, process tree (where available), related alerts by entity, AI summary | |
| Cases | `/soc/incidents` | `soc` + `joint` incidents | SOC L2, IC |
| Case detail | `/soc/incidents/[id]` | As NOC incident detail plus: entity graph, ATT&CK mapping, scope (affected hosts/users), containment actions (approval-gated), evidence locker | |
| Investigate | `/soc/investigate` | Unified search over security events (Postgres FTS → OpenSearch in P6), pivot on entity, AI query assist (suggests, never auto-runs) | SOC L2 |
| Hunt | `/soc/hunt` | Saved hunts, async hunt runs, results to case | Threat hunter |
| Detections | `/soc/detections` | Per-source detection/rule inventory with noise and true-positive stats (read-only in initial build) | Detection eng. |
| Vulnerabilities | `/soc/vulnerabilities` | Findings prioritized by KEV/EPSS/CVSS × asset criticality × exposure; risk acceptance with expiry | SOC, vuln mgmt |
| Assets & Identities | `/soc/entities` | Hosts and identities with risk context | |
| Playbooks | `/soc/automation` | SOC playbooks, runs | SOC L2 |
| Reports | `/soc/reports` | Case metrics, dwell time, ATT&CK coverage | |

## 4. Executive Command Center (`/command`)

| View | Content |
|------|---------|
| Overview | KPI cards: MTTA, MTTR (NOC/SOC), SLA attainment, open P1/P2, critical KEV exposure, automation rate (simulated), AI-assisted triage share. Trends 7/30/90 d. Every card drills into records. |
| Major incidents | Live list of P1/P2 and joint incidents with status, commander, business impact, last update |
| Service health | Business services with SLO status |
| Risk posture | Vulnerability exposure trend, top risky assets, unresolved high-severity findings |
| Tenants (MSP only) | Per-tenant health and SLA comparison (only tenants the user is a member of) |
| AI briefing | Daily AI-generated briefing with citations, labeled as AI-generated |

## 5. Shared areas (available inside each portal's nav footer)

| Item | Route | Notes |
|------|-------|-------|
| Approvals inbox | `/approvals` | Pending ActionRequests: action, tier, target, requester (human/AI/playbook), justification, policy decision, simulated preview (dry_run), approve/deny with step-up MFA |
| Workflows | `/workflows` | Playbook editor (form plus YAML view, schema-validated), versions, publish, runs with step-level status |
| Integrations | `/integrations` | Catalog cards (certification badge: SANDBOX / CONTRACT-TESTED / LIVE-VERIFIED), instances, config forms generated from JSON Schema, write-only credential fields, test connection, health & runs, scenario replay (sandbox) |
| Knowledge | `/knowledge` | Runbooks/KB used for AI retrieval; publish workflow |

## 6. Admin (`/admin`)

| Item | Route |
|------|-------|
| Tenant settings | `/admin/tenant` |
| Users & invitations | `/admin/users` |
| Roles & permissions | `/admin/roles` |
| API keys | `/admin/api-keys` |
| AI settings | `/admin/ai` (provider routing, cloud egress opt-in with explicit warning, redaction policy, budgets, usage) |
| Action policies | `/admin/policies` (tier overrides, kill switch) |
| Audit log | `/admin/audit` (search, export, chain verification status) |
| Data retention | `/admin/retention` |
| Platform (platform admins) | `/admin/platform/tenants`, `/admin/platform/system` (execution mode shown read-only: **SIMULATE**) |

## 7. UX rules

1. **AI content is always labeled.** It carries an "AI" badge, the model/provider, a confidence value and citation chips. Uncited sentences are not rendered as facts.
2. **Provenance is always visible.** Data from sandbox connectors carries a "SANDBOX" tag, and simulated action results carry a "SIMULATED" tag.
3. **Destructive and high-impact operations** use a confirmation dialog that names the target, tier and mode. There are no one-click T2/T3 actions.
4. **Keyboard-first queues** have shortcuts, and help is available on `?`.
5. **Accessibility:** WCAG 2.2 AA, focus management, no color-only status (icons and text as well), and reduced-motion support.
6. **Performance:** virtualized tables and server-side pagination, and the alert queue stays smooth at 10k rows.
7. **Empty, error and loading states** are designed for every page. A connector failure explains its cause in plain words.

## 8. Frontend structure (planned)

```
frontend/src/
├─ app/
│  ├─ (auth)/login, mfa
│  ├─ (noc)/noc/...        layout.tsx = NOC nav
│  ├─ (soc)/soc/...        layout.tsx = SOC nav
│  ├─ (command)/command/...
│  ├─ (shared)/approvals, workflows, integrations, knowledge
│  ├─ (admin)/admin/...
│  └─ api/bff/...           BFF route handlers (session → JWT, CSRF)
├─ components/ (ui/, data-table/, timeline/, copilot/, charts/, topology/)
├─ lib/api/ (generated client), lib/auth/, lib/sse/
└─ middleware.ts            session check, portal entitlement redirect
```
