# Frontend build-out with DEMO data

Date: 2026-11-16 · Requested ahead of phases P2–P6 · Status: **ready for your review**

## What changed in the plan

The phase plan delivers the operational screens with their data (P3 incidents and portals, P4 AI, P5 automation, P6 command center and search). At your request, the **complete frontend** is now built first, on clearly labelled **DEMO** data. The backend phases still need to deliver the real data. Each page swaps its demo source for the real API without UI changes, because the demo records follow `docs/03-data-model.md`.

| Area | Data source today | Real source arrives |
|------|-------------------|---------------------|
| Sign-in, MFA, tenants, members, roles, API keys, audit log, delegations, MSP customers, platform | **Real API** (P1) | Done |
| Connector catalog and status | Static catalog; status is real (none configured) | Instances and health in P2 |
| NOC/SOC screens, incidents, correlation, SLA | DEMO generator | P2 (ingest), P3 (incidents and portals) |
| AI RCA, hunt suggestions | DEMO, labelled "AI draft (demo)" | P4 |
| Playbooks, runs, approvals | DEMO, labelled simulated | P5 |
| Command Center KPIs, reports, search, hunting execution | DEMO | P6 |

## Screens delivered

- **Executive Command Center:**
  - MTTA, MTTR, SLA, open P1/P2, known-exploited vulnerabilities and automation rate.
  - Trend charts, business service health, major incidents.
  - In MSP "All customers" mode: per-customer comparison, with real customer names and demo metrics.
- **AI NOC:**
  - Overview with infrastructure health by domain.
  - Alerts with correlation groups, root-cause analysis and SLA reporting (SLOs, error budgets, response-SLA breaches).
  - Server, network, cloud, application (APM) and database monitoring, each with a drill-down asset page (48-hour metric charts, alerts, incidents, vulnerabilities).
- **AI SOC:**
  - Overview with detection funnel and ATT&CK tactics, plus investigations.
  - SIEM events, EDR/XDR with process trees and the endpoint fleet, and threat intelligence (fictional actors).
  - AI threat hunting (suggest only), the MITRE ATT&CK matrix heatmap, vulnerability management (risk = CVSS × EPSS × known-exploited × exposure × criticality) and VAPT engagements with findings.
- **Incident management:** list plus detail with SLA clocks, timeline, alerts, a cited AI RCA (marked not confirmed), the approval-gated simulated response workflow, and assets.
- **Automation center:** playbooks with risk tiers, simulated runs, and the approval inbox (two-person rule for T3).
- **Connectors:** catalog of the 15 target tools plus a generic webhook, with capabilities and honest "Not configured" status.
- **Reports:** 30-day charts, each with a table view and CSV download.
- **Global search** across incidents, assets, alerts, indicators and vulnerabilities.
- **Tenant and customer management:** the existing real admin pages, plus the MSP customer comparison.

## Reusable components

`DataTable` (search, filters, sort, pagination, CSV export, drill-down), `TimeSeriesChart`, `BarList`, `SegmentBar`, `Sparkline`, `SeverityBadge`, `HealthBadge`, `StateBadge`, `KpiTile`, `Tabs`, `DemoBadge`/`DemoNotice`, the role-based side navigation with a mobile drawer, and the `gate()` permission check.

## Verification

| Check | Result |
|-------|--------|
| Frontend unit and component tests (Vitest, jsdom) | 42 passed |
| Browser journeys (Playwright, Edge) incl. P1 journeys | 20 passed |
| axe WCAG 2.1 AA, light and dark | No serious or critical findings on 16 distinct pages (22 page checks across both themes) |
| Typecheck, lint, production build | Clean |
| Palette | Validated with the dataviz validator against this app's dark (`#121821`) and light (`#ffffff`) surfaces |

### Defects found and fixed while verifying

- **Contrast:** status yellow was used as text (1.7:1) and the sandbox banner sat at 3.9:1. Text now uses text tokens, and status colors appear only on borders, fills and icons.
- **Dark-mode button contrast:** the primary button was 3.7:1, so a separate solid-fill token was added.
- **MITRE matrix:** the label contrast was 4.35:1, and the horizontally scrolling matrix was unreachable by keyboard.
- **Inconsistent RCA:** a joint incident built from a security alert showed an infrastructure narrative. The generator now follows the alerts involved, and a regression test covers it.
- **Health sorting:** health sorted alphabetically (Degraded before Down). It now sorts by impact, with a regression test.
- **Clipped labels:** edge x-axis labels were cut off on narrow charts.

## Honesty rules enforced in code and tests

- Every demo page shows the **DEMO** badge and notice. Generated records carry `demo: true` (unit-tested).
- Demo identifiers can't be mistaken for real ones: `CVE-DEMO-…` IDs, documentation-range IPs (RFC 5737), `.example` domains, and fictional actors and testers marked "(demo)". All of this is unit-tested.
- Connector status comes only from the platform, so it is "Not configured". A unit test and an E2E test assert that no connector shows "Connected", "Healthy" or "Online".
- No control executes anything. Response steps, playbook runs and approvals are labelled simulated, and buttons for later phases are disabled and name their phase.

## Known limitations

- Demo data is computed per request (cached per tenant and hour). Fine for demonstration, and replaced by APIs later.
- Search covers only the current tenant's demo data plus the user's permissions. OpenSearch-backed search arrives in P6.
- Charts were checked visually at 1440 px in dark mode. Narrow widths are covered by the responsive layout and the mobile E2E test, but were not reviewed screen by screen.
