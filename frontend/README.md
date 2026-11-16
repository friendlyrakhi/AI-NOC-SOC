# frontend

Next.js 16 (App Router) + TypeScript + Tailwind CSS 4. The web app for the Unified AI NOC & SOC platform: Executive Command Center, AI NOC and AI SOC portals, incident management, automation center, connector administration, reporting, and tenant/MSP administration.

> **DEMO data.** Operational screens (NOC, SOC, Command Center, incidents, automation, reports) show generated, deterministic demo data, marked with a **DEMO** badge and notice on every page. Identity, tenants, members, roles, API keys, audit log, delegations and customers come from the real backend API. Connector status is never invented: it reports "Not configured" until the connector API exists (phase P2).

## Run it

### Everything in containers (recommended)

From the repo root (Windows PowerShell):

```powershell
scripts\bootstrap.ps1          # once: secrets, .env, dependencies
scripts\dev.ps1 up -Build      # postgres, migrate, valkey, mailpit, api, web
scripts\dev.ps1 seed           # once: MSP + 2 customers + users -> infrastructure/secrets/dev-users.json
```

Open http://127.0.0.1:3000 and sign in with an account from `dev-users.json`. Get MFA codes with `scripts\dev.ps1 totp <email>`.

| Try | Account | What you see |
|-----|---------|--------------|
| NOC engineer | `noc@globex.example` (no MFA) | NOC portal, infrastructure screens, incidents, automation, reports |
| SOC responder | `soc@initech.example` (no MFA) | SOC portal including hunting, vulnerabilities, VAPT |
| Customer admin | `admin@initech.example` (MFA) | Every area, including connectors and administration |
| MSP analyst | `msp.noc@acme.example` (no MFA) | Tenant switcher → "All customers (read-only)" |
| Executive | `msp.exec@acme.example` (no MFA) | Command Center, including the customer comparison view in "All customers" mode |

### Hot-reload development

Keep the API running in containers (`scripts\dev.ps1 up`), then:

```powershell
pnpm --filter frontend dev     # http://localhost:3000, talks to the API at http://127.0.0.1:8100
```

`NOCSOC_API_INTERNAL_URL` overrides the API address. In `next dev` the session cookie is not `Secure` (plain http); production builds set `Secure` unless `NOCSOC_COOKIE_SECURE=false` (the local container sets this until TLS arrives in P7).

## Test it

```powershell
pnpm --filter frontend test        # Vitest + Testing Library (jsdom): components, data generator, navigation
pnpm --filter frontend lint
pnpm --filter frontend typecheck
pnpm --filter frontend build
pnpm e2e                           # Playwright journeys + axe WCAG 2.1 AA checks (light and dark) against the running stack
```

E2E uses the Microsoft Edge already installed on Windows (no browser download). On Linux CI it uses Playwright's Chromium. The E2E helper clears TOTP replay markers in the **local dev database** so MFA users can sign in repeatedly; never point it at anything else.

## Structure

```
src/
├─ app/
│  ├─ (auth)/              login, MFA, enrollment, invitation
│  ├─ (app)/layout.tsx     shell: portal links, global search, tenant switcher, role-based side nav
│  ├─ (app)/command/       Executive Command Center, customer comparison (MSP)
│  ├─ (app)/noc/           overview, alerts & correlation, RCA, SLA, servers, network, cloud, APM, databases, asset drill-down
│  ├─ (app)/soc/           overview, investigations, SIEM, EDR/XDR, threat intel, AI hunting, MITRE ATT&CK, vulnerabilities, VAPT
│  ├─ (app)/incidents/     incident management + incident detail (timeline, alerts, AI RCA, response workflow, assets)
│  ├─ (app)/automation/    playbooks, simulated runs, approval inbox
│  ├─ (app)/connectors/    connector catalog and (honest) status
│  ├─ (app)/reports/       30-day reporting with CSV export
│  ├─ (app)/search/        global search
│  ├─ (app)/admin/         real tenant/MSP administration (backend API)
│  └─ actions/             Server Actions (all mutations)
├─ components/             data-table, charts, indicators, tabs, shell, admin forms
├─ lib/
│  ├─ demo/                deterministic DEMO data: types, reference data, generator
│  ├─ server/              server-only API client, session cookie, demo scope
│  ├─ api/schema.d.ts      types generated from backend/openapi/openapi.json (pnpm gen:api)
│  ├─ nav.ts               role-based navigation (permission per item)
│  └─ rows.ts              domain records → table rows/columns
└─ proxy.ts                redirects requests without a session to sign-in
```

## Conventions

**Data.** Pages are server components. They read data via `getDemo()` (demo) or `apiGet()` (real API) and pass plain, serializable rows to client components. The demo data shapes follow `docs/03-data-model.md`. When the P2/P3 APIs exist, a page swaps `getDemo()` for `apiGet()` and the components stay the same. Demo identifiers can never be mistaken for real ones: vulnerabilities use `CVE-DEMO-…`, IPs come from documentation ranges (RFC 5737), domains end in `.example`, and threat actors and testing firms are fictional and marked "(demo)". MITRE ATT&CK IDs are the real public identifiers.

**Role-based menus.** Every navigation item declares a permission (`src/lib/nav.ts`), and pages call `gate(me, permission, title)`. Hiding a link is a convenience; the API enforces authorization on every call.

**Tables.** `DataTable` takes serializable column specs (`type: "severity" | "health" | "state" | "time" | …`). It provides search, per-column filters, sortable headers (`aria-sort`; severity and health sort by impact), pagination, CSV export (`-DEMO` file names, formula-injection guard) and drill-down: a detail page via `_href`, or an accessible `<dialog>` via `_details`.

**Charts** follow the dataviz method:
- Categorical colors are validated slots in fixed order, checked with the dataviz palette validator against this app's light and dark surfaces.
- Status colors are fixed and never used as text.
- 2px lines, hairline grid, one y-axis only (MTTA and MTTR are separate charts).
- A legend for two or more series, plus nudged end labels.
- A crosshair tooltip that also works with the arrow keys.
- "View data as table" on every chart.

**Accessibility.** WCAG 2.1 AA is enforced by axe in E2E, in both light and dark themes. Severity and health always pair a distinct shape with a text label. The app has a skip link, keyboard-operable tabs, focus-visible rings, a mobile navigation dialog, and support for `prefers-reduced-motion`.

**Safety.** No screen can trigger a real action. Response steps, playbook runs and approvals are simulated and labelled as such. Approval, hunt and connector actions show the phase in which they arrive.
