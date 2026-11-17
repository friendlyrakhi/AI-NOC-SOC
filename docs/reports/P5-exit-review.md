# P5 Exit Review: workflow automation and human approval

Date: 2026-11-17 · Status: **ready for your review**

Automation works end to end: playbooks and single actions run through a policy engine, approvals with step-up MFA and the two-person rule, a kill switch, and Temporal workflows that survive a dead worker. **Every execution is simulated or a dry-run preview through sandbox connectors.** Live execution is not a setting anyone can turn on in this build; the API, the database and the worker each refuse it independently.

## Exit criteria (docs/08-implementation-plan.md §P5)

| Criterion | Result | Evidence |
|-----------|--------|----------|
| T3 action cannot execute without two distinct approvers; self-approval blocked; expired approvals rejected | **Pass** | `test_t3_needs_two_distinct_approvers`: one approval leaves it pending, a second vote by the same approver is `409 action.already_decided`, and only a different approver's approval releases it. `test_t2_needs_one_approval_and_blocks_self_approval` (API, `403`), `test_self_approval_blocked_in_database` (a trigger rejects approver = requester even for a direct insert), `test_expired_approvals_are_rejected` (`409 action.expired`; the request is marked expired and the workflow ends). E2E: the T3 journey with two approver accounts and authenticator codes. |
| Worker killed mid-run → workflow resumes correctly | **Pass** | `test_worker_killed_mid_run_resumes`: the Contain host run waits for T3 approval, the worker is stopped, approvals arrive while it is down, a new worker starts and the run finishes. An action interrupted while `executing` is completed as failed, never run twice. |
| Kill switch halts runs at next activity | **Pass** | `test_kill_switch_halts_run_at_next_activity`: engaging it mid-run halts the run at its next checkpoint (status `halted`) and cancels a claimed action with "Halted by the automation kill switch". Unit test `test_kill_switch_denies_except_dry_runs`. E2E: engage and release with step-up. |
| SEC-ACT-01..07 pass, including the "live mode impossible" release gate | **Pass** | See the table below. |

## Security controls (SEC-ACT, threat model T21–T26, LLM06)

| ID | Control | Tests |
|----|---------|-------|
| SEC-ACT-01 (T21) | No approval bypass. The worker has no database access; before executing it must *claim* the request from the API, which re-reads status, the approval set (distinct approvers ≥ required, no deny) and the kill switch from the database, never from workflow input. | `test_worker_cannot_execute_unapproved_requests` |
| SEC-ACT-02 (T22) | Approver ≠ requester (API and database trigger), two distinct approvers for T3, `action:approve` role, fresh step-up MFA, API keys cannot approve. | `test_t3_…`, `test_self_approval_blocked_in_database`, `test_api_keys_cannot_approve` |
| **SEC-ACT-03 (T23, release gate)** | Live execution impossible at every layer: request schema and policy engine deny it, the database `CHECK` allows only `dry_run`/`simulate`, the worker's executor refuses any other mode and any non-sandbox connector instance, and the playbook run endpoint returns `422 action.execution_disabled`. | `test_release_gate_live_execution_impossible`, `test_live_mode_always_denied`, `test_live_mode_rejected_everywhere` |
| SEC-ACT-04 (T24) | Playbooks are versioned; published and retired versions are immutable and undeletable (database trigger); publishing needs `playbook:publish` + step-up and audits a step diff; runs pin the version they started with. | `test_published_versions_are_immutable` |
| SEC-ACT-05 (T25) | Kill switch (tenant and platform-wide), at most 20 actions per incident per hour, the same action on the same target at most 3 times in 10 minutes. | `test_runaway_protection`, `test_repeated_action_on_same_target_is_denied`, kill-switch tests |
| SEC-ACT-06 (T26) | Parameters validated by the catalog's JSON Schema (no extra keys, 4 KB cap); targets must be assets or incidents of the caller's tenant. | `test_parameters_and_targets_validated`, `test_cross_tenant_requests_invisible` |
| SEC-ACT-07 (LLM06) | AI only suggests. An AI-originated request must cite an AI run that actually suggested that action, and always needs a human approver, even at T0/T1. The AI gateway cannot import or reach the workflow worker (import-linter, compose policy). | `test_ai_requests_always_need_a_human`, `test_ai_suggested_action_needs_human_approval` |

## How it works

```
analyst / playbook step / AI suggestion
        │  POST /actions/requests  (policy engine: deny | auto | 1 approval | 2 approvals)
        ▼
   API ──start──► Temporal ──task──► workflow-worker (no DB, no data-store network)
        ▲                                   │ waits for "decide" signal or expiry timer
        │  approve / deny (step-up) ─signal─┘
        │◄── claim (re-checks approvals + kill switch in DB) ──┤
        │                                                       ▼
        │                               sandbox connector: simulate | dry-run preview
        └◄── complete (result → request, incident timeline, audit)
```

- **Catalog and policy.** Actions come from the connector manifests plus two platform actions (`platform.timeline_note`, `platform.enrich_asset`). Tiers: T0/T1 run automatically, T2 needs one approver, T3 two. Tenants can disallow an action, require a justification or raise its tier, never lower it. Assets with criticality 4 or more raise the tier by one.
- **Workflows.** `ActionWorkflow` handles one request. `PlaybookWorkflow` runs a published version's steps in dependency order, requests each step's action, waits for approval within the playbook's window, checkpoints before every step (kill switch, cancel), and records each step's result. A step whose prerequisite failed is skipped; `on_failure: continue` lets later steps proceed.
- **Records.** Every request, decision, result, publish, run and kill-switch change is audited and, for incidents, added to the timeline.
- **UI.**
  - Automation center: playbooks, runs, action requests, the action catalog with tenant policy, the kill switch.
  - Approvals inbox (approvers land on it); request detail with approve/deny and the simulated or dry-run result.
  - Playbook pages (versions, draft, publish with step-up, run in dry-run or simulate); run pages that update live.
  - On real incidents, an Actions tab (request an action, start a playbook) and "Request this action" on AI suggestions.

## Deployment

The `workflow` compose profile adds:

- **`temporal`**, the Temporal CLI dev server 1.4.1, pinned by digest, with SQLite persisted to a volume.
- **`workflow-worker`**, which reaches only the API and Temporal on an internal `workflow` network. It holds no database, bus, Valkey or AI credentials, only its own token.

The compose policy check now treats the worker like the connector runner and keeps the AI gateway off the `workflow` network. `scripts/dev` starts the profile by default. Measured memory: Temporal ~100 MB and worker ~60 MB, far below ADR-0014's 1 GB estimate.

## Test results

| Suite | Count | Notes |
|-------|-------|-------|
| Backend unit (actions) | 20 | policy engine, DSL validation, release gate |
| Backend integration (automation) | 19 | against a real Temporal server and the real worker |
| Full Python suite | 414 | isolation suite extended to all new routes; 7 new tables classified FORCE RLS, `global_kill_switch` GLOBAL |
| Frontend unit | 51 | |
| Browser journeys | 35 | 5 new P5 journeys with axe checks on the automation center, approvals inbox, request and run pages |
| CI gates | all 13 green | mypy, import-linter (now 7 contracts: the worker is a separate runtime), bandit, pytest, OpenAPI drift, pip-audit, eslint, typecheck, vitest, npm-audit, build, compose policy, gitleaks |

## Deviations from the plan

1. **Temporal persistence.** ADR-0014 assumed the auto-setup image on Postgres. P5 uses the single-binary dev server with SQLite (durable across restarts, ~100 MB). Production needs a Temporal cluster on its own database before go-live (P8).
2. **Where executors run.** The plan said "via connector-runner". Executors run in the workflow worker instead (as threat T21 requires), which has the same isolation as the runner: no data-store network or credentials.
3. **"Signed" policy decision (T21).** Instead of signing decisions, the worker cannot execute anything without claiming it from the API, which re-reads the approval set from the database at that moment. This is stronger than a signature over stale data.

## Residual risks and follow-ups

1. **Simulation only.** Nothing has been tested against a real system, by design. Live execution needs its own phase, threat review and your explicit decision.
2. **Temporal dev server.** Not highly available. Its UI is not exposed. Workflow history lives in a local volume.
3. **Shared worker token.** One token for all tenants; the API scopes every call by the request's owning tenant. Per-tenant workload identity comes with OpenBao (P8).
4. **Approver availability.** Requests expire after 30 minutes by default (`NOCSOC_APPROVAL_EXPIRY_MINUTES`). There are no approval notifications yet (email/chat in P6).
5. **E2E staging helper.** The T3 browser journey links a fresh DEMO asset to an incident through the dev database (like the existing TOTP helper) so reruns do not trip the loop guard. It is test-only and refuses anything but the local dev stack's container.

## Next: P6 (needs your go-ahead)

P6 covers analytics and reporting: OpenSearch, drillable KPIs, SLA and executive reports, and notifications.
