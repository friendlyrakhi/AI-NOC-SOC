# P1 Exit Review: Platform Core (identity, MSP tenancy, RBAC, audit, portal shell)

Date: 2026-11-16 · Status: **ready for your review**

## Exit criteria (docs/08-implementation-plan.md §P1)

| Criterion | Result | Evidence |
|-----------|--------|----------|
| Log in as each seeded role; navigation shows only entitled portals | **Pass** | E2E (Edge): an MSP NOC analyst sees only the AI NOC portal. API tests check `/auth/me` portals and permissions per role. |
| Cross-tenant suite: 0 leaks across all routes | **Pass** | `test_isolation_api.py` derives every ID-taking route from the OpenAPI document and calls it as Globex with Initech IDs. Every call is refused (403/404/409/422), and Initech's data is byte-identical afterwards. `test_db_security.py` proves the same at the database level, bypassing the API. |
| Audit chain verifies; manual DB tamper is detected | **Pass** (with one documented limitation) | A modified entry and a deleted middle entry are both detected. Deleting the newest entries is not detectable from the chain alone; external anchors close this in P7 (residual risk, threat model §7). |
| MFA enforced for privileged roles | **Pass** | Privileged users get `mfa_required` or `mfa_enrollment_required`. TOTP codes cannot be replayed, challenges are single-use, and sensitive changes need a step-up in the last 5 minutes. |
| MSP: analyst sees only delegated customers; aggregate rejects writes at DB level; revocation on next request; customer sees MSP actions in own audit log | **Pass** | `test_msp.py`, `test_db_security.py` (aggregate role is SELECT-only in a READ ONLY transaction), E2E MSP journey. |

## Test results (all green)

| Suite | Count | Runs against |
|-------|-------|--------------|
| Backend unit + integration (`pytest`) | 102 | Disposable Postgres 17 + Valkey containers, real migrations and seed |
| Frontend unit (`vitest`) | 6 | — |
| Browser journeys (`pnpm e2e`) | 6 | Live dev stack in Microsoft Edge |
| CI gates (`scripts\ci.ps1`) | 14/14 | ruff, mypy strict, import-linter, bandit, pytest, OpenAPI drift, pip-audit, eslint, typecheck, vitest, npm audit, next build, compose policy, gitleaks |

## Delivered

**Backend**
- Schema (migration `0001`): tenants with MSP→customer hierarchy, users, credentials, sessions, challenges, invitations, permissions, roles, role bindings, delegations, API keys and the hash-chained audit log.
- Database roles (ADR-0018): `FORCE ROW LEVEL SECURITY` on every tenant-owned table, a read-only aggregate role, and audit entries appended only through a `SECURITY DEFINER` function that a trigger keeps append-only.
- Identity: Argon2id passwords, TOTP MFA (with enrollment and replay protection), step-up, opaque sessions with absolute and idle expiry, sign-in rate limiting in Valkey, invitations by email (Mailpit), and API keys that never exceed what their creator can do.
- Authorization: a 50-permission catalog and 11 system roles. Custom roles per tenant. Effective permissions are recomputed on every request, so revocation is immediate. Escalation is blocked: you cannot grant permissions you do not hold.
- MSP (ADR-0016): customer onboarding (tenant + default delegation + admin invitation), delegations that both sides can see and revoke, the read-only "All customers" view, and delegated actions mirrored into both audit chains.
- Platform admin: creates MSP tenants, with no access to tenant data.
- Committed OpenAPI contract with a CI drift check. RFC 9457 error responses.

**Frontend**
- Sign-in, MFA, MFA enrollment and invitation-acceptance pages.
- BFF session in an HttpOnly, SameSite=Strict cookie; all mutations are Server Actions (ADR-0017).
- Portal shell with NOC, SOC, Command Center and Admin; tenant switcher including "All customers"; delegated-access and read-only badges.
- Admin pages: tenant, members (invite, roles, suspend, remove), roles, API keys (shown once), audit log (with chain status), delegations or "MSP access", customers (MSP onboarding) and platform.
- TypeScript types generated from the OpenAPI contract.

**Infrastructure**
- `migrate` one-shot service.
- Two new secrets: identity database password and master key.
- `scripts\dev.ps1 seed | totp | migrate`.
- Playwright E2E workspace using the installed Edge.

## Bugs found and fixed during P1 (worth knowing)

1. **Audit access check returned NULL instead of false.** This would have let the application append to *any* tenant's audit chain. A test caught it, and it is fixed with a regression test (ADR-0018).
2. **The route-coverage test was passing vacuously.** FastAPI 0.163 no longer lists included routes on `app.routes`, so the test checked nothing. It now reads the OpenAPI document and asserts a minimum route count.
3. **Escalation rule blocked tenant admins.** They lacked permissions they were expected to grant. `tenant_admin` now holds every permission, and MSP-only permissions don't count toward escalation inside customer tenants.
4. **The header showed the old tenant after switching** (Next.js keeps layouts across navigation). The switch now refreshes the layout tree. Found by E2E.
5. **Forms lost input after a failed action** (React 19 resets forms automatically). Found by E2E.
6. Windows-only: psycopg async needs the selector event loop (tests only; containers run Linux). Client addresses that aren't IPs (proxies, unix sockets) are now stored as NULL instead of crashing the session insert.

## Deviations from the design docs (recorded in the docs)

- Opaque server-side sessions instead of BFF→API JWTs; Server Actions instead of double-submit CSRF tokens; Cache Components off (ADR-0017).
- UUIDv4 instead of v7 (PostgreSQL 17 has no native v7).
- The `secrets` table moves to P2 with connector credentials. TOTP seeds are already envelope-encrypted.
- Not yet implemented: `ETag`/`If-Match`, `Idempotency-Key` and general `RateLimit-*` headers (they arrive with the first resources that need them). The audit log pages by `?before=<id>`.

## Residual risks (threat model §7)

- **Audit tail truncation** is not detectable without external anchors (P7).
- **Mid-session privilege gain:** a user granted a privileged role cannot step up until they enroll MFA at their next sign-in.
- **Dev cookies are not `Secure`** over local http (P7 TLS).

## Notes for you

- **Git identity:** P0 was committed with a repo-local identity built from your account email (`friendlyrakhi`). Change it with `git config user.name "…"` and amend if you prefer.
- **TOTP for seeded users:** `scripts\dev.ps1 totp <email>`, or add the `totp_secret` from `dev-users.json` to an authenticator app.
- **Invitations** appear in Mailpit at http://127.0.0.1:8025.

## Next: P2 (connector SDK, sandbox connectors, ingestion pipeline)

Adds the `stream` and `analytics` profiles (Redpanda, ClickHouse), connector SDK v1, connector-runner, ingest-worker, 15 sandbox connectors plus a generic webhook connector, scenario packs, and the first alert queues. **Awaiting your go-ahead.**
