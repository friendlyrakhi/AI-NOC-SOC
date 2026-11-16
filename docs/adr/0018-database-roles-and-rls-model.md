# ADR-0018: Database roles, RLS enforcement and audit append path

- Status: accepted
- Date: 2026-11-16
- Refines: ADR-0002 (tenancy), ADR-0016 (MSP)

## Context
Tenant isolation must hold even if application code has a bug. Some operations are inherently cross-tenant: signing in, listing a user's tenants, and evaluating MSP delegations into a customer.

## Decision
| Role | Login | RLS | Used by | Grants |
|------|-------|-----|---------|--------|
| `nocsoc_owner` | no | bypass | migrations (`SET ROLE`), `SECURITY DEFINER` functions | owns all objects |
| `nocsoc_app` | yes | **enforced** (FORCE) | every tenant-data query in the API | minimal, column-level for updates |
| `nocsoc_aggregate` | no | enforced | MSP "All customers" view, entered with `SET LOCAL ROLE` in a READ ONLY transaction | SELECT on aggregate-readable tables only |
| `nocsoc_auth` | yes | bypass | identity only (`app.core.identity`, `app.core.authz`) | identity tables; no tenant operational data |
| `postgres` | yes | bypass | `migrate` and dev `seed` containers only; never the API | superuser |

- Tenant context is set per transaction with `set_config(..., is_local => true)`. Missing context matches no rows (fail closed).
- Identity-only tables (`sessions`, `user_credentials`, `auth_challenges`, `invitations`) have RLS enabled **with no policies**, so the application role cannot read them even if grants were added by mistake.
- **Audit entries are appended only through `audit_append()`** (`SECURITY DEFINER`). The application has no INSERT/UPDATE/DELETE on `audit_log`, and a trigger blocks UPDATE/DELETE/TRUNCATE even for the owner. The function allows only the current tenant, an explicitly set mirror tenant (delegated actions), or the identity role.
- Every table must be classified in `backend/tests/integration/test_db_security.py`. A new table fails the suite until its isolation model is decided.

## Consequences
- The API holds two database credentials (`nocsoc_app`, `nocsoc_auth`). Import-linter keeps the identity engine inside the identity/authz packages.
- A regression found during P1: a PL/pgSQL access check returned NULL (not false) for an unset setting, and `IF NOT NULL` does not raise. The check now coalesces to false, and a regression test covers it. Any future security function must be written the same way.
