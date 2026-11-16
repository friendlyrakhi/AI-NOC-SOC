# ADR-0002: Shared-schema multi-tenancy with Postgres RLS

- Status: accepted
- Date: 2026-11-16
- Decision ID: D2 (docs/10-decisions-for-approval.md)

## Context
Tenant isolation is the highest-impact confidentiality control (threat model T6-T11).

## Decision
Shared database and schema, `tenant_id` on every tenant-owned row, `FORCE ROW LEVEL SECURITY`, and a non-owner app role without BYPASSRLS. ClickHouse uses row policies. OpenSearch uses per-tenant indices. P0 already creates `nocsoc_app` as NOSUPERUSER NOBYPASSRLS.

## Alternatives considered
Schema-per-tenant; database-per-tenant.

## Consequences
A cross-tenant test suite is a release gate from P1. Large tenants can later be routed to dedicated stores.
