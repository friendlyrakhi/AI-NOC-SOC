# ADR-0016: MSP tenancy, delegated access and aggregate views

- Status: accepted
- Date: 2026-11-16
- Decision ID: open question 1 (docs/10-decisions-for-approval.md), answered "yes, we serve multiple customer organizations"

## Context
The platform is operated by an MSP for several customer organizations. MSP analysts need to work in a customer's tenant and also watch queues and KPIs across customers. Customers must still be strictly isolated from each other, and must be able to see and control what the MSP can access. ADR-0002 (one tenant per request, RLS) assumed single-tenant context.

## Decision
1. **Two tenant kinds, one level:** `msp` and `customer` (customer.parent = its MSP). Deeper hierarchies are out of scope.
2. **Delegations, not inheritance.** MSP membership never implies customer access. A delegation maps an MSP role to a role in one customer tenant, with optional expiry and an `aggregate_read` flag. Customer admins can see and revoke delegations.
3. **Single-customer mode (default, read/write):** unchanged from ADR-0002. `app.tenant_id` is set per transaction under the normal RLS policies.
4. **Aggregate mode ("All customers", read-only):** a separate DB role `app_ro_aggregate` with SELECT-only grants and policies on `tenant_id = ANY(app.tenant_ids)`. The tenant list is computed **per request from active delegations**, never taken from the token. Aggregate endpoints are GET-only.
5. **AI never runs in aggregate mode.** Evidence sets must come from a single tenant, so no prompt can mix customers.
6. **Audit:** actions taken through a delegation are recorded in the MSP tenant's chain **and** mirrored into the customer's chain.

## Alternatives considered
- Parent membership grants access to all children: simpler, but violates least privilege and gives customers no visibility or control.
- Aggregate views built by fanning out one query per tenant: safe but slow for KPI and queue views; could be kept as a fallback.
- A separate database per customer: strongest isolation, but makes aggregate views and operations far heavier (revisit for very large or regulated customers).

## Consequences
- P1 grows from L to XL (delegations, aggregate role and policies, MSP admin UI, extra isolation tests SEC-ISO-06/07, SEC-AUD-03).
- Every new tenant-owned table needs both the tenant policy and the aggregate SELECT policy. A test will enumerate tables to enforce this.
- Per-customer branding, data residency and billing remain out of scope.
