"""MSP: customer onboarding, delegations, read-only aggregate views (ADR-0016)."""

from datetime import datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query, status
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from app.core import audit
from app.core.authz.deps import get_principal, requires
from app.core.authz.principal import Principal
from app.core.identity.service import IdentityService
from app.core.tenancy.common import record, tenant_tx
from app.errors import ProblemError, forbidden, not_found
from app.services import Services, get_services

router = APIRouter(tags=["msp"])

Svc = Annotated[Services, Depends(get_services)]
P = Annotated[Principal, Depends(get_principal)]


def _require_msp(p: Principal) -> None:
    if p.tenant_kind != "msp" or p.via_msp_tenant_id is not None:
        raise ProblemError(409, "tenant.not_msp", "MSP tenant required", "Switch to your MSP tenant first.")


# ============================================================ customers
class CustomerOut(BaseModel):
    id: UUID
    name: str
    slug: str
    status: str
    created_at: datetime
    active_delegations: int


class DelegationSpec(BaseModel):
    msp_role_id: UUID
    customer_role_key: str = Field(pattern=r"^[a-z][a-z0-9_]{1,62}$")
    aggregate_read: bool = True
    expires_at: datetime | None = None


class CustomerCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    slug: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{1,62}$")
    admin_email: EmailStr
    admin_name: str = Field(min_length=1, max_length=200)
    delegations: list[DelegationSpec] = Field(default_factory=list, max_length=20)


class CustomerCreated(BaseModel):
    id: UUID
    admin_user_id: UUID
    invitation_sent: bool
    delegation_ids: list[UUID]


@router.get("/customers", response_model=list[CustomerOut], **requires("msp:customers:read"))
async def list_customers(services: Svc, p: P) -> list[CustomerOut]:
    _require_msp(p)
    async with tenant_tx(services, p) as conn:
        rows = await conn.execute(
            text(
                "SELECT t.id, t.name, t.slug::text AS slug, t.status, t.created_at, "
                "(SELECT count(*) FROM delegations d WHERE d.customer_tenant_id = t.id AND d.revoked_at IS NULL "
                " AND (d.expires_at IS NULL OR d.expires_at > now())) AS active_delegations "
                "FROM tenants t WHERE t.parent_tenant_id = app_tenant() ORDER BY t.name"
            )
        )
        return [CustomerOut(**r._mapping) for r in rows]


async def _insert_delegation(conn, p: Principal, customer_id: UUID, spec: DelegationSpec) -> UUID:  # type: ignore[no-untyped-def]
    customer_role = (
        await conn.execute(text("SELECT id FROM roles WHERE key = :k AND is_system"), {"k": spec.customer_role_key})
    ).scalar_one_or_none()
    if customer_role is None:
        raise ProblemError(422, "validation.failed", "Unknown role", "Customer role must be a system role.")
    try:
        async with conn.begin_nested():
            delegation_id = (
                await conn.execute(
                    text(
                        "INSERT INTO delegations (msp_tenant_id, customer_tenant_id, msp_role_id, customer_role_id, "
                        "aggregate_read, expires_at, created_by) VALUES (app_tenant(), :c, :mr, :cr, :agg, :exp, :by) "
                        "RETURNING id"
                    ),
                    {
                        "c": customer_id,
                        "mr": spec.msp_role_id,
                        "cr": customer_role,
                        "agg": spec.aggregate_read,
                        "exp": spec.expires_at,
                        "by": p.user_id,
                    },
                )
            ).scalar_one()
    except IntegrityError as exc:
        raise ProblemError(
            422, "validation.failed", "Invalid delegation", "Check the customer and the MSP role."
        ) from exc
    details = {
        "msp_role_id": str(spec.msp_role_id),
        "customer_role": spec.customer_role_key,
        "aggregate_read": spec.aggregate_read,
        "expires_at": spec.expires_at,
    }
    await record(
        conn,
        p,
        "delegation.create",
        target_type="delegation",
        target_id=delegation_id,
        details={**details, "customer_tenant_id": str(customer_id)},
    )
    # The customer sees the grant in its own audit chain too (T33).
    await conn.execute(text("SELECT set_config('app.audit_mirror_tenant_id', :c, true)"), {"c": str(customer_id)})
    await audit.append(
        conn,
        tenant_id=customer_id,
        actor=p.actor,
        action="delegation.create",
        target_type="delegation",
        target_id=str(delegation_id),
        via_tenant_id=p.tenant_id,
        details=details,
    )
    await conn.execute(text("SELECT set_config('app.audit_mirror_tenant_id', '', true)"))
    return delegation_id  # type: ignore[no-any-return]


@router.post(
    "/customers",
    response_model=CustomerCreated,
    status_code=status.HTTP_201_CREATED,
    **requires("msp:customers:manage", step_up=True),
)
async def onboard_customer(body: CustomerCreate, services: Svc, p: P) -> CustomerCreated:
    """Creates the customer tenant and the MSP's delegations, then invites the customer's admin."""
    _require_msp(p)
    specs = body.delegations
    if not specs:
        # Default: MSP admins administer the customer and see it in "All customers".
        async with tenant_tx(services, p) as conn:
            admin_role = (
                await conn.execute(text("SELECT id FROM roles WHERE key = 'tenant_admin' AND is_system"))
            ).scalar_one()
        specs = [DelegationSpec(msp_role_id=admin_role, customer_role_key="tenant_admin", aggregate_read=True)]
    try:
        async with tenant_tx(services, p) as conn:
            customer_id = (
                await conn.execute(
                    text(
                        "INSERT INTO tenants (kind, parent_tenant_id, slug, name) "
                        "VALUES ('customer', app_tenant(), :s, :n) RETURNING id"
                    ),
                    {"s": body.slug, "n": body.name},
                )
            ).scalar_one()
            await record(
                conn,
                p,
                "msp.customer.create",
                target_type="tenant",
                target_id=customer_id,
                details={"slug": body.slug, "name": body.name},
            )
            delegation_ids = [await _insert_delegation(conn, p, customer_id, spec) for spec in specs]
            admin_role = (
                await conn.execute(text("SELECT id FROM roles WHERE key = 'tenant_admin' AND is_system"))
            ).scalar_one()
    except IntegrityError as exc:
        raise ProblemError(409, "tenant.slug_taken", "Slug in use", "That tenant slug is already in use.") from exc

    invite = await IdentityService(services).invite_member(
        tenant_id=customer_id,
        tenant_name=body.name,
        email=str(body.admin_email),
        display_name=body.admin_name,
        role_ids=[admin_role],
        inviter_actor=p.actor,
        via_tenant_id=p.tenant_id,
    )
    return CustomerCreated(
        id=customer_id,
        admin_user_id=invite.user_id,
        invitation_sent=invite.invitation_sent,
        delegation_ids=delegation_ids,
    )


# ============================================================ delegations
class TenantRef(BaseModel):
    id: UUID
    name: str | None


class DelegationOut(BaseModel):
    id: UUID
    direction: str  # outgoing (we are the MSP) | incoming (we are the customer)
    msp_tenant: TenantRef
    customer_tenant: TenantRef
    msp_role_key: str | None
    msp_role_name: str | None
    customer_role_key: str
    customer_role_name: str
    aggregate_read: bool
    expires_at: datetime | None
    created_at: datetime
    revoked_at: datetime | None
    active: bool


class DelegationCreate(DelegationSpec):
    customer_tenant_id: UUID


_DELEGATIONS_SQL = """
SELECT d.id,
       CASE WHEN d.msp_tenant_id = app_tenant() THEN 'outgoing' ELSE 'incoming' END AS direction,
       d.msp_tenant_id, mt.name AS msp_name, d.customer_tenant_id, ct.name AS customer_name,
       mr.key AS msp_role_key, mr.name AS msp_role_name, cr.key AS customer_role_key, cr.name AS customer_role_name,
       d.aggregate_read, d.expires_at, d.created_at, d.revoked_at,
       (d.revoked_at IS NULL AND (d.expires_at IS NULL OR d.expires_at > now())) AS active
  FROM delegations d
  LEFT JOIN tenants mt ON mt.id = d.msp_tenant_id
  LEFT JOIN tenants ct ON ct.id = d.customer_tenant_id
  LEFT JOIN roles mr ON mr.id = d.msp_role_id
  JOIN roles cr ON cr.id = d.customer_role_id
 WHERE true {extra}
 ORDER BY d.created_at DESC
"""


def _delegation_out(r) -> DelegationOut:  # type: ignore[no-untyped-def]
    return DelegationOut(
        id=r.id,
        direction=r.direction,
        msp_tenant=TenantRef(id=r.msp_tenant_id, name=r.msp_name),
        customer_tenant=TenantRef(id=r.customer_tenant_id, name=r.customer_name),
        msp_role_key=r.msp_role_key,
        msp_role_name=r.msp_role_name,
        customer_role_key=r.customer_role_key,
        customer_role_name=r.customer_role_name,
        aggregate_read=r.aggregate_read,
        expires_at=r.expires_at,
        created_at=r.created_at,
        revoked_at=r.revoked_at,
        active=r.active,
    )


@router.get("/delegations", response_model=list[DelegationOut], **requires("delegation:read"))
async def list_delegations(services: Svc, p: P) -> list[DelegationOut]:
    async with tenant_tx(services, p) as conn:
        rows = await conn.execute(text(_DELEGATIONS_SQL.format(extra="")))
        return [_delegation_out(r) for r in rows]


@router.post(
    "/delegations",
    response_model=DelegationOut,
    status_code=status.HTTP_201_CREATED,
    **requires("delegation:manage", step_up=True),
)
async def create_delegation(body: DelegationCreate, services: Svc, p: P) -> DelegationOut:
    _require_msp(p)
    async with tenant_tx(services, p) as conn:
        visible = (
            await conn.execute(
                text("SELECT 1 FROM tenants WHERE id = :c AND parent_tenant_id = app_tenant()"),
                {"c": body.customer_tenant_id},
            )
        ).first()
        if visible is None:
            raise not_found("Customer")
        delegation_id = await _insert_delegation(conn, p, body.customer_tenant_id, body)
        row = (await conn.execute(text(_DELEGATIONS_SQL.format(extra="AND d.id = :id")), {"id": delegation_id})).one()
    return _delegation_out(row)


@router.post(
    "/delegations/{delegation_id}/revoke",
    response_model=DelegationOut,
    **requires("delegation:manage", step_up=True),
)
async def revoke_delegation(delegation_id: UUID, services: Svc, p: P) -> DelegationOut:
    """Either side may revoke. Takes effect on the next request (permissions are not cached)."""
    async with tenant_tx(services, p) as conn:
        row = (
            await conn.execute(
                text(
                    "UPDATE delegations SET revoked_at = now(), revoked_by = :by "
                    "WHERE id = :id AND revoked_at IS NULL RETURNING msp_tenant_id, customer_tenant_id"
                ),
                {"id": delegation_id, "by": p.user_id},
            )
        ).first()
        if row is None:
            raise not_found("Active delegation")
        await record(conn, p, "delegation.revoke", target_type="delegation", target_id=delegation_id)
        other = row.customer_tenant_id if row.msp_tenant_id == p.tenant_id else row.msp_tenant_id
        if other != p.via_msp_tenant_id:  # record() already mirrored to the MSP for delegated callers
            await conn.execute(text("SELECT set_config('app.audit_mirror_tenant_id', :t, true)"), {"t": str(other)})
            await audit.append(
                conn,
                tenant_id=other,
                actor=p.actor,
                action="delegation.revoke",
                target_type="delegation",
                target_id=str(delegation_id),
                via_tenant_id=p.tenant_id,
            )
        out = (await conn.execute(text(_DELEGATIONS_SQL.format(extra="AND d.id = :id")), {"id": delegation_id})).one()
    return _delegation_out(out)


# ============================================================ aggregate (read-only)
class AggregateCustomerOut(BaseModel):
    id: UUID
    name: str
    slug: str
    status: str
    events_24h: int


class AggregateActivityOut(BaseModel):
    id: int
    tenant_id: UUID
    tenant_name: str
    at: datetime
    actor_type: str
    action: str
    outcome: str
    target_type: str | None


@router.get(
    "/aggregate/customers",
    response_model=list[AggregateCustomerOut],
    **requires("msp:aggregate_read", aggregate=True),
)
async def aggregate_customers(services: Svc, p: P) -> list[AggregateCustomerOut]:
    if not p.aggregate_tenant_ids:
        return []
    async with services.app_db.aggregate(p.aggregate_tenant_ids, p.user_id) as conn:
        rows = await conn.execute(
            text(
                "SELECT t.id, t.name, t.slug::text AS slug, t.status, "
                "(SELECT count(*) FROM audit_log a WHERE a.tenant_id = t.id AND a.at > now() - interval '24 hours') "
                "AS events_24h FROM tenants t WHERE t.id = ANY (app_tenant_ids()) ORDER BY t.name"
            )
        )
        return [AggregateCustomerOut(**r._mapping) for r in rows]


@router.get(
    "/aggregate/activity",
    response_model=list[AggregateActivityOut],
    **requires("msp:aggregate_read", aggregate=True),
)
async def aggregate_activity(
    services: Svc, p: P, limit: Annotated[int, Query(ge=1, le=200)] = 50
) -> list[AggregateActivityOut]:
    if not p.has("audit:read"):
        raise forbidden("Cross-customer activity also requires audit:read.")
    if not p.aggregate_tenant_ids:
        return []
    async with services.app_db.aggregate(p.aggregate_tenant_ids, p.user_id) as conn:
        rows = await conn.execute(
            text(
                "SELECT a.id, a.tenant_id, t.name AS tenant_name, a.at, a.actor_type, a.action, a.outcome, "
                "a.target_type FROM audit_log a JOIN tenants t ON t.id = a.tenant_id "
                "ORDER BY a.id DESC LIMIT :limit"
            ),
            {"limit": limit},
        )
        return [AggregateActivityOut(**r._mapping) for r in rows]
