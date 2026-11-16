"""Effective-permission evaluation (RBAC + MSP delegations, ADR-0016).

Runs on the identity connection (``nocsoc_auth``) because it must look across tenants:
a user's own memberships, and an MSP's delegations into a customer. Results are computed
per request, so revoking a membership, role or delegation applies on the next request.
"""

from dataclasses import dataclass
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

from app.core.authz.catalog import effective_for_tenant_kind


def _user_delegations(select: str, extra_join: str = "", extra_where: str = "") -> str:
    """Active delegations that apply to user ``:u`` through their MSP role bindings.

    All fragments are constants defined in this module (never user input).
    """
    # Bandit B608 reviewed: only module constants are interpolated; all values are bound parameters.
    return (
        f"SELECT {select} "  # nosec B608
        "FROM delegations d "
        "JOIN tenants c ON c.id = d.customer_tenant_id AND c.status = 'active' "
        "JOIN tenants msp ON msp.id = d.msp_tenant_id AND msp.status = 'active' "
        "JOIN memberships m ON m.tenant_id = d.msp_tenant_id AND m.user_id = :u AND m.status = 'active' "
        "JOIN role_bindings rb ON rb.membership_id = m.id AND rb.role_id = d.msp_role_id "
        f"{extra_join} "
        "WHERE d.revoked_at IS NULL AND (d.expires_at IS NULL OR d.expires_at > now()) "
        f"{extra_where}"
    )


@dataclass(frozen=True)
class TenantAccess:
    tenant_id: UUID
    name: str
    slug: str
    kind: str
    access: str  # member | delegated
    via_msp_tenant_id: UUID | None


@dataclass(frozen=True)
class TenantPermissions:
    tenant_id: UUID
    tenant_kind: str
    permissions: frozenset[str]
    via_msp_tenant_id: UUID | None


async def accessible_tenants(conn: AsyncConnection, user_id: UUID) -> list[TenantAccess]:
    delegated = _user_delegations(
        "DISTINCT c.id, c.name, c.slug::text, c.kind, 'delegated', d.msp_tenant_id",
        extra_where=(
            "AND NOT EXISTS (SELECT 1 FROM memberships dm WHERE dm.tenant_id = c.id "
            "AND dm.user_id = :u AND dm.status = 'active')"
        ),
    )
    rows = await conn.execute(
        text(
            "SELECT t.id, t.name, t.slug::text AS slug, t.kind, 'member' AS access, NULL::uuid AS via "  # nosec B608
            "FROM memberships m JOIN tenants t ON t.id = m.tenant_id "
            "WHERE m.user_id = :u AND m.status = 'active' AND t.status = 'active' "
            f"UNION {delegated} ORDER BY 2"
        ),
        {"u": user_id},
    )
    return [TenantAccess(r.id, r.name, r.slug, r.kind, r.access, r.via) for r in rows]


async def tenant_permissions(conn: AsyncConnection, user_id: UUID, tenant_id: UUID) -> TenantPermissions | None:
    """Permissions of ``user_id`` in ``tenant_id``, or None if the user has no access."""
    tenant = (
        await conn.execute(text("SELECT kind FROM tenants WHERE id = :t AND status = 'active'"), {"t": tenant_id})
    ).first()
    if tenant is None:
        return None

    direct = (
        await conn.execute(
            text(
                "SELECT m.id AS membership_id, rp.permission_key FROM memberships m "
                "LEFT JOIN role_bindings rb ON rb.membership_id = m.id "
                "LEFT JOIN role_permissions rp ON rp.role_id = rb.role_id "
                "WHERE m.user_id = :u AND m.tenant_id = :t AND m.status = 'active'"
            ),
            {"u": user_id, "t": tenant_id},
        )
    ).all()
    delegated = (
        await conn.execute(
            text(
                _user_delegations(
                    "rp.permission_key, d.msp_tenant_id",
                    extra_join="JOIN role_permissions rp ON rp.role_id = d.customer_role_id",
                    extra_where="AND d.customer_tenant_id = :t",
                )
            ),
            {"u": user_id, "t": tenant_id},
        )
    ).all()

    is_member = len(direct) > 0
    if not is_member and not delegated:
        return None
    perms = {r.permission_key for r in direct if r.permission_key} | {r.permission_key for r in delegated}
    return TenantPermissions(
        tenant_id=tenant_id,
        tenant_kind=tenant.kind,
        permissions=effective_for_tenant_kind(frozenset(perms), tenant.kind),
        via_msp_tenant_id=None if is_member else delegated[0].msp_tenant_id,
    )


async def aggregate_tenant_ids(conn: AsyncConnection, user_id: UUID, msp_tenant_id: UUID) -> tuple[UUID, ...]:
    """Customers visible to ``user_id`` in the MSP's read-only "All customers" view."""
    rows = await conn.execute(
        text(
            _user_delegations(
                "DISTINCT d.customer_tenant_id",
                extra_where="AND d.msp_tenant_id = :msp AND d.aggregate_read",
            )
            + " ORDER BY 1"
        ),
        {"u": user_id, "msp": msp_tenant_id},
    )
    return tuple(r.customer_tenant_id for r in rows)


async def holds_privileged_anywhere(conn: AsyncConnection, user_id: UUID) -> bool:
    """True if any role the user holds (directly or via delegation) has a privileged permission."""
    via_delegation = _user_delegations(
        "1",
        extra_join=(
            "JOIN role_permissions rp ON rp.role_id = d.customer_role_id "
            "JOIN permissions p ON p.key = rp.permission_key AND p.privileged"
        ),
    )
    row = (
        await conn.execute(
            text(
                "SELECT EXISTS (SELECT 1 FROM memberships m "  # nosec B608
                "JOIN role_bindings rb ON rb.membership_id = m.id "
                "JOIN role_permissions rp ON rp.role_id = rb.role_id "
                "JOIN permissions p ON p.key = rp.permission_key AND p.privileged "
                "WHERE m.user_id = :u AND m.status = 'active') "
                f"OR EXISTS ({via_delegation}) AS privileged"
            ),
            {"u": user_id},
        )
    ).one()
    return bool(row.privileged)
