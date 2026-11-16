"""Helpers shared by tenant-scoped routers."""

from collections.abc import AsyncIterator, Iterable
from contextlib import asynccontextmanager
from typing import Any
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

from app.core import audit
from app.core.authz.catalog import effective_for_tenant_kind
from app.core.authz.principal import Principal
from app.errors import ProblemError
from app.services import Services


@asynccontextmanager
async def tenant_tx(services: Services, principal: Principal) -> AsyncIterator[AsyncConnection]:
    """RLS transaction for the principal's tenant. Delegated callers may also append to
    their MSP's audit chain (ADR-0016 §6)."""
    if principal.tenant_id is None:
        raise ProblemError(409, "tenant.none_selected", "No tenant selected", "Select a tenant first.")
    async with services.app_db.tenant(
        principal.tenant_id, principal.user_id, audit_mirror_tenant_id=principal.via_msp_tenant_id
    ) as conn:
        yield conn


async def record(
    conn: AsyncConnection,
    principal: Principal,
    action: str,
    *,
    target_type: str | None = None,
    target_id: str | UUID | None = None,
    details: dict[str, Any] | None = None,
    outcome: str = "success",
) -> None:
    """Audit an action in the tenant chain, and mirror it to the MSP chain if delegated."""
    tid = str(target_id) if target_id is not None else None
    await audit.append(
        conn,
        tenant_id=principal.tenant_id,
        actor=principal.actor,
        action=action,
        outcome=outcome,
        target_type=target_type,
        target_id=tid,
        details=details,
        via_tenant_id=principal.via_msp_tenant_id,
    )
    if principal.via_msp_tenant_id is not None:
        await audit.append(
            conn,
            tenant_id=principal.via_msp_tenant_id,
            actor=principal.actor,
            action=action,
            outcome=outcome,
            target_type=target_type,
            target_id=tid,
            details={**(details or {}), "delegated_into": str(principal.tenant_id)},
        )


async def role_permission_sets(conn: AsyncConnection, role_ids: Iterable[UUID]) -> dict[UUID, set[str]]:
    """Permissions per role, for roles visible to the tenant. Unknown roles raise 422."""
    ids = list(dict.fromkeys(role_ids))
    if not ids:
        return {}
    rows = await conn.execute(
        text(
            "SELECT r.id, rp.permission_key FROM roles r "
            "LEFT JOIN role_permissions rp ON rp.role_id = r.id WHERE r.id = ANY(:ids)"
        ),
        {"ids": ids},
    )
    out: dict[UUID, set[str]] = {}
    for r in rows:
        out.setdefault(r.id, set())
        if r.permission_key:
            out[r.id].add(r.permission_key)
    missing = [str(i) for i in ids if i not in out]
    if missing:
        raise ProblemError(422, "validation.failed", "Unknown role", f"Unknown role(s): {', '.join(missing)}")
    return out


def check_no_escalation(principal: Principal, permissions: Iterable[str]) -> None:
    """A caller can never grant permissions they do not hold themselves.

    Only permissions that can take effect in this tenant count: MSP-only permissions inside
    a system role are inert in a customer tenant, so they do not block an assignment there.
    """
    effective = effective_for_tenant_kind(frozenset(permissions), principal.tenant_kind or "customer")
    excess = sorted(effective - principal.permissions)
    if excess:
        raise ProblemError(
            403,
            "authz.escalation",
            "Cannot grant permissions you do not hold",
            f"You do not hold: {', '.join(excess)}",
        )
