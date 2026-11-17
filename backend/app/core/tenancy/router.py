"""Tenant administration (docs/05-api-specification.md §2.2, §2.11).

Every query runs in an RLS transaction scoped to the caller's tenant. IDs from other
tenants are invisible, so they produce 404 rather than 403 (threat model T6).
"""

from datetime import datetime
from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Response, status
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from app.core import audit
from app.core.authz.catalog import MSP_ONLY, PERMISSIONS, PRIVILEGED
from app.core.authz.deps import get_principal, requires
from app.core.authz.principal import Principal
from app.core.identity.service import IdentityService
from app.core.security import API_KEY_PREFIX, new_token, token_hash
from app.core.tenancy.common import (
    check_no_escalation,
    record,
    role_permission_sets,
    tenant_tx,
)
from app.core.types import PG_BIGINT_MAX, StrictInt
from app.errors import ProblemError, not_found
from app.services import Services, get_services

router = APIRouter(tags=["tenant administration"])

Svc = Annotated[Services, Depends(get_services)]
P = Annotated[Principal, Depends(get_principal)]


# ============================================================ tenant
class TenantOut(BaseModel):
    id: UUID
    kind: str
    slug: str
    name: str
    status: str
    parent_tenant_id: UUID | None
    created_at: datetime


class TenantPatch(BaseModel):
    name: str = Field(min_length=1, max_length=200)


@router.get("/tenant", response_model=TenantOut, **requires("tenant:read"))
async def get_tenant(services: Svc, p: P) -> TenantOut:
    async with tenant_tx(services, p) as conn:
        row = (
            await conn.execute(
                text(
                    "SELECT id, kind, slug::text AS slug, name, status, parent_tenant_id, "
                    "created_at FROM tenants WHERE id = app_tenant()"
                )
            )
        ).one()
    return TenantOut(**row._mapping)


@router.patch("/tenant", response_model=TenantOut, **requires("tenant:update", step_up=True))
async def patch_tenant(body: TenantPatch, services: Svc, p: P) -> TenantOut:
    async with tenant_tx(services, p) as conn:
        row = (
            await conn.execute(
                text(
                    "UPDATE tenants SET name = :n, updated_at = now(), version = version + 1 "
                    "WHERE id = app_tenant() RETURNING id, kind, slug::text AS slug, name, status, "
                    "parent_tenant_id, created_at"
                ),
                {"n": body.name},
            )
        ).one()
        await record(conn, p, "tenant.update", target_type="tenant", target_id=p.tenant_id, details={"name": body.name})
    return TenantOut(**row._mapping)


# ============================================================ members
class RoleRef(BaseModel):
    id: UUID
    key: str
    name: str


class MemberOut(BaseModel):
    user_id: UUID
    email: str
    display_name: str
    user_status: str
    membership_status: str
    last_login_at: datetime | None
    roles: list[RoleRef]


class InviteRequest(BaseModel):
    email: EmailStr
    display_name: str = Field(min_length=1, max_length=200)
    role_ids: list[UUID] = Field(default_factory=list, max_length=20)


class InviteResponse(BaseModel):
    user_id: UUID
    invitation_sent: bool
    created_user: bool


class MemberPatch(BaseModel):
    status: Literal["active", "suspended"]


class RoleAssignment(BaseModel):
    role_ids: list[UUID] = Field(max_length=20)


_MEMBERS_SQL = """
SELECT u.id AS user_id, u.email::text AS email, u.display_name, u.status AS user_status,
       m.status AS membership_status, u.last_login_at,
       coalesce(json_agg(json_build_object('id', r.id, 'key', r.key, 'name', r.name) ORDER BY r.name)
                FILTER (WHERE r.id IS NOT NULL), '[]') AS roles
  FROM memberships m
  JOIN users u ON u.id = m.user_id
  LEFT JOIN role_bindings rb ON rb.membership_id = m.id
  LEFT JOIN roles r ON r.id = rb.role_id
 WHERE m.tenant_id = app_tenant() {extra}
 GROUP BY u.id, m.id
 ORDER BY u.display_name
"""


@router.get("/users", response_model=list[MemberOut], **requires("user:read"))
async def list_members(services: Svc, p: P) -> list[MemberOut]:
    async with tenant_tx(services, p) as conn:
        rows = await conn.execute(text(_MEMBERS_SQL.format(extra="")))
        return [MemberOut(**r._mapping) for r in rows]


async def _membership(conn, user_id: UUID):  # type: ignore[no-untyped-def]
    row = (
        await conn.execute(
            text("SELECT id, status FROM memberships WHERE tenant_id = app_tenant() AND user_id = :u"), {"u": user_id}
        )
    ).first()
    if row is None:
        raise not_found("Member")
    return row


@router.get("/users/{user_id}", response_model=MemberOut, **requires("user:read"))
async def get_member(user_id: UUID, services: Svc, p: P) -> MemberOut:
    async with tenant_tx(services, p) as conn:
        row = (await conn.execute(text(_MEMBERS_SQL.format(extra="AND u.id = :u")), {"u": user_id})).first()
    if row is None:
        raise not_found("Member")
    return MemberOut(**row._mapping)


@router.post("/users", response_model=InviteResponse, status_code=status.HTTP_201_CREATED, **requires("user:invite"))
async def invite_member(body: InviteRequest, services: Svc, p: P) -> InviteResponse:
    if body.role_ids and not p.has("role:assign"):
        raise ProblemError(403, "authz.forbidden", "Forbidden", "Assigning roles requires role:assign.")
    async with tenant_tx(services, p) as conn:
        sets = await role_permission_sets(conn, body.role_ids)
        tenant_name = (await conn.execute(text("SELECT name FROM tenants WHERE id = app_tenant()"))).scalar_one()
    check_no_escalation(p, set().union(*sets.values()) if sets else set())
    if p.tenant_id is None:
        raise ProblemError(409, "tenant.none_selected", "No tenant selected", "Select a tenant first.")
    result = await IdentityService(services).invite_member(
        tenant_id=p.tenant_id,
        tenant_name=tenant_name,
        email=str(body.email),
        display_name=body.display_name,
        role_ids=list(sets),
        inviter_actor=p.actor,
        via_tenant_id=p.via_msp_tenant_id,
    )
    return InviteResponse(
        user_id=result.user_id, invitation_sent=result.invitation_sent, created_user=result.created_user
    )


def _not_self(p: Principal, user_id: UUID) -> None:
    if p.user_id == user_id:
        raise ProblemError(409, "user.self_change", "Not allowed on yourself", "Ask another administrator.")


@router.patch("/users/{user_id}", response_model=MemberOut, **requires("user:update", step_up=True))
async def patch_member(user_id: UUID, body: MemberPatch, services: Svc, p: P) -> MemberOut:
    _not_self(p, user_id)
    async with tenant_tx(services, p) as conn:
        m = await _membership(conn, user_id)
        await conn.execute(text("UPDATE memberships SET status = :s WHERE id = :id"), {"s": body.status, "id": m.id})
        await record(
            conn, p, "user.membership.update", target_type="user", target_id=user_id, details={"status": body.status}
        )
        row = (await conn.execute(text(_MEMBERS_SQL.format(extra="AND u.id = :u")), {"u": user_id})).one()
    return MemberOut(**row._mapping)


@router.delete("/users/{user_id}", status_code=status.HTTP_204_NO_CONTENT, **requires("user:remove", step_up=True))
async def remove_member(user_id: UUID, services: Svc, p: P) -> Response:
    _not_self(p, user_id)
    async with tenant_tx(services, p) as conn:
        m = await _membership(conn, user_id)
        await conn.execute(text("DELETE FROM memberships WHERE id = :id"), {"id": m.id})
        await record(conn, p, "user.remove", target_type="user", target_id=user_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.put("/users/{user_id}/roles", response_model=MemberOut, **requires("role:assign", step_up=True))
async def assign_roles(user_id: UUID, body: RoleAssignment, services: Svc, p: P) -> MemberOut:
    _not_self(p, user_id)
    async with tenant_tx(services, p) as conn:
        m = await _membership(conn, user_id)
        sets = await role_permission_sets(conn, body.role_ids)
        check_no_escalation(p, set().union(*sets.values()) if sets else set())
        await conn.execute(text("DELETE FROM role_bindings WHERE membership_id = :m"), {"m": m.id})
        for role_id in sets:
            await conn.execute(
                text(
                    "INSERT INTO role_bindings (tenant_id, membership_id, role_id, created_by) "
                    "VALUES (app_tenant(), :m, :r, :by)"
                ),
                {"m": m.id, "r": role_id, "by": p.user_id},
            )
        await record(
            conn,
            p,
            "user.roles.assign",
            target_type="user",
            target_id=user_id,
            details={"roles": [str(r) for r in sets]},
        )
        row = (await conn.execute(text(_MEMBERS_SQL.format(extra="AND u.id = :u")), {"u": user_id})).one()
    return MemberOut(**row._mapping)


# ============================================================ roles & permissions
class PermissionOut(BaseModel):
    key: str
    description: str
    privileged: bool
    msp_only: bool


class RoleOut(BaseModel):
    id: UUID
    key: str
    name: str
    description: str
    is_system: bool
    permissions: list[str]


class RoleCreate(BaseModel):
    key: str = Field(pattern=r"^[a-z][a-z0-9_]{1,62}$")
    name: str = Field(min_length=1, max_length=100)
    description: str = Field(default="", max_length=500)
    permissions: list[str] = Field(max_length=len(PERMISSIONS))


class RolePatch(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=100)
    description: str | None = Field(default=None, max_length=500)
    permissions: list[str] | None = Field(default=None, max_length=len(PERMISSIONS))


_ROLES_SQL = """
SELECT r.id, r.key, r.name, r.description, r.is_system,
       coalesce(array_agg(rp.permission_key ORDER BY rp.permission_key)
                FILTER (WHERE rp.permission_key IS NOT NULL), '{{}}') AS permissions
  FROM roles r LEFT JOIN role_permissions rp ON rp.role_id = r.id
 WHERE true {extra}
 GROUP BY r.id ORDER BY r.is_system DESC, r.name
"""


@router.get("/permissions", response_model=list[PermissionOut], **requires("role:read"))
async def list_permissions(p: P) -> list[PermissionOut]:
    return [
        PermissionOut(key=k, description=d, privileged=k in PRIVILEGED, msp_only=k in MSP_ONLY)
        for k, d in PERMISSIONS.items()
        if p.tenant_kind == "msp" or k not in MSP_ONLY
    ]


@router.get("/roles", response_model=list[RoleOut], **requires("role:read"))
async def list_roles(services: Svc, p: P) -> list[RoleOut]:
    async with tenant_tx(services, p) as conn:
        rows = await conn.execute(text(_ROLES_SQL.format(extra="")))
        return [RoleOut(**r._mapping) for r in rows]


def _validate_permissions(p: Principal, perms: list[str]) -> list[str]:
    unknown = sorted(set(perms) - set(PERMISSIONS))
    if unknown:
        raise ProblemError(422, "validation.failed", "Unknown permission", f"Unknown: {', '.join(unknown)}")
    if p.tenant_kind != "msp" and set(perms) & MSP_ONLY:
        raise ProblemError(422, "validation.failed", "MSP-only permission", "MSP permissions are not available here.")
    check_no_escalation(p, perms)
    return sorted(set(perms))


async def _get_custom_role(conn, role_id: UUID):  # type: ignore[no-untyped-def]
    row = (await conn.execute(text("SELECT id, is_system FROM roles WHERE id = :id"), {"id": role_id})).first()
    if row is None:
        raise not_found("Role")
    if row.is_system:
        raise ProblemError(409, "role.system_immutable", "System role", "System roles cannot be changed.")
    return row


@router.post(
    "/roles", response_model=RoleOut, status_code=status.HTTP_201_CREATED, **requires("role:manage", step_up=True)
)
async def create_role(body: RoleCreate, services: Svc, p: P) -> RoleOut:
    perms = _validate_permissions(p, body.permissions)
    try:
        async with tenant_tx(services, p) as conn:
            role_id = (
                await conn.execute(
                    text(
                        "INSERT INTO roles (tenant_id, key, name, description) VALUES (app_tenant(), :k, :n, :d) "
                        "RETURNING id"
                    ),
                    {"k": body.key, "n": body.name, "d": body.description},
                )
            ).scalar_one()
            for perm in perms:
                await conn.execute(
                    text("INSERT INTO role_permissions (role_id, permission_key) VALUES (:r, :p)"),
                    {"r": role_id, "p": perm},
                )
            await record(
                conn,
                p,
                "role.create",
                target_type="role",
                target_id=role_id,
                details={"key": body.key, "permissions": perms},
            )
            row = (await conn.execute(text(_ROLES_SQL.format(extra="AND r.id = :id")), {"id": role_id})).one()
    except IntegrityError as exc:
        raise ProblemError(409, "role.key_taken", "Role key in use", "A role with this key already exists.") from exc
    return RoleOut(**row._mapping)


@router.patch("/roles/{role_id}", response_model=RoleOut, **requires("role:manage", step_up=True))
async def patch_role(role_id: UUID, body: RolePatch, services: Svc, p: P) -> RoleOut:
    async with tenant_tx(services, p) as conn:
        await _get_custom_role(conn, role_id)
        if body.name is not None or body.description is not None:
            await conn.execute(
                text(
                    "UPDATE roles SET name = coalesce(:n, name), description = coalesce(:d, description), "
                    "updated_at = now(), version = version + 1 WHERE id = :id"
                ),
                {"n": body.name, "d": body.description, "id": role_id},
            )
        if body.permissions is not None:
            perms = _validate_permissions(p, body.permissions)
            await conn.execute(text("DELETE FROM role_permissions WHERE role_id = :r"), {"r": role_id})
            for perm in perms:
                await conn.execute(
                    text("INSERT INTO role_permissions (role_id, permission_key) VALUES (:r, :p)"),
                    {"r": role_id, "p": perm},
                )
        await record(
            conn, p, "role.update", target_type="role", target_id=role_id, details=body.model_dump(exclude_none=True)
        )
        row = (await conn.execute(text(_ROLES_SQL.format(extra="AND r.id = :id")), {"id": role_id})).one()
    return RoleOut(**row._mapping)


@router.delete("/roles/{role_id}", status_code=status.HTTP_204_NO_CONTENT, **requires("role:manage", step_up=True))
async def delete_role(role_id: UUID, services: Svc, p: P) -> Response:
    async with tenant_tx(services, p) as conn:
        await _get_custom_role(conn, role_id)
        await conn.execute(text("DELETE FROM roles WHERE id = :id"), {"id": role_id})
        await record(conn, p, "role.delete", target_type="role", target_id=role_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# ============================================================ API keys
class ApiKeyOut(BaseModel):
    id: UUID
    name: str
    prefix: str
    permissions: list[str]
    expires_at: datetime
    last_used_at: datetime | None
    revoked_at: datetime | None
    created_at: datetime


class ApiKeyCreate(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    permissions: list[str] = Field(min_length=1, max_length=len(PERMISSIONS))
    expires_in_days: StrictInt = Field(default=90, ge=1, le=365)


class ApiKeyCreated(ApiKeyOut):
    key: str = Field(description="Shown once. Store it securely.")


@router.get("/api-keys", response_model=list[ApiKeyOut], **requires("apikey:read"))
async def list_api_keys(services: Svc, p: P) -> list[ApiKeyOut]:
    async with tenant_tx(services, p) as conn:
        rows = await conn.execute(
            text(
                "SELECT id, name, prefix, permissions, expires_at, last_used_at, revoked_at, "
                "created_at FROM api_keys ORDER BY created_at DESC"
            )
        )
        return [ApiKeyOut(**r._mapping) for r in rows]


@router.post(
    "/api-keys",
    response_model=ApiKeyCreated,
    status_code=status.HTTP_201_CREATED,
    **requires("apikey:manage", step_up=True),
)
async def create_api_key(body: ApiKeyCreate, services: Svc, p: P) -> ApiKeyCreated:
    perms = _validate_permissions(p, body.permissions)
    if set(perms) & MSP_ONLY:
        raise ProblemError(422, "validation.failed", "Not allowed", "API keys cannot hold MSP permissions.")
    token = new_token(API_KEY_PREFIX)
    async with tenant_tx(services, p) as conn:
        row = (
            await conn.execute(
                text(
                    "INSERT INTO api_keys (tenant_id, name, prefix, key_hash, permissions, expires_at, created_by) "
                    "VALUES (app_tenant(), :n, :px, :h, :perms, now() + make_interval(days => :d), :by) "
                    "RETURNING id, name, prefix, permissions, expires_at, last_used_at, revoked_at, created_at"
                ),
                {
                    "n": body.name,
                    "px": token[:10],
                    "h": token_hash(token),
                    "perms": perms,
                    "d": body.expires_in_days,
                    "by": p.user_id,
                },
            )
        ).one()
        await record(
            conn,
            p,
            "apikey.create",
            target_type="api_key",
            target_id=row.id,
            details={"name": body.name, "permissions": perms},
        )
    return ApiKeyCreated(**row._mapping, key=token)


@router.delete("/api-keys/{key_id}", status_code=status.HTTP_204_NO_CONTENT, **requires("apikey:manage", step_up=True))
async def revoke_api_key(key_id: UUID, services: Svc, p: P) -> Response:
    async with tenant_tx(services, p) as conn:
        updated = (
            await conn.execute(
                text("UPDATE api_keys SET revoked_at = now() WHERE id = :id AND revoked_at IS NULL RETURNING id"),
                {"id": key_id},
            )
        ).first()
        if updated is None:
            raise not_found("API key")
        await record(conn, p, "apikey.revoke", target_type="api_key", target_id=key_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# ============================================================ audit
class AuditOut(BaseModel):
    id: int
    tenant_id: UUID | None
    seq: int
    at: datetime
    actor_type: str
    actor_id: UUID | None
    actor_ip: str | None
    via_tenant_id: UUID | None
    action: str
    target_type: str | None
    target_id: str | None
    outcome: str
    details: dict[str, object]


class AuditVerifyOut(BaseModel):
    ok: bool
    checked: int
    first_bad_seq: int | None
    reason: str | None


@router.get("/audit", response_model=list[AuditOut], **requires("audit:read"))
async def list_audit(
    services: Svc,
    p: P,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    before: Annotated[int | None, Query(ge=1, le=PG_BIGINT_MAX)] = None,
    action: Annotated[str | None, Query(max_length=100, pattern=r"^[a-z0-9_.]+$")] = None,
) -> list[AuditOut]:
    async with tenant_tx(services, p) as conn:
        entries = await audit.list_entries(conn, limit=limit, before_id=before, action_prefix=action)
    return [AuditOut(**e.__dict__) for e in entries]


@router.get("/audit/verify", response_model=AuditVerifyOut, **requires("audit:read"))
async def verify_audit(services: Svc, p: P) -> AuditVerifyOut:
    async with tenant_tx(services, p) as conn:
        result = await audit.verify(conn, p.tenant_id)
    return AuditVerifyOut(**result.__dict__)
