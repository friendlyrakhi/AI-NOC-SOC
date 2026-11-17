"""Request authentication and authorization dependencies.

Every route declares exactly one marker, which the route-permission coverage test checks:
- ``**public()``: no authentication (health, login steps, invitation acceptance)
- ``**authenticated()``: any signed-in caller (``/auth/me``, logout, tenant switch)
- ``**platform_admin()``: platform administrators
- ``**requires("perm", step_up=..., aggregate=...)``: a tenant permission
- ``**internal()``: service-to-service (connector-runner), shared token in ``X-Runner-Token``
- ``**webhook_hmac()``: vendor webhooks, authenticated per instance by an HMAC signature that
  the handler verifies (docs/06 §7)
"""

import hmac
import ipaddress
from typing import Any, Literal
from uuid import UUID

from fastapi import Depends, Request

from app.core.authz import service as authz
from app.core.authz.principal import Principal
from app.core.identity.service import IdentityService, SessionInfo
from app.errors import ProblemError, forbidden, unauthorized
from app.services import Services, get_services

PUBLIC = "public"
AUTHENTICATED = "authenticated"
PLATFORM_ADMIN = "platform_admin"
INTERNAL = "internal"
WEBHOOK_HMAC = "webhook_hmac"


def client_ip(request: Request) -> str | None:
    """The peer address if it is a valid IP (unix sockets and test clients are not)."""
    host = request.client.host if request.client else None
    if not host:
        return None
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        return None


def _bearer(request: Request) -> str | None:
    header = request.headers.get("authorization", "")
    scheme, _, token = header.partition(" ")
    if scheme.lower() != "bearer" or not token:
        return None
    return token.strip()


async def get_session(request: Request, services: Services = Depends(get_services)) -> SessionInfo:
    cached = getattr(request.state, "session_info", None)
    if cached is not None:
        return cached  # type: ignore[no-any-return]
    token = _bearer(request)
    session = await IdentityService(services).resolve_session(token) if token else None
    if session is None:
        raise unauthorized("A valid session is required.")
    request.state.session_info = session
    return session


async def get_principal(request: Request, services: Services = Depends(get_services)) -> Principal:
    cached = getattr(request.state, "principal", None)
    if cached is not None:
        return cached  # type: ignore[no-any-return]
    token = _bearer(request)
    if token is None:
        raise unauthorized()
    identity = IdentityService(services)
    ip = client_ip(request)

    api_key = await identity.resolve_api_key(token)
    if api_key is not None:
        async with services.auth_db.tx() as conn:
            kind = await authz.tenant_permissions(conn, api_key.created_by, api_key.tenant_id)
        principal = Principal(
            user_id=None,
            email=None,
            session_id=None,
            api_key_id=api_key.id,
            is_platform_admin=False,
            mode="tenant",
            tenant_id=api_key.tenant_id,
            tenant_kind=kind.tenant_kind if kind else None,
            permissions=api_key.permissions,
            ip=ip,
        )
        request.state.principal = principal
        return principal

    session = await identity.resolve_session(token)
    if session is None:
        raise unauthorized()
    request.state.session_info = session

    mode = "none"
    tenant_id: UUID | None = None
    tenant_kind: str | None = None
    permissions: frozenset[str] = frozenset()
    via: UUID | None = None
    aggregate_ids: tuple[UUID, ...] = ()
    if session.active_tenant_id is not None:
        async with services.auth_db.tx() as conn:
            tp = await authz.tenant_permissions(conn, session.user_id, session.active_tenant_id)
            if tp is not None:
                tenant_id, tenant_kind, permissions, via = (
                    tp.tenant_id,
                    tp.tenant_kind,
                    tp.permissions,
                    tp.via_msp_tenant_id,
                )
                mode = "tenant"
                if session.aggregate and tp.tenant_kind == "msp" and via is None:
                    mode = "aggregate"
                    aggregate_ids = await authz.aggregate_tenant_ids(conn, session.user_id, tp.tenant_id)
    principal = Principal(
        user_id=session.user_id,
        email=session.email,
        session_id=session.id,
        api_key_id=None,
        is_platform_admin=session.is_platform_admin,
        mode=mode,  # type: ignore[arg-type]
        tenant_id=tenant_id,
        tenant_kind=tenant_kind,
        permissions=permissions,
        via_msp_tenant_id=via,
        aggregate_tenant_ids=aggregate_ids,
        step_up_at=session.step_up_at,
        ip=ip,
    )
    request.state.principal = principal
    return principal


def requires(permission: str, *, step_up: bool = False, aggregate: bool = False) -> dict[str, Any]:
    async def check(principal: Principal = Depends(get_principal), services: Services = Depends(get_services)) -> None:
        if principal.mode == "none":
            raise ProblemError(409, "tenant.none_selected", "No tenant selected", "Select a tenant first.")
        if aggregate and principal.mode != "aggregate":
            raise ProblemError(
                409,
                "tenant.aggregate_required",
                "All customers view required",
                "Switch to the 'All customers' view to use this endpoint.",
            )
        if not aggregate and principal.mode == "aggregate":
            raise ProblemError(
                409,
                "tenant.aggregate_read_only",
                "Read-only view",
                "The 'All customers' view is read-only. Select a single customer.",
            )
        if not principal.has(permission):
            raise forbidden()
        if step_up and not principal.stepped_up(services.settings.step_up_minutes):
            raise ProblemError(
                403,
                "auth.step_up_required",
                "Re-authentication required",
                "Confirm with your authenticator code to continue.",
            )

    return {
        "dependencies": [Depends(check)],
        "openapi_extra": {"x-required-permission": permission, "x-step-up": step_up, "x-aggregate": aggregate},
    }


def authenticated() -> dict[str, Any]:
    return {"dependencies": [Depends(get_session)], "openapi_extra": {"x-required-permission": AUTHENTICATED}}


def platform_admin() -> dict[str, Any]:
    async def check(principal: Principal = Depends(get_principal)) -> None:
        if not principal.is_platform_admin:
            raise forbidden()

    return {"dependencies": [Depends(check)], "openapi_extra": {"x-required-permission": PLATFORM_ADMIN}}


def public() -> dict[str, Any]:
    return {"openapi_extra": {"x-required-permission": PUBLIC}}


def internal(which: Literal["runner", "workflow"] = "runner") -> dict[str, Any]:
    """Service-to-service endpoints for the connector-runner (``X-Runner-Token``, setting
    ``runner_token``) or the workflow worker (``X-Workflow-Token``, setting ``workflow_token``)."""

    async def check(request: Request, services: Services = Depends(get_services)) -> None:
        expected = services.settings.runner_token if which == "runner" else services.settings.workflow_token
        if expected is None:
            raise ProblemError(
                503, "internal.disabled", "Internal endpoints disabled", "No service token is configured."
            )
        header = f"x-{which}-token"
        presented = request.headers.get(header, "")
        if not hmac.compare_digest(presented.encode(), expected.get_secret_value().encode()):
            raise unauthorized("A valid service token is required.")

    return {
        "dependencies": [Depends(check)],
        "openapi_extra": {"x-required-permission": INTERNAL},
        "include_in_schema": True,
    }


def webhook_hmac() -> dict[str, Any]:
    return {"openapi_extra": {"x-required-permission": WEBHOOK_HMAC}}
