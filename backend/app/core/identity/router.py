"""/auth endpoints (docs/05-api-specification.md §2.1).

The session token is returned in the response body to the web BFF, which keeps it in an
HttpOnly, SameSite=Strict cookie (ADR-0017). It is never exposed to browser JavaScript.
"""

from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, Request, Response, status
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import text

from app.core.authz import service as authz
from app.core.authz.catalog import portals_for
from app.core.authz.deps import authenticated, client_ip, get_principal, get_session, public
from app.core.authz.principal import Principal
from app.core.identity.service import IdentityService, SessionInfo
from app.errors import unauthorized
from app.services import Services, get_services

router = APIRouter(prefix="/auth", tags=["auth"])


def identity(services: Annotated[Services, Depends(get_services)]) -> IdentityService:
    return IdentityService(services)


Identity = Annotated[IdentityService, Depends(identity)]


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=256)


class LoginResponse(BaseModel):
    status: Literal["authenticated", "mfa_required", "mfa_enrollment_required"]
    session_token: str | None = None
    challenge: str | None = None


class ChallengeRequest(BaseModel):
    challenge: str = Field(min_length=10, max_length=200)


class ChallengeCodeRequest(ChallengeRequest):
    code: str = Field(min_length=6, max_length=8)


class SessionResponse(BaseModel):
    session_token: str


class EnrollmentResponse(BaseModel):
    secret: str
    otpauth_uri: str


class CodeRequest(BaseModel):
    code: str = Field(min_length=6, max_length=8)


class AcceptInvitationRequest(BaseModel):
    token: str = Field(min_length=10, max_length=200)
    password: str = Field(min_length=1, max_length=256)


class AcceptInvitationResponse(BaseModel):
    email: str


class SwitchTenantRequest(BaseModel):
    tenant_id: UUID
    aggregate: bool = False


class TenantAccessOut(BaseModel):
    id: UUID
    name: str
    slug: str
    kind: str
    access: str
    via_msp_tenant_id: UUID | None


class MeResponse(BaseModel):
    user_id: UUID
    email: str
    is_platform_admin: bool
    mfa_enrolled: bool
    tenants: list[TenantAccessOut]
    mode: str
    active_tenant_id: UUID | None
    active_tenant_kind: str | None
    via_msp_tenant_id: UUID | None
    aggregate_tenant_ids: list[UUID]
    permissions: list[str]
    portals: list[str]
    step_up_active: bool


@router.post("/login", response_model=LoginResponse, **public())
async def login(body: LoginRequest, request: Request, svc: Identity) -> LoginResponse:
    out = await svc.login(str(body.email), body.password, client_ip(request), request.headers.get("user-agent"))
    return LoginResponse(status=out.status, session_token=out.session_token, challenge=out.challenge_token)


@router.post("/mfa/verify", response_model=SessionResponse, **public())
async def mfa_verify(body: ChallengeCodeRequest, request: Request, svc: Identity) -> SessionResponse:
    token = await svc.verify_mfa(body.challenge, body.code, client_ip(request), request.headers.get("user-agent"))
    return SessionResponse(session_token=token)


@router.post("/mfa/enroll", response_model=EnrollmentResponse, **public())
async def mfa_enroll(body: ChallengeRequest, svc: Identity) -> EnrollmentResponse:
    start = await svc.start_enrollment(body.challenge)
    return EnrollmentResponse(secret=start.secret, otpauth_uri=start.otpauth_uri)


@router.post("/mfa/confirm", response_model=SessionResponse, **public())
async def mfa_confirm(body: ChallengeCodeRequest, request: Request, svc: Identity) -> SessionResponse:
    token = await svc.confirm_enrollment(
        body.challenge, body.code, client_ip(request), request.headers.get("user-agent")
    )
    return SessionResponse(session_token=token)


@router.post("/invitations/accept", response_model=AcceptInvitationResponse, **public())
async def accept_invitation(body: AcceptInvitationRequest, request: Request, svc: Identity) -> AcceptInvitationResponse:
    email = await svc.accept_invitation(body.token, body.password, client_ip(request))
    return AcceptInvitationResponse(email=email)


@router.post("/step-up", status_code=status.HTTP_204_NO_CONTENT, **authenticated())
async def step_up(
    body: CodeRequest, request: Request, svc: Identity, session: Annotated[SessionInfo, Depends(get_session)]
) -> Response:
    await svc.step_up(session, body.code, client_ip(request))
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT, **authenticated())
async def logout(request: Request, svc: Identity, session: Annotated[SessionInfo, Depends(get_session)]) -> Response:
    await svc.logout(session, client_ip(request))
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/switch-tenant", status_code=status.HTTP_204_NO_CONTENT, **authenticated())
async def switch_tenant(
    body: SwitchTenantRequest,
    request: Request,
    svc: Identity,
    session: Annotated[SessionInfo, Depends(get_session)],
) -> Response:
    await svc.switch_tenant(session, body.tenant_id, body.aggregate, client_ip(request))
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/me", response_model=MeResponse, **authenticated())
async def me(
    services: Annotated[Services, Depends(get_services)],
    principal: Annotated[Principal, Depends(get_principal)],
) -> MeResponse:
    if principal.user_id is None or principal.email is None:
        raise unauthorized("A user session is required.")
    async with services.auth_db.tx() as conn:
        access = await authz.accessible_tenants(conn, principal.user_id)
        mfa = (
            await conn.execute(
                text("SELECT EXISTS (SELECT 1 FROM user_credentials WHERE user_id = :u AND kind = 'totp')"),
                {"u": principal.user_id},
            )
        ).scalar_one()
    return MeResponse(
        user_id=principal.user_id,
        email=principal.email,
        is_platform_admin=principal.is_platform_admin,
        mfa_enrolled=bool(mfa),
        tenants=[
            TenantAccessOut(
                id=a.tenant_id,
                name=a.name,
                slug=a.slug,
                kind=a.kind,
                access=a.access,
                via_msp_tenant_id=a.via_msp_tenant_id,
            )
            for a in access
        ],
        mode=principal.mode,
        active_tenant_id=principal.tenant_id,
        active_tenant_kind=principal.tenant_kind,
        via_msp_tenant_id=principal.via_msp_tenant_id,
        aggregate_tenant_ids=list(principal.aggregate_tenant_ids),
        permissions=sorted(principal.permissions),
        portals=portals_for(principal.permissions),
        step_up_active=principal.stepped_up(services.settings.step_up_minutes),
    )
