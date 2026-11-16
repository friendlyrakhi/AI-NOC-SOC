"""Platform administration: create MSP tenants (docs/05 §2.2).

Platform admins administer tenants but get no access to tenant data (IAM-2): creating an
MSP invites its first administrator; the platform admin is not made a member.
"""

from datetime import datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, status
from pydantic import BaseModel, EmailStr, Field

from app.core.authz.deps import get_principal, platform_admin
from app.core.authz.principal import Principal
from app.core.identity.service import IdentityService
from app.services import Services, get_services

router = APIRouter(prefix="/platform", tags=["platform"])


class PlatformTenantOut(BaseModel):
    id: UUID
    kind: str
    slug: str
    name: str
    status: str
    parent_tenant_id: UUID | None
    created_at: datetime
    members: int


class MspCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    slug: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{1,62}$")
    admin_email: EmailStr
    admin_name: str = Field(min_length=1, max_length=200)


class MspCreated(BaseModel):
    id: UUID
    admin_user_id: UUID
    invitation_sent: bool


@router.get("/tenants", response_model=list[PlatformTenantOut], **platform_admin())
async def list_tenants(services: Annotated[Services, Depends(get_services)]) -> list[PlatformTenantOut]:
    rows = await IdentityService(services).list_all_tenants()
    return [PlatformTenantOut(**r) for r in rows]  # type: ignore[arg-type]


@router.post("/tenants", response_model=MspCreated, status_code=status.HTTP_201_CREATED, **platform_admin())
async def create_msp(
    body: MspCreate,
    services: Annotated[Services, Depends(get_services)],
    p: Annotated[Principal, Depends(get_principal)],
) -> MspCreated:
    tenant_id, invite = await IdentityService(services).create_msp_tenant(
        name=body.name, slug=body.slug, admin_email=str(body.admin_email), admin_name=body.admin_name, actor=p.actor
    )
    return MspCreated(id=tenant_id, admin_user_id=invite.user_id, invitation_sent=invite.invitation_sent)
