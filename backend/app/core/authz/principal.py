"""The authenticated caller and its effective context for one request."""

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Literal
from uuid import UUID

from app.core.audit import Actor

Mode = Literal["none", "tenant", "aggregate"]


@dataclass(frozen=True)
class Principal:
    user_id: UUID | None
    email: str | None
    session_id: UUID | None
    api_key_id: UUID | None
    is_platform_admin: bool
    mode: Mode
    tenant_id: UUID | None
    tenant_kind: str | None
    permissions: frozenset[str]
    # Set when the user reaches the tenant only through an MSP delegation (ADR-0016).
    via_msp_tenant_id: UUID | None = None
    # Aggregate mode: customer tenants visible in the read-only "All customers" view.
    aggregate_tenant_ids: tuple[UUID, ...] = field(default_factory=tuple)
    step_up_at: datetime | None = None
    ip: str | None = None
    # Privileged permissions the user holds but this session may not use, because it was not
    # established with MFA (e.g. a role granted mid-session). Sign in again or step up to use them.
    withheld: frozenset[str] = frozenset()

    @property
    def actor(self) -> Actor:
        if self.api_key_id is not None:
            return Actor("api_key", self.api_key_id, self.ip)
        return Actor("user", self.user_id, self.ip)

    def has(self, permission: str) -> bool:
        return permission in self.permissions

    def stepped_up(self, minutes: int) -> bool:
        if self.api_key_id is not None or self.step_up_at is None:
            return False
        return datetime.now(UTC) - self.step_up_at <= timedelta(minutes=minutes)
