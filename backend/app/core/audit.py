"""Hash-chained audit log (AUD-1, threat model T28).

Rows are appended only through the ``audit_append`` SECURITY DEFINER function, which
serializes per-tenant chains and computes the SHA-256 link. The application has no
INSERT/UPDATE/DELETE grant on ``audit_log``, and a trigger blocks UPDATE/DELETE/TRUNCATE.
"""

import json
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

_SENSITIVE = re.compile(r"pass(word)?|secret|token|code|otp|key|credential|authorization", re.I)
_MAX_DETAIL_CHARS = 8000


def scrub(details: dict[str, Any] | None) -> dict[str, Any]:
    """Drop sensitive-looking keys so audit details never carry secrets (T17)."""
    if not details:
        return {}

    def clean(value: Any) -> Any:
        if isinstance(value, dict):
            return {k: ("[redacted]" if _SENSITIVE.search(k) else clean(v)) for k, v in value.items()}
        if isinstance(value, list):
            return [clean(v) for v in value]
        return value

    cleaned = clean(details)
    if len(json.dumps(cleaned, default=str)) > _MAX_DETAIL_CHARS:
        return {"truncated": True}
    return cleaned  # type: ignore[no-any-return]


@dataclass(frozen=True)
class Actor:
    actor_type: str  # user | api_key | system | anonymous
    actor_id: UUID | None = None
    ip: str | None = None


async def append(
    conn: AsyncConnection,
    *,
    tenant_id: UUID | None,
    actor: Actor,
    action: str,
    outcome: str = "success",
    target_type: str | None = None,
    target_id: str | None = None,
    details: dict[str, Any] | None = None,
    via_tenant_id: UUID | None = None,
    trace_id: str | None = None,
) -> int:
    result = await conn.execute(
        text(
            "SELECT audit_append(:tenant, :atype, :aid, CAST(:ip AS inet), :via, :action, "
            ":ttype, :tid, :outcome, CAST(:details AS jsonb), :trace)"
        ),
        {
            "tenant": tenant_id,
            "atype": actor.actor_type,
            "aid": actor.actor_id,
            "ip": actor.ip,
            "via": via_tenant_id,
            "action": action,
            "ttype": target_type,
            "tid": target_id,
            "outcome": outcome,
            "details": json.dumps(scrub(details), default=str),
            "trace": trace_id,
        },
    )
    return int(result.scalar_one())


@dataclass(frozen=True)
class AuditEntry:
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
    details: dict[str, Any]


async def list_entries(
    conn: AsyncConnection,
    *,
    limit: int = 50,
    before_id: int | None = None,
    action_prefix: str | None = None,
) -> list[AuditEntry]:
    """Lists entries visible under the connection's RLS context (one tenant, or aggregate)."""
    rows = await conn.execute(
        text(
            "SELECT id, tenant_id, seq, at, actor_type, actor_id, "
            "host(actor_ip) AS actor_ip, via_tenant_id, action, target_type, target_id, outcome, details "
            "FROM audit_log "
            "WHERE (CAST(:before AS bigint) IS NULL OR id < :before) "
            "AND (CAST(:prefix AS text) IS NULL OR action LIKE :prefix || '%') "
            "ORDER BY id DESC LIMIT :limit"
        ),
        {"before": before_id, "prefix": action_prefix, "limit": limit},
    )
    return [AuditEntry(**r._mapping) for r in rows]


@dataclass(frozen=True)
class VerifyResult:
    ok: bool
    checked: int
    first_bad_seq: int | None
    reason: str | None


async def verify(conn: AsyncConnection, tenant_id: UUID | None) -> VerifyResult:
    row = (await conn.execute(text("SELECT * FROM audit_verify(:t)"), {"t": tenant_id})).one()
    return VerifyResult(ok=row.ok, checked=row.checked, first_bad_seq=row.first_bad_seq, reason=row.reason)
