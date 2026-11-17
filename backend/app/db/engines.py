"""RLS-scoped database access for tenant data (ADR-0002, ADR-0016).

Every transaction sets its tenant context with ``set_config(..., is_local => true)``, so the
context ends with the transaction and pooled connections never leak it. Without a context,
RLS policies match no rows (fail closed).
"""

from collections.abc import AsyncIterator, Sequence
from contextlib import asynccontextmanager
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine, create_async_engine

from app.config import Settings

AGGREGATE_ROLE = "nocsoc_aggregate"


class TenantContextError(RuntimeError):
    """Raised when a tenant-scoped transaction is opened without a tenant."""


class AppDatabase:
    """Connections as ``nocsoc_app`` (RLS enforced), or ``nocsoc_worker`` for the ingest worker."""

    def __init__(self, settings: Settings, *, url: str | None = None, pool_size: int = 5) -> None:
        self.engine: AsyncEngine = create_async_engine(
            url or settings.app_database_url(), pool_size=pool_size, max_overflow=5, pool_pre_ping=True
        )

    async def dispose(self) -> None:
        await self.engine.dispose()

    @asynccontextmanager
    async def tenant(
        self,
        tenant_id: UUID,
        user_id: UUID | None = None,
        *,
        audit_mirror_tenant_id: UUID | None = None,
    ) -> AsyncIterator[AsyncConnection]:
        """Read/write transaction scoped to one tenant."""
        if tenant_id is None:
            raise TenantContextError("tenant-scoped transaction requires a tenant_id")
        async with self.engine.begin() as conn:
            await conn.execute(
                text(
                    "SELECT set_config('app.tenant_id', :t, true), "
                    "set_config('app.user_id', :u, true), "
                    "set_config('app.audit_mirror_tenant_id', :m, true)"
                ),
                {
                    "t": str(tenant_id),
                    "u": str(user_id) if user_id else "",
                    "m": str(audit_mirror_tenant_id) if audit_mirror_tenant_id else "",
                },
            )
            yield conn

    @asynccontextmanager
    async def aggregate(
        self, tenant_ids: Sequence[UUID], user_id: UUID | None = None
    ) -> AsyncIterator[AsyncConnection]:
        """Read-only transaction across several tenants (MSP "All customers" view).

        Runs as the SELECT-only ``nocsoc_aggregate`` role in a READ ONLY transaction.
        """
        async with self.engine.begin() as conn:
            await conn.execute(text("SET TRANSACTION READ ONLY"))
            await conn.execute(text(f"SET LOCAL ROLE {AGGREGATE_ROLE}"))
            await conn.execute(
                text("SELECT set_config('app.tenant_ids', :ids, true), set_config('app.user_id', :u, true)"),
                {
                    "ids": ",".join(str(t) for t in tenant_ids),
                    "u": str(user_id) if user_id else "",
                },
            )
            yield conn
