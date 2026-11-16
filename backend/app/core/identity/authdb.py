"""Identity database access as ``nocsoc_auth`` (BYPASSRLS, identity tables only).

Only ``app.core.identity`` and ``app.core.authz`` may import this module (import-linter
contract). Everything else uses the RLS-scoped ``AppDatabase``.
"""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine, create_async_engine

from app.config import Settings


class AuthDatabase:
    def __init__(self, settings: Settings) -> None:
        self.engine: AsyncEngine = create_async_engine(
            settings.auth_database_url(), pool_size=5, max_overflow=5, pool_pre_ping=True
        )

    async def dispose(self) -> None:
        await self.engine.dispose()

    @asynccontextmanager
    async def tx(self) -> AsyncIterator[AsyncConnection]:
        async with self.engine.begin() as conn:
            yield conn
