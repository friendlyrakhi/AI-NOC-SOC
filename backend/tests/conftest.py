"""Shared test configuration."""

import asyncio
import sys

# psycopg's async driver cannot use Windows' default Proactor loop. The API itself runs in
# Linux containers; this only matters for tests (and local runs) on a Windows host.
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())  # type: ignore[attr-defined]
