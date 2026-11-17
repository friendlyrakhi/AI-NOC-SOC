"""Search setup: ``python -m app.db.migrate_search``.

Creates the OpenSearch index templates, the 30-day retention policy, and the two service users
(``nocsoc_reader`` for the API, ``nocsoc_indexer`` for the ingest worker), idempotently. Runs as
a one-shot container in the ``search`` profile and is the only holder of the admin password.
"""

import asyncio
import logging

import httpx

from app.config import Settings, get_settings
from app.searchstore import setup

logger = logging.getLogger("app.db.migrate_search")


async def wait_for_cluster(url: str, admin_password: str, attempts: int = 90) -> None:
    async with httpx.AsyncClient(base_url=url, auth=("admin", admin_password), timeout=10) as c:
        for attempt in range(attempts):
            try:
                r = await c.get("/_cluster/health", params={"wait_for_status": "yellow", "timeout": "5s"})
                if r.status_code == 200 and r.json().get("status") in ("yellow", "green"):
                    return
            except httpx.HTTPError:
                pass
            if attempt == attempts - 1:
                raise SystemExit("OpenSearch did not become ready")
            await asyncio.sleep(2)


async def run(settings: Settings) -> None:
    if not (
        settings.opensearch_url
        and settings.opensearch_admin_password
        and settings.opensearch_reader_password
        and settings.opensearch_indexer_password
    ):
        raise SystemExit("missing OpenSearch settings or secrets")
    admin = settings.opensearch_admin_password.get_secret_value()
    await wait_for_cluster(settings.opensearch_url, admin)
    await setup(
        settings.opensearch_url,
        admin,
        {
            "nocsoc_reader": settings.opensearch_reader_password.get_secret_value(),
            "nocsoc_indexer": settings.opensearch_indexer_password.get_secret_value(),
        },
    )
    logger.info("opensearch templates, retention policy and service users ready")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s %(message)s")
    asyncio.run(run(get_settings()))
