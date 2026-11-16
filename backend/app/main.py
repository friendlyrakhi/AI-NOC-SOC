"""API entrypoint. Feature modules are mounted here phase by phase."""

import logging

from fastapi import FastAPI

from app import __version__
from app.config import get_settings
from app.health import router as health_router
from app.telemetry import setup_telemetry

API_PREFIX = "/api/v1"


def create_app() -> FastAPI:
    settings = get_settings()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")

    app = FastAPI(
        title="AI NOC & SOC Platform API",
        version=__version__,
        openapi_url=f"{API_PREFIX}/openapi.json",
        docs_url=f"{API_PREFIX}/docs",
        redoc_url=None,
    )
    app.include_router(health_router, prefix=API_PREFIX)
    setup_telemetry(app, settings)
    logging.getLogger(__name__).info(
        "starting %s env=%s execution_mode=%s",
        settings.service_name,
        settings.environment,
        settings.execution_mode,
    )
    return app


app = create_app()
