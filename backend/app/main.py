"""API entrypoint. Feature modules are mounted here phase by phase."""

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from app import __version__, errors
from app.alerts.router import router as alerts_router
from app.config import Settings, get_settings
from app.core.identity.router import router as auth_router
from app.core.msp.router import router as msp_router
from app.core.tenancy.platform import router as platform_router
from app.core.tenancy.router import router as tenancy_router
from app.events import router as events_router
from app.health import router as health_router
from app.integrations.internal import router as internal_router
from app.integrations.router import router as integrations_router
from app.logging_setup import RequestContextMiddleware, configure_logging
from app.mail import Mailer
from app.services import build_services
from app.telemetry import setup_telemetry

API_PREFIX = "/api/v1"


def create_app(settings: Settings | None = None, *, mailer: Mailer | None = None) -> FastAPI:
    settings = settings or get_settings()
    configure_logging(json_format=settings.log_format == "json", settings=settings)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        services = build_services(settings, mailer)
        app.state.services = services
        logging.getLogger(__name__).info(
            "starting %s env=%s execution_mode=%s",
            settings.service_name,
            settings.environment,
            settings.execution_mode,
        )
        try:
            yield
        finally:
            await services.close()

    app = FastAPI(
        title="AI NOC & SOC Platform API",
        version=__version__,
        openapi_url=f"{API_PREFIX}/openapi.json",
        docs_url=f"{API_PREFIX}/docs",
        redoc_url=None,
        lifespan=lifespan,
    )
    app.state.settings = settings
    errors.install(app)
    for router in (
        health_router,
        auth_router,
        tenancy_router,
        msp_router,
        platform_router,
        integrations_router,
        alerts_router,
        events_router,
        internal_router,
    ):
        app.include_router(router, prefix=API_PREFIX)
    app.add_middleware(RequestContextMiddleware)
    setup_telemetry(app, settings)
    return app


def _create_default() -> FastAPI:
    return create_app()


app = _create_default()
