"""OpenTelemetry bootstrap (NFR-6).

Off by default. When enabled, it uses the standard ``OTEL_EXPORTER_OTLP_*`` environment
variables. The collector arrives with the ``observability`` profile (P7).
"""

from fastapi import FastAPI

from app.config import Settings


def setup_telemetry(app: FastAPI, settings: Settings) -> None:
    if not settings.otel_enabled:
        return

    from opentelemetry import trace
    from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
    from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor

    provider = TracerProvider(resource=Resource.create({"service.name": settings.service_name}))
    provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter()))
    trace.set_tracer_provider(provider)
    FastAPIInstrumentor.instrument_app(app, excluded_urls="/api/v1/health/.*")
