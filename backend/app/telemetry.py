"""OpenTelemetry (NFR-6): traces and metrics over OTLP/HTTP to the ``observability`` profile.

Off unless ``NOCSOC_OTEL_ENABLED=true``; the exporter uses the standard ``OTEL_EXPORTER_OTLP_*``
environment variables. The instruments below are created on the global (proxy) meter, so code can
record measurements unconditionally: they are no-ops until :func:`setup` installs a provider.

Trace context crosses the event bus in W3C ``traceparent`` Kafka headers (:func:`kafka_headers`,
:func:`context_from_headers`), so an API-triggered replay and the ingestion it causes share a
trace. Log records carry the active ``trace_id`` (``app.logging_setup``).
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from fastapi import FastAPI
from opentelemetry import context, metrics, propagate, trace

from app.config import Settings

_meter = metrics.get_meter("nocsoc")
tracer = trace.get_tracer("nocsoc")

# ---------------------------------------------------------------- platform instruments (SLO inputs)
INGEST_MESSAGES = _meter.create_counter(
    "nocsoc.ingest.messages", unit="{message}", description="Raw messages handled, by result"
)
INGEST_DURATION = _meter.create_histogram(
    "nocsoc.ingest.duration", unit="s", description="Time to process one raw message (all records)"
)
INGEST_LATENCY = _meter.create_histogram(
    "nocsoc.ingest.latency", unit="s", description="Envelope emitted by the connector -> stored (alert-to-store)"
)
OUTBOX_PENDING = _meter.create_gauge(
    "nocsoc.outbox.pending", unit="{row}", description="Telemetry rows waiting for a sink after a relay pass"
)
PROJECTOR_ROWS = _meter.create_counter("nocsoc.projector.rows", unit="{row}", description="Rows projected, by sink")
PROJECTOR_FAILURES = _meter.create_counter(
    "nocsoc.projector.failures", unit="{failure}", description="Projection batches that failed, by sink"
)
ANCHOR_RUNS = _meter.create_counter("nocsoc.audit_anchor.runs", unit="{run}", description="Audit anchor checks")
ANCHOR_PROBLEMS = _meter.create_counter(
    "nocsoc.audit_anchor.problems", unit="{problem}", description="Audit chain/anchor mismatches (must stay 0)"
)

_LATENCY_BUCKETS = [0.05, 0.1, 0.25, 0.5, 1, 2, 3, 5, 10, 30, 60]
_configured = False


def setup(service_name: str, settings: Settings) -> bool:
    """Installs tracer and meter providers once per process. Returns whether telemetry is on."""
    global _configured
    if not settings.otel_enabled:
        return False
    if _configured:
        return True

    from opentelemetry.exporter.otlp.proto.http.metric_exporter import OTLPMetricExporter
    from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
    from opentelemetry.sdk.metrics import MeterProvider
    from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
    from opentelemetry.sdk.metrics.view import ExplicitBucketHistogramAggregation, View
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor

    resource = Resource.create(
        {
            "service.name": service_name,
            "service.namespace": "nocsoc",
            "deployment.environment.name": settings.environment,
        }
    )
    provider = TracerProvider(resource=resource)
    provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter()))
    trace.set_tracer_provider(provider)
    seconds = ExplicitBucketHistogramAggregation(_LATENCY_BUCKETS)
    metrics.set_meter_provider(
        MeterProvider(
            resource=resource,
            metric_readers=[PeriodicExportingMetricReader(OTLPMetricExporter(), export_interval_millis=15_000)],
            views=[
                View(instrument_name="nocsoc.ingest.duration", aggregation=seconds),
                View(instrument_name="nocsoc.ingest.latency", aggregation=seconds),
            ],
        )
    )
    _configured = True
    return True


def shutdown() -> None:
    """Flushes pending spans and metrics (workers call this on stop)."""
    for provider in (trace.get_tracer_provider(), metrics.get_meter_provider()):
        flush = getattr(provider, "shutdown", None)
        if flush is not None:
            flush()


def setup_telemetry(app: FastAPI, settings: Settings) -> None:
    if not setup(settings.service_name, settings):
        return
    from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor

    FastAPIInstrumentor.instrument_app(app, excluded_urls="/api/v1/health/.*,/api/v1/stream")


# ---------------------------------------------------------------- trace context over Kafka
def kafka_headers() -> list[tuple[str, bytes]]:
    carrier: dict[str, str] = {}
    propagate.inject(carrier)
    return [(k, v.encode()) for k, v in carrier.items()]


def context_from_headers(headers: Iterable[tuple[str, bytes]] | None) -> context.Context:
    carrier: dict[str, Any] = {k: v.decode(errors="replace") for k, v in headers or [] if isinstance(v, bytes)}
    return propagate.extract(carrier)


def current_trace_id() -> str | None:
    ctx = trace.get_current_span().get_span_context()
    return format(ctx.trace_id, "032x") if ctx.is_valid else None
