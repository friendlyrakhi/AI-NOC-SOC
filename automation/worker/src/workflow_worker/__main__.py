"""``python -m workflow_worker``: run the Temporal worker for playbooks and action requests."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import signal
from typing import Any

from temporalio.client import Client
from temporalio.worker import Worker

from workflow_worker.activities import Activities
from workflow_worker.api import WorkflowApi
from workflow_worker.config import TASK_QUEUE, WorkerSettings
from workflow_worker.workflows import ActionWorkflow, PlaybookWorkflow

logger = logging.getLogger("workflow_worker")


def build_worker(client: Client, api: WorkflowApi) -> Worker:
    return Worker(
        client,
        task_queue=TASK_QUEUE,
        workflows=[ActionWorkflow, PlaybookWorkflow],
        activities=Activities(api).all(),
    )


def tracing(settings: WorkerSettings) -> list[Any]:
    """Client interceptors: continue the API's trace through workflows and activities (NFR-6)."""
    if not settings.otel_enabled:
        return []
    from opentelemetry import trace
    from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor
    from temporalio.contrib.opentelemetry import TracingInterceptor

    provider = TracerProvider(
        resource=Resource.create({"service.name": "nocsoc-workflow-worker", "service.namespace": "nocsoc"})
    )
    provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter()))
    trace.set_tracer_provider(provider)
    return [TracingInterceptor()]


async def main() -> None:
    settings = WorkerSettings()
    interceptors = tracing(settings)
    if settings.workflow_token is None:
        raise SystemExit("workflow token secret (nocsoc_workflow_token) is required")
    for attempt in range(60):
        try:
            client = await Client.connect(
                settings.temporal_address, namespace=settings.temporal_namespace, interceptors=interceptors
            )
            break
        except Exception:
            if attempt == 59:
                raise
            await asyncio.sleep(2)
    api = WorkflowApi(settings.api_url, settings.workflow_token.get_secret_value(), verify=settings.tls_ca_file or True)
    worker = build_worker(client, api)
    stopping = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        with contextlib.suppress(NotImplementedError):
            loop.add_signal_handler(sig, stopping.set)
    logger.info("workflow worker started (simulate and dry-run only)")
    async with worker:
        await stopping.wait()
    await api.close()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    asyncio.run(main())
