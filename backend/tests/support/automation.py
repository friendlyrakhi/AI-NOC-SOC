"""P5 test harness: a real Temporal dev server (container), the API served over HTTP by uvicorn
(the worker reaches it like in production), and the real workflow worker in a background thread
that tests can stop and start again (to prove workflows survive a dead worker)."""

from __future__ import annotations

import asyncio
import dataclasses
import secrets
import socket
import threading
import time
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

import httpx
import pytest
import uvicorn
from pydantic import SecretStr
from testcontainers.core.container import DockerContainer
from testcontainers.core.wait_strategies import LogMessageWaitStrategy

from app.config import Settings
from app.db.seed import seed_demo_integrations, seed_demo_playbooks
from app.mail import MemoryMailer
from app.main import create_app
from support.integration import Api, Env, attach_gateway

TEMPORAL_IMAGE = "temporalio/temporal:1.4.1"


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


class WorkerThread:
    """The production worker (workflow_worker.build_worker) on its own event loop."""

    def __init__(self, temporal_address: str, api_url: str, token: str) -> None:
        self.temporal_address, self.api_url, self.token = temporal_address, api_url, token
        self._thread: threading.Thread | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._stop: asyncio.Event | None = None
        self._ready = threading.Event()

    def start(self) -> None:
        self._ready.clear()
        self._thread = threading.Thread(target=self._run, name="workflow-worker", daemon=True)
        self._thread.start()
        if not self._ready.wait(60):
            raise RuntimeError("workflow worker did not start")

    def _run(self) -> None:
        self._loop = asyncio.new_event_loop()
        self._loop.run_until_complete(self._main())

    async def _main(self) -> None:
        from temporalio.client import Client

        from workflow_worker.__main__ import build_worker
        from workflow_worker.api import WorkflowApi

        client = await Client.connect(self.temporal_address)
        api = WorkflowApi(self.api_url, self.token)
        self._stop = asyncio.Event()
        worker = build_worker(client, api)
        async with worker:
            self._ready.set()
            await self._stop.wait()
        await api.close()

    def stop(self) -> None:
        if self._loop and self._stop:
            self._loop.call_soon_threadsafe(self._stop.set)
        if self._thread:
            self._thread.join(60)


@dataclass
class AutomationEnv:
    env: Env
    api: Api
    settings: Settings
    worker: WorkerThread
    api_url: str

    def wait_request(self, email: str, request_id: str, statuses: set[str], timeout: float = 45) -> dict[str, Any]:
        deadline = time.monotonic() + timeout
        last: dict[str, Any] = {}
        while time.monotonic() < deadline:
            last = self.api.get(email, f"/actions/requests/{request_id}").json()
            if last.get("status") in statuses:
                return last
            time.sleep(0.5)
        raise AssertionError(f"request {request_id} stayed {last.get('status')}, expected {statuses}")

    def wait_run(self, email: str, run_id: str, predicate: Any, timeout: float = 60) -> dict[str, Any]:
        deadline = time.monotonic() + timeout
        last: dict[str, Any] = {}
        while time.monotonic() < deadline:
            last = self.api.get(email, f"/workflow-runs/{run_id}").json()
            if predicate(last):
                return last
            time.sleep(0.5)
        raise AssertionError(f"run {run_id} did not reach the expected state: {last}")


@pytest.fixture(scope="session")
def automation(env: Env) -> Iterator[AutomationEnv]:
    with (
        DockerContainer(TEMPORAL_IMAGE)
        .with_command("server start-dev --ip 0.0.0.0 --headless")
        .with_exposed_ports(7233)
        .waiting_for(LogMessageWaitStrategy("Server:")) as temporal
    ):
        address = f"{temporal.get_container_host_ip()}:{temporal.get_exposed_port(7233)}"
        token = secrets.token_hex(24)
        settings = env.settings.model_copy(update={"temporal_address": address, "workflow_token": SecretStr(token)})
        dev = settings.model_copy(update={"environment": "dev"})
        seed_demo_integrations(dev)
        seed_demo_playbooks(dev)

        app = create_app(settings, mailer=MemoryMailer())
        port = _free_port()
        server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning", loop="none"))
        thread = threading.Thread(target=server.run, name="api-server", daemon=True)
        thread.start()
        deadline = time.monotonic() + 30
        while not server.started and time.monotonic() < deadline:
            time.sleep(0.1)
        attach_gateway(app, settings)
        url = f"http://127.0.0.1:{port}"
        worker = WorkerThread(address, url, token)
        worker.start()
        with httpx.Client(base_url=url, timeout=60) as client:
            auto_env = dataclasses.replace(env, settings=settings)
            yield AutomationEnv(env=auto_env, api=Api(auto_env, client), settings=settings, worker=worker, api_url=url)
        worker.stop()
        server.should_exit = True
        thread.join(15)
