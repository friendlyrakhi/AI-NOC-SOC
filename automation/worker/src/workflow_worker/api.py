"""Client for the platform's internal workflow endpoints (the worker has no database access)."""

from __future__ import annotations

from typing import Any

import httpx


class WorkflowApi:
    def __init__(self, base_url: str, token: str, transport: httpx.AsyncBaseTransport | None = None) -> None:
        self._client = httpx.AsyncClient(
            base_url=base_url.rstrip("/") + "/api/v1/internal/workflow",
            headers={"X-Workflow-Token": token},
            timeout=30.0,
            transport=transport,
            follow_redirects=False,
        )

    async def close(self) -> None:
        await self._client.aclose()

    async def _post(self, path: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
        r = await self._client.post(path, json=body or {})
        r.raise_for_status()
        data: dict[str, Any] = r.json()
        return data

    async def claim(self, request_id: str) -> dict[str, Any]:
        return await self._post(f"/actions/{request_id}/claim")

    async def complete(self, request_id: str, status: str, result: dict[str, Any], error: str | None) -> None:
        await self._post(f"/actions/{request_id}/complete", {"status": status, "result": result, "error": error})

    async def platform_execute(self, request_id: str) -> dict[str, Any]:
        return await self._post(f"/actions/{request_id}/platform-execute")

    async def expire(self, request_id: str) -> dict[str, Any]:
        return await self._post(f"/actions/{request_id}/expire")

    async def request_status(self, request_id: str) -> dict[str, Any]:
        r = await self._client.get(f"/actions/{request_id}")
        r.raise_for_status()
        data: dict[str, Any] = r.json()
        return data

    async def request_step(self, run_id: str, step_id: str) -> dict[str, Any]:
        return await self._post(f"/runs/{run_id}/steps/{step_id}/request")

    async def checkpoint(self, run_id: str) -> dict[str, Any]:
        return await self._post(f"/runs/{run_id}/checkpoint")

    async def step_result(self, run_id: str, step_id: str, status: str, request_id: str | None, detail: str) -> None:
        await self._post(
            f"/runs/{run_id}/step-result",
            {"step_id": step_id, "status": status, "request_id": request_id, "detail": detail[:500]},
        )

    async def finish(self, run_id: str, status: str, error: str | None) -> None:
        await self._post(f"/runs/{run_id}/finish", {"status": status, "error": error})
