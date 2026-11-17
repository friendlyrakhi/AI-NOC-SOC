"""Client for the platform's internal runner endpoints."""

from __future__ import annotations

from typing import Any, Protocol

import httpx


class PlatformApi(Protocol):
    async def work(self) -> list[dict[str, Any]]: ...

    async def credentials(self, instance_id: str) -> dict[str, str]: ...

    async def report(self, instance_id: str, body: dict[str, Any]) -> None: ...


class HttpPlatformApi:
    def __init__(self, base_url: str, token: str, verify: str | bool = True) -> None:
        self._client = httpx.AsyncClient(
            base_url=base_url.rstrip("/") + "/api/v1/internal/runner",
            headers={"X-Runner-Token": token},
            timeout=15.0,
            follow_redirects=False,
            verify=verify,  # hardened profile: credentials travel over TLS to the platform CA
        )

    async def close(self) -> None:
        await self._client.aclose()

    async def work(self) -> list[dict[str, Any]]:
        r = await self._client.get("/work")
        r.raise_for_status()
        data: list[dict[str, Any]] = r.json()
        return data

    async def credentials(self, instance_id: str) -> dict[str, str]:
        r = await self._client.get(f"/instances/{instance_id}/credentials")
        r.raise_for_status()
        secrets: dict[str, str] = r.json()["secrets"]
        return secrets

    async def report(self, instance_id: str, body: dict[str, Any]) -> None:
        r = await self._client.post(f"/instances/{instance_id}/report", json=body)
        r.raise_for_status()
