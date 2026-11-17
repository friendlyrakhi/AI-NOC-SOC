"""HTTP client for the internal AI gateway. The API never holds model keys or calls a model."""

from __future__ import annotations

from typing import Any

import httpx

from app.errors import ProblemError
from app.services import Services


class GatewayError(ProblemError):
    pass


def _client(services: Services) -> httpx.AsyncClient:
    s = services.settings
    if not s.ai_gateway_url or s.ai_gateway_token is None:
        raise GatewayError(503, "ai.disabled", "AI not configured", "Start the 'ai' profile to use AI assistance.")
    return httpx.AsyncClient(
        base_url=s.ai_gateway_url.rstrip("/"),
        headers={"X-Gateway-Token": s.ai_gateway_token.get_secret_value()},
        timeout=s.ai_request_timeout_seconds,
        transport=services.ai_transport,  # injected in tests (in-process gateway)
        follow_redirects=False,
        verify=s.tls_ca_file or True,  # hardened profile: the gateway serves TLS
    )


async def _post(services: Services, path: str, body: dict[str, Any]) -> dict[str, Any]:
    try:
        async with _client(services) as c:
            r = await c.post(path, json=body)
    except httpx.HTTPError as exc:
        raise GatewayError(503, "ai.unavailable", "AI unavailable", "The AI gateway could not be reached.") from exc
    if r.status_code == 200:
        data: dict[str, Any] = r.json()
        return data
    detail = ""
    try:
        detail = str(r.json().get("detail", ""))[:300]
        code = str(r.json().get("code", "ai.error"))
    except ValueError:
        code = "ai.error"
    if r.status_code == 403:
        raise GatewayError(
            409, "ai.egress_denied", "Provider not allowed", detail or "This AI provider is not enabled."
        )
    if r.status_code == 422 and code == "ai.refused":
        raise GatewayError(422, "ai.refused", "The model declined", detail)
    raise GatewayError(502, "ai.provider_error", "AI provider error", detail or f"Gateway returned {r.status_code}.")


async def generate(services: Services, body: dict[str, Any]) -> dict[str, Any]:
    return await _post(services, "/v1/generate", body)


async def embed(services: Services, texts: list[str]) -> tuple[str, list[list[float]]]:
    data = await _post(services, "/v1/embed", {"texts": texts})
    return str(data["model"]), data["vectors"]


async def health(services: Services) -> dict[str, Any] | None:
    try:
        async with _client(services) as c:
            r = await c.get("/health")
        return r.json() if r.status_code == 200 else None
    except (httpx.HTTPError, ProblemError):
        return None
