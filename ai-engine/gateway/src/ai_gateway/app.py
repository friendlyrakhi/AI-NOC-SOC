"""AI gateway HTTP service (internal only).

POST /v1/generate  task + evidence -> structured output (redacted, templated, provider-routed)
POST /v1/embed     texts -> vectors (local hash embeddings)
GET  /health

The gateway holds provider keys; the API never does. It has no route to the connector-runner,
the event bus or any data store, and no provider is given tools (threat model LLM06).
"""

from __future__ import annotations

import hmac
import logging
import time
from typing import Annotated, Any

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse

from ai_gateway import embeddings
from ai_gateway.config import GatewaySettings
from ai_gateway.providers.base import Provider, ProviderError, ProviderRefusalError
from ai_gateway.providers.mock import MockProvider
from ai_gateway.redaction import redact
from ai_gateway.schemas import (
    EmbedRequest,
    EmbedResponse,
    GenerateRequest,
    GenerateResponse,
    Policy,
    Usage,
)
from ai_gateway.templates import load_templates, render_user_message

logger = logging.getLogger("ai_gateway")


class EgressDeniedError(Exception):
    pass


class Providers:
    """Builds a provider only once it is allowed. A cloud client object is never created while
    egress is off, so no code path can open a connection to it."""

    def __init__(self, settings: GatewaySettings) -> None:
        self.settings = settings
        self._cache: dict[str, Provider] = {"mock": MockProvider()}

    def available(self) -> dict[str, bool]:
        s = self.settings
        return {
            "mock": True,
            "ollama": bool(s.ollama_url),
            "anthropic": bool(s.cloud_egress_enabled and s.anthropic_api_key),
        }

    def select(self, policy: Policy) -> Provider:
        s = self.settings
        if policy.provider == "mock":
            return self._cache["mock"]
        if policy.provider == "ollama":
            if not s.ollama_url:
                raise EgressDeniedError("the local model server is not configured")
            if "ollama" not in self._cache:
                from ai_gateway.providers.ollama import OllamaProvider

                self._cache["ollama"] = OllamaProvider(s.ollama_url, s.ollama_model, s.request_timeout_seconds)
            return self._cache["ollama"]
        if policy.provider == "anthropic":
            if not s.cloud_egress_enabled:
                raise EgressDeniedError("cloud egress is disabled on this gateway")
            if not policy.allow_cloud:
                raise EgressDeniedError("this tenant has not opted in to cloud AI")
            if s.anthropic_api_key is None:
                raise EgressDeniedError("no Anthropic API key is configured")
            if "anthropic" not in self._cache:
                from ai_gateway.providers.anthropic import AnthropicProvider

                self._cache["anthropic"] = AnthropicProvider(
                    s.anthropic_api_key.get_secret_value(),
                    s.anthropic_model,
                    s.anthropic_effort,
                    s.request_timeout_seconds,
                )
            return self._cache["anthropic"]
        raise EgressDeniedError(f"unknown provider {policy.provider}")


def _redact_value(value: Any, pii: bool) -> tuple[Any, int]:
    if isinstance(value, str):
        return redact(value, pii=pii)
    if isinstance(value, list):
        total, out = 0, []
        for v in value:
            r, n = _redact_value(v, pii)
            out.append(r)
            total += n
        return out, total
    if isinstance(value, dict):
        total, d = 0, {}
        for k, v in value.items():
            r, n = _redact_value(v, pii)
            d[k] = r
            total += n
        return d, total
    return value, 0


def create_app(settings: GatewaySettings | None = None, providers: Providers | None = None) -> FastAPI:
    settings = settings or GatewaySettings()
    registry = providers or Providers(settings)
    app = FastAPI(title="NOC/SOC AI gateway", docs_url=None, redoc_url=None, openapi_url=None)

    def authorize(x_gateway_token: Annotated[str, Header()] = "") -> None:  # nosec B107 - header default, not a secret
        expected = settings.gateway_token
        if expected is None:
            raise HTTPException(503, "gateway token not configured")
        if not hmac.compare_digest(x_gateway_token.encode(), expected.get_secret_value().encode()):
            raise HTTPException(401, "invalid gateway token")

    @app.exception_handler(EgressDeniedError)
    async def _egress(_: Request, exc: EgressDeniedError) -> JSONResponse:
        return JSONResponse({"code": "ai.egress_denied", "detail": str(exc)}, status_code=403)

    @app.exception_handler(ProviderRefusalError)
    async def _refused(_: Request, exc: ProviderRefusalError) -> JSONResponse:
        return JSONResponse({"code": "ai.refused", "detail": str(exc)}, status_code=422)

    @app.exception_handler(ProviderError)
    async def _failed(_: Request, exc: ProviderError) -> JSONResponse:
        return JSONResponse({"code": "ai.provider_error", "detail": str(exc)}, status_code=502)

    @app.get("/health")
    async def health() -> dict[str, Any]:
        return {"status": "ok", "providers": registry.available()}

    @app.post("/v1/generate", response_model=GenerateResponse, dependencies=[Depends(authorize)])
    async def generate(req: GenerateRequest) -> GenerateResponse:
        provider = registry.select(req.policy)
        templates = load_templates(settings.prompts_dir)
        template = templates.get(req.task)
        if template is None:
            raise HTTPException(404, f"no template for task {req.task}")
        pii = provider.name != "mock" and req.policy.redact_pii
        redactions = 0
        evidence: list[dict[str, Any]] = []
        for e in req.evidence:
            item, n = _redact_value(e.model_dump(), pii)
            redactions += n
            evidence.append(item)
        question = None
        if req.question:
            question, n = redact(req.question, pii=pii)
            redactions += n
        redacted = req.model_copy(update={"question": question})
        user = render_user_message(template, redacted, evidence)
        started = time.monotonic()
        result = await provider.generate(redacted, template.system, user)
        latency = int((time.monotonic() - started) * 1000)
        logger.info(
            "generate task=%s provider=%s model=%s tokens=%d/%d",
            req.task,
            provider.name,
            result.model,
            result.tokens_in,
            result.tokens_out,
        )
        return GenerateResponse(
            output=result.output,
            provider=provider.name,  # type: ignore[arg-type]
            model=result.model,
            template=template.ref,
            usage=Usage(
                tokens_in=result.tokens_in, tokens_out=result.tokens_out, latency_ms=latency, redactions=redactions
            ),
        )

    @app.post("/v1/embed", response_model=EmbedResponse, dependencies=[Depends(authorize)])
    async def embed(req: EmbedRequest) -> EmbedResponse:
        return EmbedResponse(
            model=embeddings.MODEL,
            dimensions=embeddings.DIMENSIONS,
            vectors=[embeddings.embed(t[:20_000]) for t in req.texts],
        )

    return app


def main() -> None:
    import uvicorn

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    uvicorn.run(create_app(), host="0.0.0.0", port=8200, log_level="info")  # noqa: S104  # nosec B104 - container-internal service
