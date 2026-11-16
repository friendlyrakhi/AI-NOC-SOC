"""Anthropic Claude adapter (cloud; off unless egress is enabled and the tenant opted in).

Uses the official SDK with structured outputs (``output_config.format`` with a JSON schema), so
the response is constrained to the gateway's output contract. Server-side refusal fallback is
enabled (``fallbacks: "default"``); a refusal that remains is surfaced as ``ProviderRefusalError``.
No tools are declared: the model cannot call anything.
"""

from __future__ import annotations

import json

import anthropic
from anthropic.types.beta import BetaMessageParam, BetaOutputConfigParam
from pydantic import ValidationError

from ai_gateway.providers.base import ProviderError, ProviderRefusalError, ProviderResult
from ai_gateway.schemas import OUTPUT_JSON_SCHEMA, AiOutput, GenerateRequest

FALLBACK_BETA = "server-side-fallback-2026-07-01"


class AnthropicProvider:
    name = "anthropic"

    def __init__(self, api_key: str, model: str, effort: str, timeout: float) -> None:
        self.model = model
        self.effort = effort
        self._client = anthropic.AsyncAnthropic(api_key=api_key, timeout=timeout, max_retries=2)

    async def generate(self, req: GenerateRequest, system: str, user: str) -> ProviderResult:
        messages: list[BetaMessageParam] = [{"role": "user", "content": user}]
        output_config: BetaOutputConfigParam = {
            "effort": self.effort,  # type: ignore[typeddict-item]
            "format": {"type": "json_schema", "schema": OUTPUT_JSON_SCHEMA},
        }
        try:
            response = await self._client.beta.messages.create(
                model=self.model,
                max_tokens=req.policy.max_output_tokens,
                system=system,
                messages=messages,
                output_config=output_config,
                betas=[FALLBACK_BETA],
                fallbacks="default",
            )
        except anthropic.RateLimitError as exc:
            raise ProviderError("provider rate limited") from exc
        except anthropic.APIStatusError as exc:
            raise ProviderError(f"provider error {exc.status_code}") from exc
        except anthropic.APIConnectionError as exc:
            raise ProviderError("provider unreachable") from exc
        if response.stop_reason == "refusal":
            raise ProviderRefusalError("the model declined this request")
        if response.stop_reason == "max_tokens":
            raise ProviderError("output truncated at max_tokens")
        text = next((b.text for b in response.content if b.type == "text"), "")
        try:
            output = AiOutput.model_validate(json.loads(text))
        except (ValueError, ValidationError) as exc:
            raise ProviderError("output did not match the schema") from exc
        return ProviderResult(
            output=output,
            model=response.model,
            tokens_in=response.usage.input_tokens,
            tokens_out=response.usage.output_tokens,
        )
