"""Local Ollama adapter (optional). Uses Ollama's JSON-schema ``format`` for structured output."""

from __future__ import annotations

import json

import httpx
from pydantic import ValidationError

from ai_gateway.providers.base import ProviderError, ProviderResult
from ai_gateway.schemas import OUTPUT_JSON_SCHEMA, AiOutput, GenerateRequest


class OllamaProvider:
    name = "ollama"

    def __init__(self, base_url: str, model: str, timeout: float) -> None:
        self.model = model
        self._client = httpx.AsyncClient(base_url=base_url.rstrip("/"), timeout=timeout, follow_redirects=False)

    async def generate(self, req: GenerateRequest, system: str, user: str) -> ProviderResult:
        try:
            r = await self._client.post(
                "/api/chat",
                json={
                    "model": self.model,
                    "stream": False,
                    "format": OUTPUT_JSON_SCHEMA,
                    "options": {"num_predict": req.policy.max_output_tokens, "temperature": 0},
                    "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
                },
            )
            r.raise_for_status()
            data = r.json()
            output = AiOutput.model_validate(json.loads(data["message"]["content"]))
        except httpx.HTTPError as exc:
            raise ProviderError("local model unreachable") from exc
        except (KeyError, ValueError, ValidationError) as exc:
            raise ProviderError("output did not match the schema") from exc
        return ProviderResult(
            output=output,
            model=f"ollama:{self.model}",
            tokens_in=int(data.get("prompt_eval_count", 0)),
            tokens_out=int(data.get("eval_count", 0)),
        )
