"""Provider interface. Providers turn a rendered prompt into an ``AiOutput``; they have no tools
and no way to act on anything (threat model LLM06)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from ai_gateway.schemas import AiOutput, GenerateRequest


class ProviderError(Exception):
    """The provider failed or returned something unusable. Message never contains evidence."""


class ProviderRefusalError(ProviderError):
    """The model declined the request."""


@dataclass(frozen=True)
class ProviderResult:
    output: AiOutput
    model: str
    tokens_in: int
    tokens_out: int


class Provider(Protocol):
    name: str

    async def generate(self, req: GenerateRequest, system: str, user: str) -> ProviderResult: ...
