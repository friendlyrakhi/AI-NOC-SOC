"""Health state machine, circuit breaker and rate limiting per instance (docs/06 §5).

Health is derived only from real fetch outcomes:
- success -> healthy (degraded if the source rate-limited us, or records drifted from the schema)
- retryable or drift errors -> degraded; three consecutive failures -> failing
- auth, permission, configuration and egress errors -> failing immediately

While failing, an open circuit spaces retries with exponential backoff (max 15 min).
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Literal

from nocsoc_connector_sdk import ConnectorError, RateLimitedError

Health = Literal["healthy", "degraded", "failing"]

FAILING_AFTER = 3
BASE_BACKOFF_SECONDS = 15.0
MAX_BACKOFF_SECONDS = 900.0


@dataclass
class InstanceHealth:
    consecutive_failures: int = 0
    open_until: float = 0.0  # monotonic seconds; circuit open while now < open_until
    health: Health = "healthy"

    def allows(self, now: float | None = None) -> bool:
        return (now if now is not None else time.monotonic()) >= self.open_until

    def success(self, *, rate_limited: bool = False, drifted: bool = False) -> Health:
        self.consecutive_failures = 0
        self.open_until = 0.0
        self.health = "degraded" if (rate_limited or drifted) else "healthy"
        return self.health

    def failure(self, exc: BaseException, now: float | None = None) -> Health:
        now = now if now is not None else time.monotonic()
        self.consecutive_failures += 1
        if isinstance(exc, RateLimitedError):
            self.open_until = now + min(MAX_BACKOFF_SECONDS, exc.retry_after)
            self.health = "degraded" if self.consecutive_failures < FAILING_AFTER else "failing"
            return self.health
        hard = isinstance(exc, ConnectorError) and exc.health == "failing"
        if hard or self.consecutive_failures >= FAILING_AFTER:
            self.health = "failing"
            backoff = BASE_BACKOFF_SECONDS * (2 ** min(self.consecutive_failures - 1, 6))
            self.open_until = now + min(MAX_BACKOFF_SECONDS, backoff)
        else:
            self.health = "degraded"
        return self.health


@dataclass
class TokenBucket:
    """Requests per minute towards one source (manifest ``rate_limit_per_minute``)."""

    per_minute: int
    tokens: float = field(default=-1.0)
    updated: float = field(default_factory=time.monotonic)

    def __post_init__(self) -> None:
        if self.tokens < 0:
            self.tokens = float(self.per_minute)

    def take(self, now: float | None = None) -> bool:
        now = now if now is not None else time.monotonic()
        self.tokens = min(float(self.per_minute), self.tokens + (now - self.updated) * self.per_minute / 60.0)
        self.updated = now
        if self.tokens >= 1.0:
            self.tokens -= 1.0
            return True
        return False


def error_class(exc: BaseException) -> str:
    return type(exc).__name__


def safe_detail(exc: BaseException) -> str:
    """Connector errors carry vetted messages; anything else is reduced to its class name."""
    if isinstance(exc, ConnectorError):
        return str(exc)[:500]
    return type(exc).__name__
