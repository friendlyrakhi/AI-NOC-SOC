"""Connector error taxonomy (docs/06 §5). The runner maps these to health states."""


class ConnectorError(Exception):
    """Base class. Messages must never contain secrets."""

    retryable = False
    health = "degraded"


class AuthError(ConnectorError):
    health = "failing"


class PermissionDeniedError(ConnectorError):
    health = "failing"


class RateLimitedError(ConnectorError):
    retryable = True

    def __init__(self, message: str = "rate limited", retry_after: float = 30.0) -> None:
        super().__init__(message)
        self.retry_after = retry_after


class TransientError(ConnectorError):
    retryable = True


class SchemaDriftError(ConnectorError):
    """The vendor payload no longer matches the expected schema."""


class ConfigError(ConnectorError):
    health = "failing"


class EgressBlockedError(ConnectorError):
    """Outbound request refused by the SSRF / egress policy."""

    health = "failing"
