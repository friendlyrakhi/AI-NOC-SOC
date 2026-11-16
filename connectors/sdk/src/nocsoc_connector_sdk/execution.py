"""Execution-mode policy enforced by the SDK base class (docs/06-connector-sdk.md §4)."""

from enum import StrEnum


class ExecutionMode(StrEnum):
    DRY_RUN = "dry_run"
    SIMULATE = "simulate"
    LIVE = "live"


class ConnectorMode(StrEnum):
    SANDBOX = "sandbox"
    LIVE = "live"


class Certification(StrEnum):
    SANDBOX = "sandbox"
    CONTRACT_TESTED = "contract-tested"
    LIVE_VERIFIED = "live-verified"


class ExecutionDisabledError(RuntimeError):
    """Raised when an action would run against a real system without every gate open."""


def assert_execution_allowed(
    requested: ExecutionMode,
    *,
    platform_mode: ExecutionMode,
    connector_mode: ConnectorMode,
    certification: Certification,
) -> None:
    """Allow ``dry_run`` and ``simulate`` always. Allow ``live`` only when all gates agree.

    In Phases 0-7 the platform mode is never ``live`` (the API settings reject it), so this
    always raises for live requests.
    """
    if requested is not ExecutionMode.LIVE:
        return
    if (
        platform_mode is not ExecutionMode.LIVE
        or connector_mode is not ConnectorMode.LIVE
        or certification is not Certification.LIVE_VERIFIED
    ):
        raise ExecutionDisabledError(
            "live execution is disabled "
            f"(platform={platform_mode}, connector={connector_mode}, cert={certification})"
        )
