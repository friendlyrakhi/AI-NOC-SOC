"""Connector SDK (docs/06-connector-sdk.md). The full contract lands in P2.

P0 ships only the execution-mode guard, so the "no live execution" rule exists and is
tested before any connector does.
"""

from nocsoc_connector_sdk.execution import (
    Certification,
    ConnectorMode,
    ExecutionDisabledError,
    ExecutionMode,
    assert_execution_allowed,
)

__version__ = "0.1.0"

__all__ = [
    "Certification",
    "ConnectorMode",
    "ExecutionDisabledError",
    "ExecutionMode",
    "assert_execution_allowed",
]
