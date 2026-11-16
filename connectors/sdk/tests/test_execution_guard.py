import itertools

import pytest

from nocsoc_connector_sdk.execution import (
    Certification,
    ConnectorMode,
    ExecutionDisabledError,
    ExecutionMode,
    assert_execution_allowed,
)


@pytest.mark.parametrize("requested", [ExecutionMode.DRY_RUN, ExecutionMode.SIMULATE])
def test_non_live_modes_always_allowed(requested: ExecutionMode) -> None:
    assert_execution_allowed(
        requested,
        platform_mode=ExecutionMode.SIMULATE,
        connector_mode=ConnectorMode.SANDBOX,
        certification=Certification.SANDBOX,
    )


_live_combos = [
    combo
    for combo in itertools.product(ExecutionMode, ConnectorMode, Certification)
    if combo != (ExecutionMode.LIVE, ConnectorMode.LIVE, Certification.LIVE_VERIFIED)
]


@pytest.mark.parametrize(("platform", "connector", "cert"), _live_combos)
def test_live_blocked_unless_every_gate_open(
    platform: ExecutionMode, connector: ConnectorMode, cert: Certification
) -> None:
    with pytest.raises(ExecutionDisabledError):
        assert_execution_allowed(
            ExecutionMode.LIVE,
            platform_mode=platform,
            connector_mode=connector,
            certification=cert,
        )
