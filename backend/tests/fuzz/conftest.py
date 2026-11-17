"""Fuzzing fixtures: the same container-backed stack as the integration tests."""

from support.insights import insights  # noqa: F401 - pytest fixture (OpenSearch on top of stream)
from support.integration import api, client, env, mailer  # noqa: F401 - pytest fixtures
from support.stream import stream  # noqa: F401 - pytest fixture (Redpanda + ClickHouse)
