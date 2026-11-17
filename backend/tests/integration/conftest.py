"""Integration fixtures: real Postgres + Valkey in disposable containers, real migrations,
real seed data, and the real FastAPI app (no mocks of the security layer)."""

from support.automation import automation  # noqa: F401 - pytest fixture (Temporal + worker)
from support.integration import api, client, env, mailer  # noqa: F401 - pytest fixtures
from support.stream import stream  # noqa: F401 - pytest fixture (Redpanda + ClickHouse)
