"""Integration fixtures: real Postgres + Valkey in disposable containers, real migrations,
real seed data, and the real FastAPI app (no mocks of the security layer)."""

from support.integration import api, client, env, mailer  # noqa: F401 - pytest fixtures
