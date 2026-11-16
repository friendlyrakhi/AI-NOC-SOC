"""Runtime configuration.

Values come from environment variables (prefix ``NOCSOC_``) and Docker secret files in
``/run/secrets``. Secret file names include the prefix, e.g. ``nocsoc_database_password``.
Secrets are never given defaults.
"""

from functools import lru_cache
from pathlib import Path
from typing import Literal
from urllib.parse import quote

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

_SECRETS_DIR = Path("/run/secrets")


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="NOCSOC_",
        secrets_dir=_SECRETS_DIR if _SECRETS_DIR.is_dir() else None,
        extra="ignore",
    )

    environment: Literal["dev", "test"] = "dev"
    service_name: str = "nocsoc-api"

    # Guardrail (docs/README.md #2, threat T23): "live" is not a valid value in
    # Phases 0-7, so the process refuses to start if anyone tries to set it.
    execution_mode: Literal["dry_run", "simulate"] = "simulate"

    # --- PostgreSQL ---
    database_host: str = "postgres"
    database_port: int = 5432
    database_name: str = "nocsoc"
    # RLS-enforced application role (all tenant data access).
    database_user: str = "nocsoc_app"
    database_password: SecretStr | None = None
    # Identity role (BYPASSRLS, identity tables only). Used only by app.core.identity/authz.
    auth_database_user: str = "nocsoc_auth"
    auth_database_password: SecretStr | None = None
    # Ingest worker role (RLS enforced; tenant context set per message).
    worker_database_user: str = "nocsoc_worker"
    worker_database_password: SecretStr | None = None
    # Superuser: migrations and dev seeding only, never by the running API.
    postgres_user: str = "postgres"
    postgres_password: SecretStr | None = None

    # --- Valkey ---
    valkey_host: str = "valkey"
    valkey_port: int = 6379
    valkey_password: SecretStr | None = None

    # --- Streaming (Kafka API: Redpanda in dev). Optional: features return 503 without it.
    kafka_bootstrap: str | None = None
    # --- Analytics (ClickHouse). Optional.
    clickhouse_host: str | None = None
    clickhouse_port: int = 8123
    clickhouse_database: str = "nocsoc"
    clickhouse_admin_user: str = "nocsoc_admin"
    clickhouse_admin_password: SecretStr | None = None
    clickhouse_ingest_password: SecretStr | None = None
    clickhouse_reader_password: SecretStr | None = None
    # Shared token the connector-runner presents on internal endpoints.
    runner_token: SecretStr | None = None
    webhook_max_bytes: int = Field(default=1_048_576, ge=1024, le=10_485_760)

    # --- Secrets (envelope encryption master key, 32 bytes hex) ---
    master_key: SecretStr | None = None

    # --- Sessions & auth ---
    session_ttl_hours: int = Field(default=12, ge=1, le=72)
    session_idle_minutes: int = Field(default=60, ge=5, le=720)
    step_up_minutes: int = Field(default=5, ge=1, le=30)
    challenge_minutes: int = Field(default=5, ge=1, le=15)
    invitation_hours: int = Field(default=72, ge=1, le=336)
    login_max_failures: int = Field(default=10, ge=3)
    login_window_seconds: int = Field(default=900, ge=60)

    # --- Mail (Mailpit in dev) ---
    smtp_host: str = "mailpit"
    smtp_port: int = 1025
    mail_from: str = "noc-soc-platform@localhost"
    web_base_url: str = "http://127.0.0.1:3000"

    readiness_timeout_seconds: float = Field(default=2.0, gt=0, le=10)

    otel_enabled: bool = False
    log_format: Literal["json", "text"] = "json"

    # Per-tenant API budget for expensive endpoints (scenario replay, event search).
    tenant_heavy_requests_per_minute: int = Field(default=60, ge=1, le=10_000)
    # Per-tenant ingest quota (records per minute). Over-quota records are dead-lettered with
    # reason "quota_exceeded" (kept, visible to the tenant, replayable), so one noisy tenant
    # cannot monopolise the ingest workers.
    tenant_ingest_records_per_minute: int = Field(default=6000, ge=10, le=1_000_000)

    def _url(self, user: str, password: SecretStr | None) -> str:
        pw = quote(password.get_secret_value(), safe="") if password else ""
        return (
            f"postgresql+psycopg://{quote(user, safe='')}:{pw}"
            f"@{self.database_host}:{self.database_port}/{self.database_name}"
        )

    def app_database_url(self) -> str:
        return self._url(self.database_user, self.database_password)

    def auth_database_url(self) -> str:
        return self._url(self.auth_database_user, self.auth_database_password)

    def worker_database_url(self) -> str:
        return self._url(self.worker_database_user, self.worker_database_password)

    def superuser_database_url(self) -> str:
        return self._url(self.postgres_user, self.postgres_password)


@lru_cache
def get_settings() -> Settings:
    return Settings()
