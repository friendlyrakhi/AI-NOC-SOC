"""Runtime configuration.

Values come from environment variables (prefix ``NOCSOC_``) and Docker secret files in
``/run/secrets``. Secret file names include the prefix, e.g. ``nocsoc_database_password``.
Secrets are never given defaults.
"""

from functools import lru_cache
from pathlib import Path
from typing import Literal

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

    database_host: str = "postgres"
    database_port: int = 5432
    database_name: str = "nocsoc"
    database_user: str = "nocsoc_app"
    database_password: SecretStr | None = None

    valkey_host: str = "valkey"
    valkey_port: int = 6379
    valkey_password: SecretStr | None = None

    readiness_timeout_seconds: float = Field(default=2.0, gt=0, le=10)

    otel_enabled: bool = False


@lru_cache
def get_settings() -> Settings:
    return Settings()
