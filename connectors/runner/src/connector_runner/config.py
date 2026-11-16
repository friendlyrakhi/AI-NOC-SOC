"""Runner settings (env prefix ``NOCSOC_``; secrets from /run/secrets)."""

from pathlib import Path

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

_SECRETS_DIR = Path("/run/secrets")


class RunnerSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="NOCSOC_",
        secrets_dir=_SECRETS_DIR if _SECRETS_DIR.is_dir() else None,
        extra="ignore",
    )

    api_url: str = "http://api:8000"
    runner_token: SecretStr | None = None
    kafka_bootstrap: str = "redpanda:9092"
    poll_seconds: float = Field(default=5.0, ge=0.5, le=300)
    max_pages_per_run: int = Field(default=10, ge=1, le=100)
    concurrency: int = Field(default=8, ge=1, le=64)
