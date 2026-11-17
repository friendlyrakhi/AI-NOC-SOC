"""Worker settings (env prefix ``NOCSOC_``; secrets from /run/secrets)."""

from pathlib import Path

from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

_SECRETS_DIR = Path("/run/secrets")

TASK_QUEUE = "nocsoc-automation"


class WorkerSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="NOCSOC_",
        secrets_dir=_SECRETS_DIR if _SECRETS_DIR.is_dir() else None,
        extra="ignore",
    )

    api_url: str = "http://api:8000"
    workflow_token: SecretStr | None = None
    temporal_address: str = "temporal:7233"
    temporal_namespace: str = "default"
    # Observability profile (P7): spans over OTLP (standard OTEL_EXPORTER_OTLP_* variables).
    otel_enabled: bool = False
    # Hardened profile: CA bundle for the API's TLS certificate.
    tls_ca_file: str | None = None
