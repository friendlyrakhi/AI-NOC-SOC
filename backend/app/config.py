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
    valkey_tls: bool = False

    # --- Streaming (Kafka API: Redpanda in dev). Optional: features return 503 without it.
    kafka_bootstrap: str | None = None
    # --- Analytics (ClickHouse). Optional.
    clickhouse_host: str | None = None
    clickhouse_port: int = 8123
    clickhouse_secure: bool = False  # hardened profile: HTTPS (port 8443)
    clickhouse_database: str = "nocsoc"
    clickhouse_admin_user: str = "nocsoc_admin"
    clickhouse_admin_password: SecretStr | None = None
    clickhouse_ingest_password: SecretStr | None = None
    clickhouse_reader_password: SecretStr | None = None
    # --- Search and hunting (P6): OpenSearch with the security plugin. Optional: search falls
    # back to Postgres and hunts answer 503 without it. Reader (API) and indexer (ingest worker)
    # are separate store users; the admin password is used only by the one-shot setup job.
    opensearch_url: str | None = None
    opensearch_reader_password: SecretStr | None = None
    opensearch_indexer_password: SecretStr | None = None
    opensearch_admin_password: SecretStr | None = None
    # Analytics projector (P6): Postgres state -> ClickHouse facts and the OpenSearch entity index.
    projector_interval_seconds: float = Field(default=5.0, gt=0, le=3600)
    # Telemetry outbox (P7): undelivered ClickHouse/OpenSearch rows are retried at this interval and
    # dropped (with a warning) after the maximum age; raw records stay replayable from the bus.
    telemetry_outbox_interval_seconds: float = Field(default=5.0, gt=0, le=3600)
    telemetry_outbox_max_age_hours: int = Field(default=72, ge=1, le=720)
    # Hunts run asynchronously; per tenant at most this many at once and per hour.
    hunt_max_concurrent: int = Field(default=2, ge=1, le=20)
    hunt_runs_per_hour: int = Field(default=60, ge=1, le=10_000)
    # --- AI gateway (P4). Optional: AI endpoints return 503 without it.
    ai_gateway_url: str | None = None
    ai_gateway_token: SecretStr | None = None
    ai_request_timeout_seconds: float = Field(default=90.0, gt=0, le=600)
    # --- Workflow automation (P5): Temporal and the workflow worker. Optional: 503 without it.
    temporal_address: str | None = None
    temporal_namespace: str = "default"
    workflow_token: SecretStr | None = None
    approval_expiry_minutes: int = Field(default=30, ge=1, le=1440)
    # Shared token the connector-runner presents on internal endpoints.
    runner_token: SecretStr | None = None
    webhook_max_bytes: int = Field(default=1_048_576, ge=1024, le=10_485_760)

    # --- Secrets (envelope encryption master key, 32 bytes hex) ---
    master_key: SecretStr | None = None
    # P7 hardened profile: data keys from OpenBao Transit (AppRole credentials written by the
    # one-shot openbao-setup job). With a master key still configured, v1 values stay readable.
    secrets_provider: Literal["local", "openbao"] = "local"
    openbao_url: str | None = None
    openbao_approle_dir: str = "/run/openbao"
    openbao_transit_key: str = "nocsoc-master"
    # CA bundle for TLS between services (hardened profile); None = plain connections (dev).
    tls_ca_file: str | None = None

    # --- Audit anchors (P7, threat model T28): signed chain heads outside the database. Only the
    # audit-anchor service (and the one-shot verifier) hold this key and mount the anchor volume.
    audit_anchor_key: SecretStr | None = None
    audit_anchor_path: str = "/var/lib/nocsoc/anchors/audit-anchors.jsonl"
    audit_anchor_interval_seconds: float = Field(default=300.0, gt=0, le=86_400)
    audit_anchor_heartbeat_seconds: float = Field(default=3600.0, gt=0, le=86_400)

    # --- Optional OIDC sign-in (P7, D7): Keycloak (`sso` profile) or Entra ID. Users must already
    # exist (matched by verified e-mail). Discovery and token calls use the internal URL; the issuer
    # is what the IdP puts in its tokens (its public URL).
    oidc_enabled: bool = False
    oidc_display_name: str = "Single sign-on"
    oidc_issuer: str | None = None
    oidc_discovery_url: str | None = None
    oidc_client_id: str = "nocsoc-web"
    oidc_client_secret: SecretStr | None = None
    oidc_redirect_uri: str = "http://127.0.0.1:3000/login/sso/callback"
    # A session is MFA when the ID token's amr has one of these, or the IdP enforces MFA for everyone.
    oidc_mfa_amr: list[str] = Field(default_factory=lambda: ["otp", "mfa", "hwk", "swk", "totp"])
    oidc_idp_enforces_mfa: bool = False

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

    # Concurrent live-update (SSE) streams (P7): per tenant and per user.
    sse_streams_per_tenant: int = Field(default=100, ge=1, le=10_000)
    sse_streams_per_user: int = Field(default=6, ge=1, le=100)
    # Per-user AI requests per hour (P7), on top of the tenant's daily token budget.
    ai_requests_per_user_hour: int = Field(default=120, ge=1, le=10_000)

    # Per-tenant API budget for expensive endpoints (scenario replay, event search).
    tenant_heavy_requests_per_minute: int = Field(default=60, ge=1, le=10_000)
    # Per-tenant ingest quota (records per minute). Over-quota records are dead-lettered with
    # reason "quota_exceeded" (kept, visible to the tenant, replayable), so one noisy tenant
    # cannot monopolise the ingest workers.
    tenant_ingest_records_per_minute: int = Field(default=6000, ge=10, le=1_000_000)

    def _url(self, user: str, password: SecretStr | None) -> str:
        pw = quote(password.get_secret_value(), safe="") if password else ""
        url = (
            f"postgresql+psycopg://{quote(user, safe='')}:{pw}"
            f"@{self.database_host}:{self.database_port}/{self.database_name}"
        )
        if self.tls_ca_file:  # hardened profile: TLS with full certificate and host name checks
            url += f"?sslmode=verify-full&sslrootcert={quote(self.tls_ca_file, safe='/')}"
        return url

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
