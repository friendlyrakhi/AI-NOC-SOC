"""Gateway settings (env prefix ``NOCSOC_AI_``; secrets from /run/secrets).

Cloud egress is OFF unless ``cloud_egress_enabled`` is true AND a provider key is configured
AND the requesting tenant opted in. In the dev compose file the gateway also sits on an
internal-only network, so even a misconfiguration cannot reach the internet.
"""

from pathlib import Path

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

_SECRETS_DIR = Path("/run/secrets")
_DEFAULT_PROMPTS = Path(__file__).resolve().parents[3] / "prompts"


class GatewaySettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="NOCSOC_AI_",
        secrets_dir=_SECRETS_DIR if _SECRETS_DIR.is_dir() else None,
        extra="ignore",
    )

    # Shared token the API presents (X-Gateway-Token).
    gateway_token: SecretStr | None = None
    prompts_dir: Path = _DEFAULT_PROMPTS

    cloud_egress_enabled: bool = False
    anthropic_api_key: SecretStr | None = None
    anthropic_model: str = "claude-opus-5-5"
    anthropic_effort: str = Field(default="medium", pattern="^(low|medium|high|xhigh|max)$")

    # Local model server (Ollama). Not cloud egress, but still opt-in.
    ollama_url: str | None = None
    ollama_model: str = "llama3.1:8b"

    request_timeout_seconds: float = Field(default=60.0, gt=0, le=600)
