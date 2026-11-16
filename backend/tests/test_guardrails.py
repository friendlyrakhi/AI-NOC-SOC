"""Early form of release gate SEC-ACT-03: live execution must be impossible."""

from pathlib import Path

import pytest
from pydantic import ValidationError

from app.config import Settings


def test_default_execution_mode_is_simulate() -> None:
    assert Settings().execution_mode == "simulate"


@pytest.mark.parametrize("value", ["live", "LIVE", "production", ""])
def test_live_execution_mode_rejected(monkeypatch: pytest.MonkeyPatch, value: str) -> None:
    monkeypatch.setenv("NOCSOC_EXECUTION_MODE", value)
    with pytest.raises(ValidationError):
        Settings()


def test_secrets_are_masked_in_repr(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NOCSOC_DATABASE_PASSWORD", "s3cr3t-value")
    settings = Settings()
    assert "s3cr3t-value" not in repr(settings)
    assert "s3cr3t-value" not in settings.model_dump_json()


def test_secrets_load_from_prefixed_files(tmp_path: Path) -> None:
    (tmp_path / "nocsoc_database_password").write_text("from-file")
    (tmp_path / "nocsoc_valkey_password").write_text("vk-file")
    settings = Settings(_secrets_dir=tmp_path)
    assert settings.database_password is not None
    assert settings.database_password.get_secret_value() == "from-file"
    assert settings.valkey_password is not None
    assert settings.valkey_password.get_secret_value() == "vk-file"
