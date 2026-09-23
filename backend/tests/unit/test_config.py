"""Unit tests for configuration management."""

from app.core.config import Settings


def test_default_settings_instantiation():
    """Verify default settings instantiation and types."""
    settings = Settings()
    assert settings.app_name == "TunnelTrace AI"
    assert settings.app_env in ["development", "testing", "production"]
    assert settings.api_v1_prefix == "/api/v1"
    assert settings.database_pool_size >= 5
    assert not settings.netagent_enabled


def test_masked_secrets():
    """Ensure sensitive credentials are masked and never leaked in representations."""
    settings = Settings(
        database_url="postgresql+asyncpg://supersecret_user:supersecret_pass@db.internal:5432/tt_db",
        redis_url="redis://:redis_secret_token@redis.internal:6379/0",
    )
    masked = settings.masked_dict()
    assert "supersecret_pass" not in masked["database_url"]
    assert "***" in masked["database_url"]
    assert "redis_secret_token" not in masked["redis_url"]
    assert "***" in masked["redis_url"]

    # Also test repr
    rep = repr(settings)
    assert "supersecret_pass" not in rep
    assert "redis_secret_token" not in rep


def test_cors_origins_parsing():
    """Test CORS origin parsing from list and comma-separated strings."""
    s1 = Settings(cors_allowed_origins=["http://localhost:3000", "http://127.0.0.1:3000"])
    assert len(s1.cors_allowed_origins) == 2

    s2 = Settings(cors_allowed_origins="http://localhost:3000,http://127.0.0.1:3000")
    assert len(s2.cors_allowed_origins) == 2
    assert "http://localhost:3000" in s2.cors_allowed_origins


def test_env_override(monkeypatch):
    """Test that environment variables override defaults cleanly."""
    monkeypatch.setenv("APP_NAME", "TunnelTrace SIH Test")
    monkeypatch.setenv("APP_PORT", "9090")
    monkeypatch.setenv("NETAGENT_ENABLED", "true")

    settings = Settings()
    assert settings.app_name == "TunnelTrace SIH Test"
    assert settings.app_port == 9090
    assert settings.netagent_enabled is True
