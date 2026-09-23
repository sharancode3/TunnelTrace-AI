"""Typed application configuration management using Pydantic Settings."""

from functools import lru_cache
from pathlib import Path

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Canonical configuration model for TunnelTrace AI."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # --------------------------------------------------------------------------
    # Application Runtime Settings
    # --------------------------------------------------------------------------
    APP_NAME: str = Field(default="TunnelTrace AI", description="System application name")
    APP_ENV: str = Field(
        default="development", description="Environment: development, test, production"
    )
    APP_DEBUG: bool = Field(default=False, description="Enable debug mode (disables in production)")
    APP_HOST: str = Field(default="127.0.0.1", description="Host address for loopback binding")
    APP_PORT: int = Field(default=8000, description="HTTP listening port")
    APP_LOG_LEVEL: str = Field(default="INFO", description="Log level: DEBUG, INFO, WARNING, ERROR")
    APP_SECRET_KEY: SecretStr = Field(
        default=SecretStr("insecure-local-dev-secret-change-in-production-min32chars"),
        description="Internal encryption and session signing key",
    )
    API_V1_PREFIX: str = Field(default="/api/v1", description="API version namespace prefix")

    # --------------------------------------------------------------------------
    # Database Settings (PostgreSQL 15+ with pgvector)
    # --------------------------------------------------------------------------
    DATABASE_URL: str = Field(
        default="postgresql+asyncpg://tunneltrace_user:tunneltrace_dev_password@127.0.0.1:5432/tunneltrace_db",
        description="Async SQLAlchemy database connection URI",
    )
    DATABASE_POOL_SIZE: int = Field(default=10, description="SQLAlchemy connection pool size")
    DATABASE_MAX_OVERFLOW: int = Field(
        default=5, description="Max overflow connections beyond pool size"
    )
    DATABASE_POOL_TIMEOUT: float = Field(
        default=30.0, description="Seconds to wait before giving up on acquiring connection"
    )
    DATABASE_ECHO: bool = Field(default=False, description="Log raw SQL queries for debugging")

    # --------------------------------------------------------------------------
    # Redis Settings (Caching & Asynchronous Broker)
    # --------------------------------------------------------------------------
    REDIS_URL: str = Field(
        default="redis://127.0.0.1:6379/0",
        description="Redis connection URI for broker and transient data",
    )
    REDIS_SOCKET_TIMEOUT: float = Field(
        default=2.0, description="Timeout in seconds for Redis socket operations"
    )
    REDIS_MAX_CONNECTIONS: int = Field(
        default=10, description="Maximum concurrent connection pool size for Redis"
    )
    REDIS_TIMEOUT: float = Field(
        default=2.0, description="General timeout in seconds for Redis operations"
    )

    # --------------------------------------------------------------------------
    # Celery Worker Settings
    # --------------------------------------------------------------------------
    CELERY_TASK_SERIALIZER: str = Field(
        default="json", description="Task payload serialization format (strict JSON)"
    )
    CELERY_RESULT_SERIALIZER: str = Field(
        default="json", description="Result payload serialization format"
    )
    CELERY_ACCEPT_CONTENT: list[str] = Field(
        default_factory=lambda: ["json"], description="Accepted serializers"
    )

    # --------------------------------------------------------------------------
    # Local Storage Settings
    # --------------------------------------------------------------------------
    STORAGE_ROOT: Path = Field(
        default=Path("./storage"),
        description="Root filesystem path for non-DB storage (captures, reports, temp files)",
    )

    # --------------------------------------------------------------------------
    # HTTP & CORS Security Settings
    # --------------------------------------------------------------------------
    CORS_ALLOWED_ORIGINS: list[str] = Field(
        default_factory=lambda: ["http://localhost:3000", "http://127.0.0.1:3000"],
        description="List of allowed CORS origins (never wildcard * in production)",
    )
    CORS_ALLOW_CREDENTIALS: bool = Field(default=True, description="Allow credentials in CORS")

    # --------------------------------------------------------------------------
    # Stage 3: Capture Ingestion & Protocol Forensics Settings
    # --------------------------------------------------------------------------
    CAPTURE_MAX_UPLOAD_BYTES: int = Field(
        default=250 * 1024 * 1024,
        description="Implementation safety default for maximum upload size in bytes (not official product limit)",
    )
    CAPTURE_MAX_DURATION_SEC: int = Field(
        default=300,
        description="Implementation safety default for live capture duration limit in seconds",
    )
    CAPTURE_MAX_BYTES: int = Field(
        default=500 * 1024 * 1024,
        description="Implementation safety default for live capture maximum byte volume",
    )
    TSHARK_TIMEOUT_SEC: float = Field(
        default=60.0,
        description="Implementation safety default for TShark subprocess execution timeout",
    )
    TSHARK_PATH: str | None = Field(
        default=None,
        description="Optional custom path to TShark binary",
    )
    CAPINFOS_PATH: str | None = Field(
        default=None,
        description="Optional custom path to Capinfos binary",
    )

    # --------------------------------------------------------------------------
    # Future Subsystem Boundaries (Placeholders for upcoming stages)
    # --------------------------------------------------------------------------
    NETAGENT_ENABLED: bool = Field(
        default=False, description="Whether privileged network agent is enabled"
    )
    NETAGENT_ENDPOINT: str = Field(
        default="http://127.0.0.1:8001", description="Privileged agent endpoint"
    )
    POLICIES_DIR: Path = Field(
        default=Path("./policies/active"), description="Directory for Policy-as-Code rules"
    )
    MODELS_DIR: Path = Field(
        default=Path("./models/active"), description="Directory for ML model artifacts"
    )

    @field_validator("CORS_ALLOWED_ORIGINS", mode="before")
    @classmethod
    def parse_cors_origins(cls, v: object) -> list[str]:
        if isinstance(v, str):
            import json

            try:
                parsed = json.loads(v)
                if isinstance(parsed, list):
                    return [str(item) for item in parsed]
            except Exception:
                return [origin.strip() for origin in v.split(",") if origin.strip()]
        elif isinstance(v, (list, tuple, set)):
            return [str(origin) for origin in v]
        return ["http://localhost:3000", "http://127.0.0.1:3000"]

    @property
    def sync_database_url(self) -> str:
        """Derive synchronous database URL for Alembic migrations and synchronous drivers."""
        url = self.DATABASE_URL
        if url.startswith("postgresql+asyncpg://"):
            return url.replace("postgresql+asyncpg://", "postgresql://", 1)
        return url

    @property
    def is_production(self) -> bool:
        """Check whether the active environment is production."""
        return self.APP_ENV.lower() == "production"

    @property
    def CELERY_BROKER_URL(self) -> str:
        """Celery broker URI matching Redis configuration."""
        return self.REDIS_URL

    @property
    def CELERY_RESULT_BACKEND(self) -> str:
        """Celery result backend URI matching Redis configuration."""
        return self.REDIS_URL

    # --------------------------------------------------------------------------
    # Lowercase property accessors for uniform API ergonomics
    # --------------------------------------------------------------------------
    @property
    def app_name(self) -> str:
        return self.APP_NAME

    @property
    def app_env(self) -> str:
        return self.APP_ENV

    @property
    def app_debug(self) -> bool:
        return self.APP_DEBUG

    @property
    def app_host(self) -> str:
        return self.APP_HOST

    @property
    def app_port(self) -> int:
        return self.APP_PORT

    @property
    def app_log_level(self) -> str:
        return self.APP_LOG_LEVEL

    @property
    def api_v1_prefix(self) -> str:
        return self.API_V1_PREFIX

    @property
    def database_url(self) -> str:
        return self.DATABASE_URL

    @property
    def database_pool_size(self) -> int:
        return self.DATABASE_POOL_SIZE

    @property
    def redis_url(self) -> str:
        return self.REDIS_URL

    @property
    def redis_socket_timeout(self) -> float:
        return self.REDIS_SOCKET_TIMEOUT

    @property
    def redis_max_connections(self) -> int:
        return self.REDIS_MAX_CONNECTIONS

    @property
    def storage_root(self) -> Path:
        return self.STORAGE_ROOT

    @property
    def cors_allowed_origins(self) -> list[str]:
        return self.CORS_ALLOWED_ORIGINS

    @property
    def netagent_enabled(self) -> bool:
        return self.NETAGENT_ENABLED

    @property
    def netagent_endpoint(self) -> str:
        return self.NETAGENT_ENDPOINT

    def masked_dict(self) -> dict[str, object]:
        """Return configuration dictionary with all credentials safely masked."""
        data = self.model_dump()
        # Redact secrets
        if "APP_SECRET_KEY" in data:
            data["APP_SECRET_KEY"] = "***REDACTED***"
        if "DATABASE_URL" in data and isinstance(data["DATABASE_URL"], str):
            import re

            data["DATABASE_URL"] = re.sub(
                r"://([^:]+):([^@]+)@", r"://\1:***@", data["DATABASE_URL"]
            )
        if "REDIS_URL" in data and isinstance(data["REDIS_URL"], str):
            import re

            data["REDIS_URL"] = re.sub(r"://:([^@]+)@", r"://:***@", data["REDIS_URL"])

        # Populate lowercase aliases for uniform consumer access
        for key in list(data.keys()):
            data[key.lower()] = data[key]

        return data

    def __repr__(self) -> str:
        masked = self.masked_dict()
        return f"Settings({masked})"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Singleton getter for application settings."""
    return Settings()
