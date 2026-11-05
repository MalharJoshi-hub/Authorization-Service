"""Configuration Management Module for Auth-as-a-Service.

Loads settings from environment variables and provides centralized, validated
application configuration using Pydantic Settings.
"""

from functools import lru_cache
from typing import List, Union
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Central application settings and environment configuration."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Application Information
    APP_NAME: str = "Auth-as-a-Service"
    APP_VERSION: str = "1.0.0"
    APP_ENV: str = "development"
    APP_DEBUG: bool = True
    APP_HOST: str = "0.0.0.0"
    APP_PORT: int = 8000
    API_PREFIX: str = "/api/v1"
    SECRET_KEY: str = "super-secret-system-key-change-in-production-min-32-chars"

    # Security & Cryptographic Settings
    JWT_SECRET_KEY: str = "super-secret-jwt-signing-key-for-auth-as-a-service-token-engine-2026"
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 14
    PASSWORD_BCRYPT_ROUNDS: int = 12
    ENFORCE_PASSWORD_COMPLEXITY: bool = True

    # Database Configuration
    DATABASE_URL: str = "sqlite+aiosqlite:///./auth_service.db"
    DB_POOL_SIZE: int = 20
    DB_MAX_OVERFLOW: int = 10
    DB_POOL_TIMEOUT: int = 30
    DB_ECHO: bool = False

    # Redis Configuration
    REDIS_URL: str = "redis://localhost:6379/0"
    REDIS_POOL_SIZE: int = 20
    REDIS_TIMEOUT_SECONDS: float = 2.0
    REDIS_KEY_PREFIX: str = "aas:"

    # Rate Limiting Engine
    RATE_LIMIT_ENABLED: bool = True
    RATE_LIMIT_LOGIN_PER_MINUTE: int = 5
    RATE_LIMIT_REGISTER_PER_MINUTE: int = 3
    RATE_LIMIT_DEFAULT_PER_MINUTE: int = 100

    # Account Lockout & Brute Force Defense
    LOCKOUT_MAX_ATTEMPTS: int = 5
    LOCKOUT_DURATION_MINUTES: int = 15

    # Multi-Tenancy
    DEFAULT_TENANT_ID: str = "00000000-0000-0000-0000-000000000001"
    DEFAULT_TENANT_NAME: str = "Default Organization"
    MULTI_TENANCY_ENABLED: bool = True

    # Social OAuth2 Credentials
    GOOGLE_CLIENT_ID: str = "mock-google-client-id"
    GOOGLE_CLIENT_SECRET: str = "mock-google-client-secret"
    GOOGLE_REDIRECT_URI: str = "http://localhost:8000/api/v1/oauth/google/callback"

    GITHUB_CLIENT_ID: str = "mock-github-client-id"
    GITHUB_CLIENT_SECRET: str = "mock-github-client-secret"
    GITHUB_REDIRECT_URI: str = "http://localhost:8000/api/v1/oauth/github/callback"

    # Email & Verification Settings
    SMTP_HOST: str = "smtp.mailtrap.io"
    SMTP_PORT: int = 2525
    SMTP_USER: str = "test-user"
    SMTP_PASSWORD: str = "test-password"
    EMAIL_FROM: str = "noreply@auth-service.io"
    EMAIL_VERIFICATION_TTL_HOURS: int = 24
    PASSWORD_RESET_TTL_HOURS: int = 1

    # CORS Settings
    CORS_ORIGINS: Union[List[str], str] = ["*"]

    @field_validator("CORS_ORIGINS", mode="before")
    @classmethod
    def assemble_cors_origins(cls, v: Union[str, List[str]]) -> List[str]:
        """Parse CORS origins whether string or list."""
        if isinstance(v, str):
            if v.startswith("[") and v.endswith("]"):
                import json
                try:
                    return json.loads(v)
                except Exception:
                    pass
            return [i.strip() for i in v.split(",") if i.strip()]
        return v

    @property
    def is_production(self) -> bool:
        """Check if running in production mode."""
        return self.APP_ENV.lower() in ("production", "prod")

    @property
    def is_sqlite(self) -> bool:
        """Check if using SQLite database."""
        return "sqlite" in self.DATABASE_URL.lower()


@lru_cache()
def get_settings() -> Settings:
    """Retrieve cached global settings instance."""
    return Settings()


settings = get_settings()

