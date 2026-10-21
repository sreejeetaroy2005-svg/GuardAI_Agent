"""
Configuration management for AgentGuard using Pydantic Settings.
Loads configuration from environment variables and provides runtime state overrides.
"""

from typing import Optional
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings with environment variable support."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # Policy Thresholds
    max_auto_approve_amount: float = 10000.0
    min_confidence_threshold: float = 0.80

    # Slack Alerting
    slack_webhook_url: Optional[str] = None

    # Circuit Breakers & Kill Switch
    kill_switch_active: bool = False
    repeated_failure_threshold: int = 3

    # Observability
    log_level: str = "INFO"
    environment: str = "development"


# Global settings singleton
settings = Settings()


def get_settings() -> Settings:
    """Dependency injector / accessor for current application settings."""
    return settings
