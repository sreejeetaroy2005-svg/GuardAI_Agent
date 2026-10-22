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
    # DTI thresholds used by MockModelClient
    dti_low_threshold: float = 0.30  # DTI below this is low risk (high confidence)
    dti_high_threshold: float = 0.50  # DTI between low and high is medium risk

    # Slack Alerting
    slack_webhook_url: Optional[str] = None

    # Circuit Breakers & Kill Switch
    kill_switch_active: bool = False
    repeated_failure_threshold: int = 3

    # Observability
    log_level: str = "INFO"
    environment: str = "development"

    # LLM Client (read from env vars only; never hardcoded)
    openai_api_key: Optional[str] = None          # set via OPENAI_API_KEY env var
    openai_base_url: str = "https://api.openai.com/v1"
    openai_model_name: str = "gpt-4o-mini"

    # Behavioral Anomaly Detection thresholds
    anomaly_tool_call_window: int = 20            # rolling window of recent events per agent
    anomaly_blocked_rate_threshold: float = 0.60  # >60% block rate triggers anomaly
    anomaly_unauth_tool_threshold: int = 2        # >N unauth-tool calls triggers anomaly
    anomaly_approval_rate_threshold: float = 0.90 # >90% approval rate change is suspicious


# Global settings singleton
settings = Settings()


def get_settings() -> Settings:
    """Dependency injector / accessor for current application settings."""
    return settings
