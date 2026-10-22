"""
Pytest configuration and shared fixtures for AgentGuard test suite.
Ensures clean test isolation, mocks external network calls (e.g., Slack),
and provides FastAPI TestClient instances.
"""

from typing import Generator
from fastapi.testclient import TestClient
import pytest

from agentguard.api.app import app
from agentguard.config import Settings, get_settings
from agentguard.monitoring.monitor import incident_store, monitor
from agentguard.observability.store import event_store
from agentguard.observability.trace_store import trace_store
from agentguard.review.human_review import human_review_store


@pytest.fixture(autouse=True)
def reset_stores_and_settings() -> Generator[None, None, None]:
    """
    Automatically reset all in-memory event stores, incident stores,
    trace stores, human review store, and kill switch settings before
    and after each test.
    """
    settings = get_settings()
    settings.kill_switch_active = False
    settings.max_auto_approve_amount = 10000.0
    settings.min_confidence_threshold = 0.80
    settings.repeated_failure_threshold = 3
    settings.slack_webhook_url = None

    event_store.clear()
    incident_store.clear()
    trace_store.clear()
    human_review_store.clear()

    yield

    event_store.clear()
    incident_store.clear()
    trace_store.clear()
    human_review_store.clear()
    settings.kill_switch_active = False


@pytest.fixture
def client() -> TestClient:
    """FastAPI TestClient fixture."""
    return TestClient(app)


@pytest.fixture
def clean_settings() -> Settings:
    """Isolated Settings instance for unit tests."""
    return Settings(
        max_auto_approve_amount=10000.0,
        min_confidence_threshold=0.80,
        kill_switch_active=False,
        repeated_failure_threshold=3,
        slack_webhook_url=None,
    )
