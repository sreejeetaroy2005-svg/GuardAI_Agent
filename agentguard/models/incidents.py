"""
Incident and alert data models for monitoring.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict
import uuid
from pydantic import BaseModel, Field


class IncidentSeverity(str, Enum):
    """Severity classification for policy violations and suspicious agent activities."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class IncidentRecord(BaseModel):
    """
    Incident generated when a policy violation or suspicious pattern is detected.
    Note: Detection occurs asynchronously or synchronously post-action, but
    incident creation does not alter execution outcome (prevention occurs strictly before execution).
    """

    incident_id: str = Field(
        default_factory=lambda: f"inc_{uuid.uuid4().hex[:12]}",
        description="Unique identifier for the incident.",
    )
    severity: IncidentSeverity = Field(
        ...,
        description="Severity classification of the incident.",
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp of the incident creation.",
    )
    agent_id: str = Field(
        ...,
        description="Agent responsible for the anomalous action.",
    )
    correlation_id: str = Field(
        ...,
        description="Correlation ID of the originating event.",
    )
    reason: str = Field(
        ...,
        description="Root cause or violation rationale.",
    )
    details: Dict[str, Any] = Field(
        default_factory=dict,
        description="Supporting event attributes (sanitized).",
    )
    slack_notification_sent: bool = Field(
        default=False,
        description="Whether a Slack webhook notification was successfully dispatched.",
    )
    kill_switch_triggered: bool = Field(
        default=False,
        description="Whether this incident triggered the automated kill switch.",
    )
