"""
Observability event models for recording attempted and executed agent actions.
"""

from datetime import datetime, timezone
from typing import Any, Dict, Optional
import uuid
from pydantic import BaseModel, Field
from agentguard.models.actions import PolicyDecision


class EventRecord(BaseModel):
    """
    Structured event representation for the observability audit log.
    Captures both attempted tool proposals and finalized execution states.
    """

    event_id: str = Field(
        default_factory=lambda: f"evt_{uuid.uuid4().hex[:12]}",
        description="Unique event record ID.",
    )
    correlation_id: str = Field(
        ...,
        description="Correlation ID tying together agent proposal, policy decision, and tool execution.",
    )
    agent_id: str = Field(
        ...,
        description="Identifier of the proposing agent.",
    )
    requested_tool: str = Field(
        ...,
        description="Tool name requested by the agent.",
    )
    loan_id: Optional[str] = Field(
        default=None,
        description="Identifier of the loan.",
    )
    loan_amount: Optional[float] = Field(
        default=None,
        description="Loan amount in INR (if valid numeric), or None if malformed.",
    )
    confidence: Optional[float] = Field(
        default=None,
        description="Simulated confidence score (if valid numeric), or None if malformed.",
    )
    policy_decision: PolicyDecision = Field(
        ...,
        description="Synchronous policy evaluation outcome: ALLOWED, BLOCKED, or ESCALATED.",
    )
    execution_status: str = Field(
        ...,
        description="Current state: 'attempted', 'executed', 'blocked', 'escalated', or 'failed'.",
    )
    violation_reason: Optional[str] = Field(
        default=None,
        description="Detailed explanation if policy violation occurred.",
    )
    rule_triggered: Optional[str] = Field(
        default=None,
        description="Name of the specific policy rule triggered.",
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp of the recorded event.",
    )
    metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Sanitized contextual attributes (strictly PII and secret-free).",
    )
