"""
Action proposal and policy evaluation schemas.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Optional
import uuid
from pydantic import BaseModel, Field


class PolicyDecision(str, Enum):
    """Possible outcomes of a policy evaluation."""

    ALLOWED = "ALLOWED"
    BLOCKED = "BLOCKED"
    ESCALATED = "ESCALATED"


class AuthorizedTool(str, Enum):
    """Permitted tools that loan agents may propose."""

    APPROVE_LOAN = "approve_loan"
    ESCALATE_FOR_HUMAN_REVIEW = "escalate_for_human_review"
    REJECT_LOAN = "reject_loan"


class LoanProposalRequest(BaseModel):
    """
    Action proposal emitted by an AI agent requesting a tool invocation.
    Agents never invoke tools directly; they submit this proposal to the policy layer.
    """
    user_message: Optional[str] = Field(
        None,
        description="Free‑text supplied by the end‑user; treated as untrusted input.",
    )

    correlation_id: str = Field(
        default_factory=lambda: f"corr_{uuid.uuid4().hex[:12]}",
        description="Unique trace identifier across agent proposal, policy, and execution.",
    )
    agent_id: str = Field(
        ...,
        description="Identifier of the proposing agent (e.g., 'agent_a', 'agent_b_adversary').",
    )
    tool: str = Field(
        ...,
        description="Tool name requested by the agent.",
    )
    loan_id: str = Field(
        ...,
        description="Target loan application identifier.",
    )
    amount: Any = Field(
        ...,
        description="Proposed loan amount in INR (can be float/int, or adversarial malformed input).",
    )
    confidence: Any = Field(
        ...,
        description="Simulated confidence score [0.0 - 1.0] (can be adversarial malformed input).",
    )
    metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Optional auxiliary data (sanitized before storage/logging).",
    )


class PolicyResult(BaseModel):
    """Synchronous outcome of policy rule evaluation."""

    decision: PolicyDecision
    is_allowed: bool
    rule_name: Optional[str] = None
    violation_reason: Optional[str] = None
    evaluated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )


class ToolExecutionResult(BaseModel):
    """Result returned by the tool executor after policy validation and optional execution."""

    correlation_id: str
    agent_id: str
    tool: str
    loan_id: str
    executed: bool
    policy_decision: PolicyDecision
    violation_reason: Optional[str] = None
    result_data: Optional[Dict[str, Any]] = None
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
