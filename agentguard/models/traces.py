"""
Trace and evaluation models for AgentGuard observability.

Each agent run produces exactly one AgentTrace that captures the full
lifecycle: input hash, LLM call metadata, tool proposal, policy decision,
tool execution result, latency, token usage, cost estimate, and an
evaluation result.

Architectural note:
- EvaluationResult is audit/evaluation metadata only.
- It MUST NOT retroactively change a policy decision.
- It MUST NOT be used as a gate on execution.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# ToolProposal
# ---------------------------------------------------------------------------

class ToolProposal(BaseModel):
    """
    Structured output from the LLM Banking Agent.

    The agent proposes exactly one tool action but is architecturally
    prohibited from executing it.  Only the ControlledToolExecutor may
    invoke a banking tool, and only after a PolicyResult of ALLOWED.
    """

    proposal_id: str = Field(
        default_factory=lambda: f"prop_{uuid.uuid4().hex[:16]}",
        description="Globally unique, immutable proposal identifier.",
    )
    agent_id: str = Field(
        ...,
        description="Identifier of the proposing LLM agent.",
    )
    tool: str = Field(
        ...,
        description=(
            "Proposed banking tool: "
            "'approve_loan' | 'reject_loan' | 'escalate_for_human_review'"
        ),
    )
    loan_id: str = Field(..., description="Target loan application identifier.")
    amount: float = Field(..., description="Loan amount in INR.")
    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Agent confidence score in [0.0, 1.0].",
    )
    reasoning_summary: str = Field(
        ...,
        description="Human-readable explanation of the agent's reasoning.",
    )
    evidence: List[str] = Field(
        default_factory=list,
        description="Ordered list of evidence items supporting the decision.",
    )
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
    )

    def to_loan_proposal_request(self) -> "LoanProposalRequest":
        """
        Convert this ToolProposal into a LoanProposalRequest suitable for
        submission to the ControlledToolExecutor / PolicyEngine.

        The correlation_id is derived from the proposal_id so the two objects
        are traceable across the audit log.
        """
        from agentguard.models.actions import LoanProposalRequest

        return LoanProposalRequest(
            correlation_id=self.proposal_id,
            agent_id=self.agent_id,
            tool=self.tool,
            loan_id=self.loan_id,
            amount=self.amount,
            confidence=self.confidence,
            metadata={
                "reasoning_summary": self.reasoning_summary,
                "evidence": self.evidence,
                "source": "llm_banking_agent",
            },
        )


# ---------------------------------------------------------------------------
# EvaluationResult
# ---------------------------------------------------------------------------

class EvaluationResult(BaseModel):
    """
    Post-hoc evaluation metadata for a completed agent trace.

    IMPORTANT: This is evaluation metadata only.  It MUST NOT change the
    policy decision after the fact.
    """

    policy_compliance: Literal["compliant", "non_compliant"] = Field(
        ...,
        description=(
            "'compliant' if the agent proposed a tool that matched the policy outcome; "
            "'non_compliant' if the agent attempted a blocked action."
        ),
    )
    injection_detected: bool = Field(
        ...,
        description="True if prompt-injection was detected in any user-controlled field.",
    )
    pii_leakage_detected: bool = Field(
        default=False,
        description="True if PII was found in any sanitized log/event field.",
    )
    tool_choice_valid: bool = Field(
        ...,
        description="True if the agent proposed an authorized tool from the permitted set.",
    )
    confidence_justified: Optional[bool] = Field(
        default=None,
        description=(
            "True if the agent's confidence score is consistent with the policy outcome; "
            "None if indeterminate."
        ),
    )


# ---------------------------------------------------------------------------
# AgentTrace
# ---------------------------------------------------------------------------

class AgentTrace(BaseModel):
    """
    Structured trace record for a single end-to-end agent invocation.

    Every LLM call, tool proposal, policy decision, and tool execution is
    captured as a child event under the same trace_id.
    """

    trace_id: str = Field(
        default_factory=lambda: f"trace_{uuid.uuid4().hex}",
        description="Globally unique trace identifier.",
    )
    conversation_id: Optional[str] = Field(
        default=None,
        description="Optional conversation or session identifier.",
    )
    agent_id: str = Field(..., description="Identifier of the agent that ran.")
    model_name: str = Field(
        default="mock",
        description="Name of the model used (e.g., 'mock', 'gpt-4o-mini').",
    )
    input_text_hash: Optional[str] = Field(
        default=None,
        description="SHA-256 hex digest of the sanitized input text.",
    )
    llm_call_metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Raw metadata from the LLM call (sanitized).",
    )
    tool_proposal: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Serialised ToolProposal (sanitized).",
    )
    policy_decision: Optional[str] = Field(
        default=None,
        description="ALLOWED | BLOCKED | ESCALATED",
    )
    tool_execution_result: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Serialised ToolExecutionResult (sanitized).",
    )
    latency_ms: Optional[float] = Field(
        default=None,
        description="Total wall-clock time for the agent run in milliseconds.",
    )
    input_tokens: Optional[int] = Field(
        default=None,
        description="Estimated number of input tokens consumed.",
    )
    output_tokens: Optional[int] = Field(
        default=None,
        description="Estimated number of output tokens generated.",
    )
    estimated_cost: Optional[float] = Field(
        default=None,
        description="Estimated USD cost for the LLM call.",
    )
    evaluation_result: Optional[EvaluationResult] = Field(
        default=None,
        description="Post-hoc evaluation metadata (does not alter policy decision).",
    )
    injection_scan_results: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Serialised InjectionScanResult records from UntrustedInputGuard.",
    )
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
    )
