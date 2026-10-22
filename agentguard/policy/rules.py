"""
Concrete policy rules for loan approval validation.
Each rule evaluates a proposal against specific security and risk boundaries.
"""

import datetime
from datetime import timezone
import math
from typing import Any, Optional, Tuple
from abc import ABC, abstractmethod
from agentguard.config import Settings
from agentguard.models.actions import AuthorizedTool, LoanProposalRequest, PolicyDecision


class BaseRule(ABC):
    """Abstract base class for all policy rules."""

    rule_name: str

    @abstractmethod
    def evaluate(
        self, proposal: LoanProposalRequest, settings: Settings
    ) -> Optional[Tuple[PolicyDecision, str]]:
        """
        Evaluate proposal against this rule.
        Returns None if rule passes without stopping evaluation.
        Returns (PolicyDecision, reason) if rule triggers a decision/violation.
        """
        pass


class KillSwitchRule(BaseRule):
    """
    Blocks all automated loan approvals when the kill switch is active.
    Human escalation and rejection are permitted to proceed.
    """

    rule_name = "RULE_KILL_SWITCH_ACTIVE"

    def evaluate(
        self, proposal: LoanProposalRequest, settings: Settings
    ) -> Optional[Tuple[PolicyDecision, str]]:
        if settings.kill_switch_active and proposal.tool == AuthorizedTool.APPROVE_LOAN.value:
            return (
                PolicyDecision.BLOCKED,
                "Global kill switch is active. All automated approvals are halted.",
            )
        return None


class AuthorizedToolRule(BaseRule):
    """Rejects unauthorized or unexpected tool calls from the agent."""

    rule_name = "RULE_TOOL_AUTHORIZATION"

    def evaluate(
        self, proposal: LoanProposalRequest, settings: Settings
    ) -> Optional[Tuple[PolicyDecision, str]]:
        authorized_tools = {t.value for t in AuthorizedTool}
        if proposal.tool not in authorized_tools:
            return (
                PolicyDecision.BLOCKED,
                f"Unauthorized tool invocation: '{proposal.tool}' is not a permitted agent action.",
            )
        return None


class InputSanityRule(BaseRule):
    """
    Validates structural integrity and bounds of inputs (amount and confidence).
    Rejects malformed, non-numeric, negative, infinite, or out-of-bounds inputs.
    Treats confidence as a simulated input, verifying it falls in [0.0, 1.0].
    """

    rule_name = "RULE_INPUT_VALIDATION"

    def evaluate(
        self, proposal: LoanProposalRequest, settings: Settings
    ) -> Optional[Tuple[PolicyDecision, str]]:
        # 1. Validate loan amount
        amount_val = proposal.amount
        if amount_val is None or isinstance(amount_val, bool):
            return (
                PolicyDecision.BLOCKED,
                f"Malformed input: loan amount '{amount_val}' must be a positive numeric value.",
            )
        try:
            num_amount = float(amount_val)
            if math.isnan(num_amount) or math.isinf(num_amount) or num_amount <= 0:
                return (
                    PolicyDecision.BLOCKED,
                    f"Malformed input: loan amount '{amount_val}' must be a finite positive number.",
                )
        except (ValueError, TypeError):
            return (
                PolicyDecision.BLOCKED,
                f"Malformed input: loan amount '{amount_val}' cannot be parsed as numeric.",
            )

        # 2. Validate confidence score (simulated input check)
        conf_val = proposal.confidence
        if conf_val is None or isinstance(conf_val, bool):
            return (
                PolicyDecision.BLOCKED,
                f"Malformed input: confidence score '{conf_val}' must be a float between 0.0 and 1.0.",
            )
        try:
            num_conf = float(conf_val)
            if math.isnan(num_conf) or math.isinf(num_conf) or num_conf < 0.0 or num_conf > 1.0:
                return (
                    PolicyDecision.BLOCKED,
                    f"Malformed input: confidence score '{conf_val}' is outside valid range [0.0, 1.0].",
                )
        except (ValueError, TypeError):
            return (
                PolicyDecision.BLOCKED,
                f"Malformed input: confidence score '{conf_val}' cannot be parsed as a float.",
            )

        return None


class MaxLoanAmountRule(BaseRule):
    """
    Enforces the ₹10,000 automated approval ceiling.
    Loans above ₹10,000 must NEVER be auto-approved, regardless of confidence.
    """

    rule_name = "RULE_MAX_AMOUNT_EXCEEDED"

    def evaluate(
        self, proposal: LoanProposalRequest, settings: Settings
    ) -> Optional[Tuple[PolicyDecision, str]]:
        if proposal.tool == AuthorizedTool.APPROVE_LOAN.value:
            amount = float(proposal.amount)
            if amount > settings.max_auto_approve_amount:
                return (
                    PolicyDecision.BLOCKED,
                    f"Automated approval prohibited: loan amount ₹{amount:,.2f} exceeds "
                    f"autonomous limit of ₹{settings.max_auto_approve_amount:,.2f}. "
                    "Loans above ₹10,000 always require human approval.",
                )
        return None


class MinConfidenceRule(BaseRule):
    """
    Enforces minimum simulated confidence score (default 0.80) for automated approval.
    Note: Confidence is treated as a simulated agent input, not a calibrated mathematical probability.
    """

    rule_name = "RULE_LOW_CONFIDENCE"

    def evaluate(
        self, proposal: LoanProposalRequest, settings: Settings
    ) -> Optional[Tuple[PolicyDecision, str]]:
        if proposal.tool == AuthorizedTool.APPROVE_LOAN.value:
            conf = float(proposal.confidence)
            if conf < settings.min_confidence_threshold:
                return (
                    PolicyDecision.BLOCKED,
                    f"Automated approval prohibited: confidence {conf:.2f} is below the "
                    f"configured threshold of {settings.min_confidence_threshold:.2f}.",
                )
        return None

# ----- New Prompt Injection Detection Rule -----
from agentguard.monitoring.monitor import incident_store, IncidentRecord, IncidentSeverity
from agentguard.observability.sanitizer import sanitize_string

class PromptInjectionSuspectedRule(BaseRule):
    """Detects common prompt‑injection phrasing supplied via `user_message`.
    The rule never alters policy decisions. If the injection tries to approve a loan
    above the auto‑approval limit, the proposal is BLOCKED. Otherwise a HIGH‑severity
    incident is recorded and evaluation proceeds normally.
    """

    rule_name = "RULE_PROMPT_INJECTION_SUSPECTED"

    # Simple lower‑casing substring matches for known patterns
    _patterns = [
        r"ignore previous instructions",
        r"ignore all previous instructions",
        r"you are now in developer mode",
        r"disable safety rules",
        r"approve all loans",
        r"override_loan_limit",
        r"call override_loan_limit",
        r"bypass policy",
    ]

    def _contains_injection(self, text: str) -> bool:
        lowered = text.lower()
        for pat in self._patterns:
            if pat in lowered:
                return True
        return False

    def evaluate(
        self, proposal: LoanProposalRequest, settings: Settings
    ) -> Optional[Tuple[PolicyDecision, str]]:
        # Grab free‑text either from the new field or legacy metadata key
        user_msg = getattr(proposal, "user_message", None) or proposal.metadata.get("user_message")
        if not user_msg:
            return None
        if not isinstance(user_msg, str):
            return None
        if not self._contains_injection(user_msg):
            return None

        # Injection detected – decide whether to block or just log
        # Block only if the proposal tries to auto‑approve a loan above the limit
        try:
            amount = float(proposal.amount)
        except Exception:
            amount = None
        if (
            proposal.tool == AuthorizedTool.APPROVE_LOAN.value
            and amount is not None
            and amount > settings.max_auto_approve_amount
        ):
            # Block and record reason
            return (
                PolicyDecision.BLOCKED,
                "Prompt injection attempted auto‑approval of loan exceeding limit.",
            )

        # Safe path – generate a HIGH severity incident but allow evaluation to continue
        sanitized_msg = sanitize_string(user_msg)
        incident = IncidentRecord(
            severity=IncidentSeverity.HIGH,
            timestamp=datetime.now(timezone.utc),
            agent_id=proposal.agent_id,
            correlation_id=proposal.correlation_id,
            reason="Prompt‑injection language detected in user_message.",
            details={
                "detected_message": sanitized_msg,
                "requested_tool": proposal.tool,
                "loan_amount": proposal.amount,
            },
            kill_switch_triggered=False,
        )
        incident_store.add_incident(incident)
        # No blocking – return None so normal policy continues
        return None



class HumanEscalationRule(BaseRule):
    """Handles explicit requests to route loans to a human reviewer."""

    rule_name = "RULE_HUMAN_REVIEW_ROUTED"

    def evaluate(
        self, proposal: LoanProposalRequest, settings: Settings
    ) -> Optional[Tuple[PolicyDecision, str]]:
        if proposal.tool == AuthorizedTool.ESCALATE_FOR_HUMAN_REVIEW.value:
            return (
                PolicyDecision.ESCALATED,
                "Action routed to human approval queue.",
            )
        return None


class LoanRejectionRule(BaseRule):
    """Handles explicit loan rejection recommendations by the agent."""

    rule_name = "RULE_LOAN_REJECTION"

    def evaluate(
        self, proposal: LoanProposalRequest, settings: Settings
    ) -> Optional[Tuple[PolicyDecision, str]]:
        if proposal.tool == AuthorizedTool.REJECT_LOAN.value:
            return (
                PolicyDecision.ALLOWED,
                "Loan rejection recommendation accepted.",
            )
        return None
