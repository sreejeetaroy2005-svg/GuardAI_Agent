"""
Concrete policy rules for loan approval validation.
Each rule evaluates a proposal against specific security and risk boundaries.
"""

from abc import ABC, abstractmethod
import math
from typing import Any, Optional, Tuple
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
