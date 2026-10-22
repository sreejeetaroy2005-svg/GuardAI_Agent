"""
Synchronous, independent Policy Enforcement Engine for AgentGuard.
Evaluates agent proposals against security rules and fails closed on any anomaly or internal error.
"""

import logging
from typing import List, Optional
from agentguard.config import Settings, get_settings
from agentguard.models.actions import AuthorizedTool, LoanProposalRequest, PolicyDecision, PolicyResult
from agentguard.policy.rules import (
    AuthorizedToolRule,
    BaseRule,
    HumanEscalationRule,
    InputSanityRule,
    KillSwitchRule,
    LoanRejectionRule,
    MaxLoanAmountRule,
    MinConfidenceRule,
    PromptInjectionSuspectedRule,
)

logger = logging.getLogger("agentguard.policy")


class PolicyEngine:
    """
    Independent policy evaluation engine.
    Ensures zero unauthorized executions occur by validating every proposal
    against immutable security constraints BEFORE any tool execution can begin.
    """

    def __init__(
        self,
        settings: Optional[Settings] = None,
        custom_rules: Optional[List[BaseRule]] = None,
    ) -> None:
        self.settings = settings or get_settings()
        # Default ordered rule pipeline
        self.rules: List[BaseRule] = custom_rules or [
            KillSwitchRule(),
            AuthorizedToolRule(),
            InputSanityRule(),
            MaxLoanAmountRule(),
            MinConfidenceRule(),
            PromptInjectionSuspectedRule(),
            HumanEscalationRule(),
            LoanRejectionRule(),
        ]

    def evaluate(self, proposal: LoanProposalRequest) -> PolicyResult:
        """
        Synchronously evaluate a proposal against all policy rules.
        Fails closed on any unexpected exception.
        """
        try:
            for rule in self.rules:
                outcome = rule.evaluate(proposal, self.settings)
                if outcome is not None:
                    decision, reason = outcome
                    is_allowed = decision == PolicyDecision.ALLOWED
                    return PolicyResult(
                        decision=decision,
                        is_allowed=is_allowed,
                        rule_name=rule.rule_name,
                        violation_reason=reason if decision == PolicyDecision.BLOCKED else None,
                    )

            # If tool is approve_loan and passed all checks:
            if proposal.tool == AuthorizedTool.APPROVE_LOAN.value:
                return PolicyResult(
                    decision=PolicyDecision.ALLOWED,
                    is_allowed=True,
                    rule_name="POLICY_AUTO_APPROVAL_PERMITTED",
                    violation_reason=None,
                )

            # Fallback fail-closed if tool was unhandled
            return PolicyResult(
                decision=PolicyDecision.BLOCKED,
                is_allowed=False,
                rule_name="UNHANDLED_TOOL_ACTION",
                violation_reason=f"Action '{proposal.tool}' not explicitly permitted by policy.",
            )

        except Exception as exc:
            # Absolute fail-closed guarantee
            logger.error(
                "Policy evaluation encountered unexpected exception; failing closed: %s",
                exc,
                exc_info=True,
            )
            return PolicyResult(
                decision=PolicyDecision.BLOCKED,
                is_allowed=False,
                rule_name="FAIL_CLOSED_EXCEPTION",
                violation_reason=f"Internal policy evaluation failure: {str(exc)}",
            )


# Default global policy engine
policy_engine = PolicyEngine()
