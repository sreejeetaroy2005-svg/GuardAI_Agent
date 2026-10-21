"""
Unit tests for the AgentGuard Policy Enforcement Layer.
Validates each policy rule in complete isolation and verifies the fail-closed guarantee.
"""

from unittest.mock import MagicMock
import pytest

from agentguard.config import Settings
from agentguard.models.actions import (
    AuthorizedTool,
    LoanProposalRequest,
    PolicyDecision,
)
from agentguard.policy.engine import PolicyEngine
from agentguard.policy.rules import (
    AuthorizedToolRule,
    HumanEscalationRule,
    InputSanityRule,
    KillSwitchRule,
    LoanRejectionRule,
    MaxLoanAmountRule,
    MinConfidenceRule,
)


def make_proposal(
    tool: str = AuthorizedTool.APPROVE_LOAN.value,
    amount: float = 8000.0,
    confidence: float = 0.85,
    loan_id: str = "TEST_LOAN_01",
    agent_id: str = "test_agent",
) -> LoanProposalRequest:
    return LoanProposalRequest(
        agent_id=agent_id,
        tool=tool,
        loan_id=loan_id,
        amount=amount,
        confidence=confidence,
    )


# -------------------------------------------------------------
# Unit Tests for Individual Policy Rules
# -------------------------------------------------------------

class TestKillSwitchRule:
    def test_kill_switch_inactive_allows_approval(self, clean_settings: Settings):
        clean_settings.kill_switch_active = False
        rule = KillSwitchRule()
        proposal = make_proposal(tool=AuthorizedTool.APPROVE_LOAN.value)
        outcome = rule.evaluate(proposal, clean_settings)
        assert outcome is None

    def test_kill_switch_active_blocks_approval(self, clean_settings: Settings):
        clean_settings.kill_switch_active = True
        rule = KillSwitchRule()
        proposal = make_proposal(tool=AuthorizedTool.APPROVE_LOAN.value)
        outcome = rule.evaluate(proposal, clean_settings)
        assert outcome is not None
        decision, reason = outcome
        assert decision == PolicyDecision.BLOCKED
        assert "kill switch is active" in reason.lower()

    def test_kill_switch_active_permits_human_escalation(self, clean_settings: Settings):
        clean_settings.kill_switch_active = True
        rule = KillSwitchRule()
        proposal = make_proposal(tool=AuthorizedTool.ESCALATE_FOR_HUMAN_REVIEW.value)
        outcome = rule.evaluate(proposal, clean_settings)
        assert outcome is None  # Does not block escalation


class TestAuthorizedToolRule:
    @pytest.mark.parametrize(
        "valid_tool",
        [
            AuthorizedTool.APPROVE_LOAN.value,
            AuthorizedTool.ESCALATE_FOR_HUMAN_REVIEW.value,
            AuthorizedTool.REJECT_LOAN.value,
        ],
    )
    def test_authorized_tools_pass(self, clean_settings: Settings, valid_tool: str):
        rule = AuthorizedToolRule()
        proposal = make_proposal(tool=valid_tool)
        outcome = rule.evaluate(proposal, clean_settings)
        assert outcome is None

    @pytest.mark.parametrize(
        "unauthorized_tool",
        [
            "override_loan_limit",
            "disburse_funds",
            "admin_bypass",
            "delete_audit_log",
            "execute_raw_sql",
            "",
        ],
    )
    def test_unauthorized_tools_blocked(self, clean_settings: Settings, unauthorized_tool: str):
        rule = AuthorizedToolRule()
        proposal = make_proposal(tool=unauthorized_tool)
        outcome = rule.evaluate(proposal, clean_settings)
        assert outcome is not None
        decision, reason = outcome
        assert decision == PolicyDecision.BLOCKED
        assert "unauthorized tool invocation" in reason.lower()


class TestInputSanityRule:
    def test_valid_inputs_pass(self, clean_settings: Settings):
        rule = InputSanityRule()
        proposal = make_proposal(amount=5000.0, confidence=0.85)
        outcome = rule.evaluate(proposal, clean_settings)
        assert outcome is None

    @pytest.mark.parametrize("invalid_amount", [-500.0, 0.0, "abc", None, float("nan"), float("inf"), True])
    def test_malformed_amounts_blocked(self, clean_settings: Settings, invalid_amount):
        rule = InputSanityRule()
        proposal = make_proposal(amount=invalid_amount, confidence=0.90)
        outcome = rule.evaluate(proposal, clean_settings)
        assert outcome is not None
        decision, reason = outcome
        assert decision == PolicyDecision.BLOCKED
        assert "loan amount" in reason.lower()

    @pytest.mark.parametrize("invalid_conf", [-0.1, 1.05, 99.0, "high", None, float("nan"), float("inf"), False])
    def test_malformed_confidence_blocked(self, clean_settings: Settings, invalid_conf):
        rule = InputSanityRule()
        proposal = make_proposal(amount=5000.0, confidence=invalid_conf)
        outcome = rule.evaluate(proposal, clean_settings)
        assert outcome is not None
        decision, reason = outcome
        assert decision == PolicyDecision.BLOCKED
        assert "confidence score" in reason.lower()


class TestMaxLoanAmountRule:
    def test_amount_within_limit_passes(self, clean_settings: Settings):
        rule = MaxLoanAmountRule()
        proposal = make_proposal(amount=10000.0)
        outcome = rule.evaluate(proposal, clean_settings)
        assert outcome is None

    def test_amount_above_limit_blocked_for_approval(self, clean_settings: Settings):
        rule = MaxLoanAmountRule()
        proposal = make_proposal(amount=10001.0, tool=AuthorizedTool.APPROVE_LOAN.value)
        outcome = rule.evaluate(proposal, clean_settings)
        assert outcome is not None
        decision, reason = outcome
        assert decision == PolicyDecision.BLOCKED
        assert "exceeds autonomous limit" in reason.lower()

    def test_amount_above_limit_not_blocked_for_escalation(self, clean_settings: Settings):
        rule = MaxLoanAmountRule()
        proposal = make_proposal(amount=50000.0, tool=AuthorizedTool.ESCALATE_FOR_HUMAN_REVIEW.value)
        outcome = rule.evaluate(proposal, clean_settings)
        assert outcome is None


class TestMinConfidenceRule:
    def test_confidence_above_threshold_passes(self, clean_settings: Settings):
        rule = MinConfidenceRule()
        proposal = make_proposal(confidence=0.80)
        outcome = rule.evaluate(proposal, clean_settings)
        assert outcome is None

    def test_confidence_below_threshold_blocked(self, clean_settings: Settings):
        rule = MinConfidenceRule()
        proposal = make_proposal(confidence=0.79)
        outcome = rule.evaluate(proposal, clean_settings)
        assert outcome is not None
        decision, reason = outcome
        assert decision == PolicyDecision.BLOCKED
        assert "below the configured threshold" in reason.lower()


class TestHumanEscalationRule:
    def test_escalation_returns_escalated_decision(self, clean_settings: Settings):
        rule = HumanEscalationRule()
        proposal = make_proposal(tool=AuthorizedTool.ESCALATE_FOR_HUMAN_REVIEW.value, amount=25000.0)
        outcome = rule.evaluate(proposal, clean_settings)
        assert outcome is not None
        decision, _ = outcome
        assert decision == PolicyDecision.ESCALATED


class TestLoanRejectionRule:
    def test_rejection_returns_allowed_decision(self, clean_settings: Settings):
        rule = LoanRejectionRule()
        proposal = make_proposal(tool=AuthorizedTool.REJECT_LOAN.value)
        outcome = rule.evaluate(proposal, clean_settings)
        assert outcome is not None
        decision, _ = outcome
        assert decision == PolicyDecision.ALLOWED


# -------------------------------------------------------------
# PolicyEngine Integration & Fail-Closed Guarantee
# -------------------------------------------------------------

class TestPolicyEngineWorkflow:
    def test_legitimate_low_risk_loan_allowed(self, clean_settings: Settings):
        engine = PolicyEngine(settings=clean_settings)
        proposal = make_proposal(amount=9500.0, confidence=0.85)
        result = engine.evaluate(proposal)
        assert result.decision == PolicyDecision.ALLOWED
        assert result.is_allowed is True
        assert result.violation_reason is None

    def test_policy_fails_closed_on_unexpected_exception(self, clean_settings: Settings):
        # Create a faulty rule that raises an unhandled exception
        faulty_rule = MagicMock()
        faulty_rule.evaluate.side_effect = RuntimeError("Fatal crash in rule engine!")

        engine = PolicyEngine(settings=clean_settings, custom_rules=[faulty_rule])
        proposal = make_proposal(amount=5000.0, confidence=0.90)

        result = engine.evaluate(proposal)
        assert result.decision == PolicyDecision.BLOCKED
        assert result.is_allowed is False
        assert result.rule_name == "FAIL_CLOSED_EXCEPTION"
        assert "fail-closed" in result.violation_reason.lower() or "internal policy" in result.violation_reason.lower()
