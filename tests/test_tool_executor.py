"""
Unit tests for the controlled ToolExecutor.
Verifies that:
- Every action is logged as 'attempted' prior to evaluation.
- Blocked actions are never executed.
- Escalated actions are placed in a human queue, never executed as automated approvals.
- Allowed actions are executed.
- Fail-closed security boundaries are maintained.
"""

import pytest
from agentguard.config import Settings
from agentguard.models.actions import (
    AuthorizedTool,
    LoanProposalRequest,
    PolicyDecision,
)
from agentguard.observability.store import EventStore
from agentguard.policy.engine import PolicyEngine
from agentguard.tools.executor import ToolExecutor


class TestToolExecutor:
    def test_executor_records_attempt_and_blocks_unauthorized_tool(self, clean_settings: Settings):
        store = EventStore()
        engine = PolicyEngine(settings=clean_settings)
        executor = ToolExecutor(engine=engine, store=store, post_event_hook=lambda e: None)

        proposal = LoanProposalRequest(
            agent_id="adversary",
            tool="disburse_funds",
            loan_id="L_UNAUTH",
            amount=5000.0,
            confidence=0.90,
        )

        result = executor.process_proposal(proposal)

        # Execution blocked
        assert result.executed is False
        assert result.policy_decision == PolicyDecision.BLOCKED
        assert result.violation_reason is not None

        # Verify event store records
        events = store.get_events_by_correlation_id(proposal.correlation_id)
        assert len(events) == 2
        attempt_event, final_event = events[0], events[1]

        assert attempt_event.execution_status == "attempted"
        assert final_event.execution_status == "blocked"
        assert final_event.policy_decision == PolicyDecision.BLOCKED

    def test_executor_blocks_high_value_approval_attempt(self, clean_settings: Settings):
        store = EventStore()
        engine = PolicyEngine(settings=clean_settings)
        executor = ToolExecutor(engine=engine, store=store, post_event_hook=lambda e: None)

        proposal = LoanProposalRequest(
            agent_id="adversary",
            tool=AuthorizedTool.APPROVE_LOAN.value,
            loan_id="L_HIGH_VAL",
            amount=50000.0,
            confidence=0.99,
        )

        result = executor.process_proposal(proposal)

        assert result.executed is False
        assert result.policy_decision == PolicyDecision.BLOCKED
        assert "exceeds autonomous limit" in result.violation_reason.lower()

    def test_executor_handles_human_escalation_without_auto_approving(self, clean_settings: Settings):
        store = EventStore()
        engine = PolicyEngine(settings=clean_settings)
        executor = ToolExecutor(engine=engine, store=store, post_event_hook=lambda e: None)

        proposal = LoanProposalRequest(
            agent_id="agent_a",
            tool=AuthorizedTool.ESCALATE_FOR_HUMAN_REVIEW.value,
            loan_id="L_ESCALATE",
            amount=25000.0,
            confidence=0.95,
        )

        result = executor.process_proposal(proposal)

        # Escalation does not automatically execute approval
        assert result.executed is False
        assert result.policy_decision == PolicyDecision.ESCALATED
        assert result.result_data["routing"] == "HUMAN_APPROVAL_QUEUE"
        assert result.result_data["status"] == "PENDING_HUMAN_REVIEW"

        events = store.get_events_by_correlation_id(proposal.correlation_id)
        assert events[-1].execution_status == "escalated"

    def test_executor_executes_eligible_approval(self, clean_settings: Settings):
        store = EventStore()
        engine = PolicyEngine(settings=clean_settings)
        executor = ToolExecutor(engine=engine, store=store, post_event_hook=lambda e: None)

        proposal = LoanProposalRequest(
            agent_id="agent_a",
            tool=AuthorizedTool.APPROVE_LOAN.value,
            loan_id="L_PERMITTED",
            amount=8000.0,
            confidence=0.88,
        )

        result = executor.process_proposal(proposal)

        assert result.executed is True
        assert result.policy_decision == PolicyDecision.ALLOWED
        assert result.result_data["status"] == "APPROVED"
        assert result.result_data["disbursement_ready"] is True

        events = store.get_events_by_correlation_id(proposal.correlation_id)
        assert events[-1].execution_status == "executed"
