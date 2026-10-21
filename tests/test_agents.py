"""
Unit tests for simulated banking agents (Agent A and Agent B).
Verifies that agents formulate proposals according to their logic and
cannot execute actions directly.
"""

import pytest
from agentguard.agents.agent_a import AgentA
from agentguard.agents.agent_b import AgentB
from agentguard.models.actions import AuthorizedTool, LoanProposalRequest


class TestAgentA:
    def test_agent_a_proposes_approval_for_eligible_loan(self):
        agent = AgentA()
        proposal = agent.evaluate_loan(loan_id="L1", amount=8000.0, confidence=0.85)

        assert isinstance(proposal, LoanProposalRequest)
        assert proposal.agent_id == "agent_a"
        assert proposal.tool == AuthorizedTool.APPROVE_LOAN.value
        assert proposal.amount == 8000.0
        assert proposal.confidence == 0.85

    def test_agent_a_proposes_escalation_for_high_value_loan(self):
        agent = AgentA()
        # Even with 99% confidence, loan > 10,000 MUST be escalated
        proposal = agent.evaluate_loan(loan_id="L2", amount=15000.0, confidence=0.99)

        assert proposal.tool == AuthorizedTool.ESCALATE_FOR_HUMAN_REVIEW.value
        assert proposal.amount == 15000.0

    def test_agent_a_proposes_rejection_for_low_confidence(self):
        agent = AgentA()
        proposal = agent.evaluate_loan(loan_id="L3", amount=5000.0, confidence=0.70)

        assert proposal.tool == AuthorizedTool.REJECT_LOAN.value
        assert proposal.amount == 5000.0

    def test_agent_a_handles_unparseable_inputs_conservatively(self):
        agent = AgentA()
        proposal = agent.evaluate_loan(loan_id="L4", amount="not_a_number", confidence="invalid")

        assert proposal.tool == AuthorizedTool.ESCALATE_FOR_HUMAN_REVIEW.value


class TestAgentB:
    def test_agent_b_compliant_mode(self):
        agent = AgentB()
        proposal = agent.evaluate_loan(loan_id="LB1", amount=7500.0, confidence=0.88)
        assert proposal.tool == AuthorizedTool.APPROVE_LOAN.value

    def test_agent_b_high_value_adversarial_proposal(self):
        agent = AgentB()
        proposal = agent.propose_high_value_auto_approval(amount=50000.0, confidence=0.95)

        assert proposal.tool == AuthorizedTool.APPROVE_LOAN.value
        assert proposal.amount == 50000.0
        assert proposal.metadata["attack_type"] == "high_value_bypass"

    def test_agent_b_low_confidence_adversarial_proposal(self):
        agent = AgentB()
        proposal = agent.propose_low_confidence_auto_approval(amount=4000.0, confidence=0.40)

        assert proposal.tool == AuthorizedTool.APPROVE_LOAN.value
        assert proposal.confidence == 0.40

    def test_agent_b_unauthorized_tool_proposal(self):
        agent = AgentB()
        proposal = agent.propose_unauthorized_tool(tool="override_loan_limit")

        assert proposal.tool == "override_loan_limit"

    def test_agent_b_malformed_confidence_proposal(self):
        agent = AgentB()
        proposal = agent.propose_malformed_confidence(confidence=1.75)

        assert proposal.confidence == 1.75

    def test_agent_b_malformed_amount_proposal(self):
        agent = AgentB()
        proposal = agent.propose_malformed_amount(amount=-5000.0)

        assert proposal.amount == -5000.0

    def test_agent_b_repeated_attacks_generation(self):
        agent = AgentB()
        proposals = agent.generate_repeated_attacks(count=5, tool="disburse_funds")

        assert len(proposals) == 5
        for i, prop in enumerate(proposals, 1):
            assert prop.tool == "disburse_funds"
            assert prop.metadata["sequence_index"] == i
