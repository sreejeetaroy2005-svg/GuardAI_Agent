"""
Compliant Banking Loan Approval Agent (Agent A).
Adheres strictly to the loan authorization policy:
- Recommends approval for loans <= ₹10,000 when confidence >= threshold.
- Recommends escalation for human review for any loan > ₹10,000, regardless of confidence.
- Recommends rejection or escalation for low confidence loans.
- Never directly executes actions.
"""

from typing import Any, Dict, Optional
from agentguard.agents.base import BaseLoanAgent
from agentguard.config import get_settings
from agentguard.models.actions import AuthorizedTool, LoanProposalRequest


class AgentA(BaseLoanAgent):
    """
    Standard policy-compliant loan recommendation agent.
    """

    def __init__(self, agent_id: str = "agent_a") -> None:
        super().__init__(agent_id=agent_id)

    def evaluate_loan(
        self,
        loan_id: str,
        amount: Any,
        confidence: Any,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> LoanProposalRequest:
        """
        Evaluate loan parameters and return an appropriate proposal according to bank guidelines.
        """
        settings = get_settings()

        try:
            num_amount = float(amount)
            num_conf = float(confidence)
        except (ValueError, TypeError):
            # If input is unparseable, Agent A conservatively requests human review
            return self.create_proposal(
                tool=AuthorizedTool.ESCALATE_FOR_HUMAN_REVIEW.value,
                loan_id=loan_id,
                amount=amount,
                confidence=confidence,
                metadata={"reason": "Unparseable input encountered", **(metadata or {})},
            )

        # 1. Any loan above ₹10,000 MUST be routed to human review, regardless of confidence
        if num_amount > settings.max_auto_approve_amount:
            return self.create_proposal(
                tool=AuthorizedTool.ESCALATE_FOR_HUMAN_REVIEW.value,
                loan_id=loan_id,
                amount=num_amount,
                confidence=num_conf,
                metadata={"reason": "Amount exceeds autonomous threshold", **(metadata or {})},
            )

        # 2. Loan <= ₹10,000 and confidence >= threshold: propose approval
        if num_conf >= settings.min_confidence_threshold:
            return self.create_proposal(
                tool=AuthorizedTool.APPROVE_LOAN.value,
                loan_id=loan_id,
                amount=num_amount,
                confidence=num_conf,
                metadata={"reason": "Low risk, high confidence", **(metadata or {})},
            )

        # 3. Loan <= ₹10,000 but confidence < threshold: propose rejection
        return self.create_proposal(
            tool=AuthorizedTool.REJECT_LOAN.value,
            loan_id=loan_id,
            amount=num_amount,
            confidence=num_conf,
            metadata={"reason": "Confidence below autonomous approval threshold", **(metadata or {})},
        )


# Global instance of Agent A
agent_a = AgentA()
