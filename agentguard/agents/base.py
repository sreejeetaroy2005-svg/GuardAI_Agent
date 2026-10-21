"""
Base class for simulated loan approval agents.
Architectural constraint: Agents NEVER directly execute actions;
they only construct and submit action proposals to the controlled tool executor.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, Optional
import uuid
from agentguard.models.actions import LoanProposalRequest, ToolExecutionResult
from agentguard.tools.executor import ToolExecutor, tool_executor


class BaseLoanAgent(ABC):
    """
    Abstract base class for all simulated loan agents.
    Provides standard proposal generation and submission mechanisms.
    """

    def __init__(self, agent_id: str) -> None:
        self.agent_id = agent_id

    def create_proposal(
        self,
        tool: str,
        loan_id: str,
        amount: Any,
        confidence: Any,
        metadata: Optional[Dict[str, Any]] = None,
        correlation_id: Optional[str] = None,
    ) -> LoanProposalRequest:
        """
        Construct a proposal without executing it.
        """
        cid = correlation_id or f"corr_{uuid.uuid4().hex[:12]}"
        return LoanProposalRequest(
            correlation_id=cid,
            agent_id=self.agent_id,
            tool=tool,
            loan_id=loan_id,
            amount=amount,
            confidence=confidence,
            metadata=metadata or {},
        )

    def submit_proposal(
        self,
        proposal: LoanProposalRequest,
        executor: Optional[ToolExecutor] = None,
    ) -> ToolExecutionResult:
        """
        Submit a proposal to the controlled ToolExecutor.
        The executor validates policy before executing.
        """
        target_executor = executor or tool_executor
        return target_executor.process_proposal(proposal)

    @abstractmethod
    def evaluate_loan(
        self,
        loan_id: str,
        amount: Any,
        confidence: Any,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> LoanProposalRequest:
        """
        Formulate a proposed action for a given loan scenario.
        """
        pass
