"""
Controlled Tool Execution Interface for AgentGuard.
Agents cannot directly execute actions; all proposals must route through this executor.
The executor enforces synchronous policy validation BEFORE any action is dispatched.
"""

from datetime import datetime, timezone
import logging
from typing import Any, Callable, Dict, Optional
from agentguard.models.actions import (
    AuthorizedTool,
    LoanProposalRequest,
    PolicyDecision,
    ToolExecutionResult,
)
from agentguard.models.events import EventRecord
from agentguard.observability.logger import audit_logger
from agentguard.observability.sanitizer import sanitize_payload
from agentguard.observability.store import EventStore, event_store
from agentguard.policy.engine import PolicyEngine, policy_engine

logger = logging.getLogger("agentguard.tools")


class ToolExecutor:
    """
    Guarded tool execution framework.
    Guarantees:
    1. Attempted action is recorded prior to evaluation.
    2. Policy validation runs synchronously.
    3. Blocked or escalated actions are never executed.
    4. Execution events and audit logs are recorded.
    5. Post-decision events are passed to the monitoring layer.
    """

    def __init__(
        self,
        engine: Optional[PolicyEngine] = None,
        store: Optional[EventStore] = None,
        post_event_hook: Optional[Callable[[EventRecord], None]] = None,
    ) -> None:
        self.engine = engine or policy_engine
        self.store = store or event_store
        if post_event_hook is not None:
            self.post_event_hook = post_event_hook
        else:
            # Lazy import to avoid circular dependency
            from agentguard.monitoring.monitor import monitor
            self.post_event_hook = monitor.process_event

    def process_proposal(self, proposal: LoanProposalRequest) -> ToolExecutionResult:
        """
        Evaluate an agent's proposal and execute the tool only if authorized by policy.
        """
        # Parse numeric representations safely for event recording
        safe_amount: Optional[float] = None
        safe_conf: Optional[float] = None
        try:
            safe_amount = float(proposal.amount)
        except (ValueError, TypeError):
            pass
        try:
            safe_conf = float(proposal.confidence)
        except (ValueError, TypeError):
            pass

        # 1. Record ATTEMPTED event
        attempt_record = EventRecord(
            correlation_id=proposal.correlation_id,
            agent_id=proposal.agent_id,
            requested_tool=proposal.tool,
            loan_id=proposal.loan_id,
            loan_amount=safe_amount,
            confidence=safe_conf,
            policy_decision=PolicyDecision.BLOCKED,  # Provisional until validated
            execution_status="attempted",
            timestamp=datetime.now(timezone.utc),
            metadata=sanitize_payload(proposal.metadata),
        )
        self.store.record_event(attempt_record)

        audit_logger.info(
            "Agent action proposed",
            extra={
                "correlation_id": proposal.correlation_id,
                "agent_id": proposal.agent_id,
                "requested_tool": proposal.tool,
                "loan_id": proposal.loan_id,
                "loan_amount": safe_amount,
                "confidence": safe_conf,
                "execution_status": "attempted",
            },
        )

        # 2. Synchronous Policy Evaluation
        policy_result = self.engine.evaluate(proposal)

        # 3. Execution Decision Dispatch
        execution_status: str
        is_executed: bool = False
        result_data: Optional[Dict[str, Any]] = None

        if policy_result.decision == PolicyDecision.ALLOWED:
            # Policy cleared: perform simulated tool execution
            result_data = self._simulate_tool_execution(proposal)
            execution_status = "executed"
            is_executed = True
        elif policy_result.decision == PolicyDecision.ESCALATED:
            # Policy sent for human review: DO NOT auto-execute approval
            result_data = {
                "routing": "HUMAN_APPROVAL_QUEUE",
                "loan_id": proposal.loan_id,
                "status": "PENDING_HUMAN_REVIEW",
                "reason": "Loan requires human officer sign-off.",
            }
            execution_status = "escalated"
            is_executed = False
        else:
            # Policy BLOCKED: strict refusal
            execution_status = "blocked"
            is_executed = False

        # 4. Record FINALIZED event
        final_record = EventRecord(
            correlation_id=proposal.correlation_id,
            agent_id=proposal.agent_id,
            requested_tool=proposal.tool,
            loan_id=proposal.loan_id,
            loan_amount=safe_amount,
            confidence=safe_conf,
            policy_decision=policy_result.decision,
            execution_status=execution_status,
            violation_reason=policy_result.violation_reason,
            rule_triggered=policy_result.rule_name,
            timestamp=datetime.now(timezone.utc),
            metadata=sanitize_payload(proposal.metadata),
        )
        self.store.record_event(final_record)

        audit_logger.info(
            f"Policy evaluation finalized: {policy_result.decision.value}",
            extra={
                "correlation_id": proposal.correlation_id,
                "agent_id": proposal.agent_id,
                "requested_tool": proposal.tool,
                "loan_id": proposal.loan_id,
                "loan_amount": safe_amount,
                "confidence": safe_conf,
                "policy_decision": policy_result.decision.value,
                "execution_status": execution_status,
                "violation_reason": policy_result.violation_reason,
                "rule_triggered": policy_result.rule_name,
            },
        )

        # 5. Invoke Monitoring Hook (for alert dispatch / pattern detection)
        if self.post_event_hook:
            try:
                self.post_event_hook(final_record)
            except Exception as exc:
                logger.error("Error in post_event_hook monitoring: %s", exc, exc_info=True)

        return ToolExecutionResult(
            correlation_id=proposal.correlation_id,
            agent_id=proposal.agent_id,
            tool=proposal.tool,
            loan_id=proposal.loan_id,
            executed=is_executed,
            policy_decision=policy_result.decision,
            violation_reason=policy_result.violation_reason,
            result_data=result_data,
        )

    def _simulate_tool_execution(self, proposal: LoanProposalRequest) -> Dict[str, Any]:
        """
        Simulate backend execution of permitted banking tools.
        In a real bank, this would call core banking systems.
        """
        if proposal.tool == AuthorizedTool.APPROVE_LOAN.value:
            return {
                "action": "loan_approval",
                "loan_id": proposal.loan_id,
                "amount": proposal.amount,
                "status": "APPROVED",
                "disbursement_ready": True,
            }
        elif proposal.tool == AuthorizedTool.REJECT_LOAN.value:
            return {
                "action": "loan_rejection",
                "loan_id": proposal.loan_id,
                "status": "REJECTED",
                "notification_queued": True,
            }
        return {"status": "UNKNOWN_ACTION"}


# Global tool executor instance
tool_executor = ToolExecutor()
