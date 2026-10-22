"""
Controlled Tool Execution Interface for AgentGuard.
Agents cannot directly execute actions; all proposals must route through this executor.
The executor enforces synchronous policy validation BEFORE any action is dispatched.
"""

import time
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
from agentguard.models.traces import AgentTrace, EvaluationResult, ToolProposal
from agentguard.observability.logger import audit_logger
from agentguard.observability.sanitizer import sanitize_payload
from agentguard.observability.store import EventStore, event_store
from agentguard.observability.trace_store import TraceStore, trace_store
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
    6. ESCALATED proposals create a HumanReviewTask.
    7. Every run produces an AgentTrace stored in TraceStore.
    """

    def __init__(
        self,
        engine: Optional[PolicyEngine] = None,
        store: Optional[EventStore] = None,
        post_event_hook: Optional[Callable[[EventRecord], None]] = None,
        review_store: Optional[Any] = None,  # HumanReviewStore (lazy to avoid circular)
        traces: Optional[TraceStore] = None,
    ) -> None:
        self.engine = engine or policy_engine
        self.store = store or event_store
        self.traces = traces or trace_store
        self._review_store = review_store  # None means "use global lazily"

        if post_event_hook is not None:
            self.post_event_hook = post_event_hook
        else:
            # Lazy import to avoid circular dependency
            from agentguard.monitoring.monitor import monitor
            self.post_event_hook = monitor.process_event

    # ------------------------------------------------------------------
    # Human review store accessor (lazy import to avoid circular dep)
    # ------------------------------------------------------------------

    @property
    def review_store(self):
        if self._review_store is not None:
            return self._review_store
        from agentguard.review.human_review import human_review_store
        return human_review_store

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    def process_proposal(self, proposal: LoanProposalRequest) -> ToolExecutionResult:
        """
        Evaluate an agent's proposal and execute the tool only if authorized by policy.
        """
        run_start = time.monotonic()

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

            # Create durable HumanReviewTask
            try:
                task = self.review_store.create_task(
                    proposal_id=proposal.correlation_id,
                    agent_id=proposal.agent_id,
                    loan_id=proposal.loan_id,
                    amount=safe_amount or 0.0,
                    confidence=safe_conf or 0.0,
                    reason=policy_result.violation_reason or "Escalated for human review.",
                )
                result_data["human_review_task_id"] = task.task_id
                audit_logger.info(
                    "Human review task created",
                    extra={
                        "task_id": task.task_id,
                        "correlation_id": proposal.correlation_id,
                        "loan_id": proposal.loan_id,
                    },
                )
            except Exception as exc:
                logger.error("Failed to create human review task: %s", exc, exc_info=True)

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

        # Build result
        exec_result = ToolExecutionResult(
            correlation_id=proposal.correlation_id,
            agent_id=proposal.agent_id,
            tool=proposal.tool,
            loan_id=proposal.loan_id,
            executed=is_executed,
            policy_decision=policy_result.decision,
            violation_reason=policy_result.violation_reason,
            result_data=result_data,
        )

        # 6. Record AgentTrace (best-effort; never raises)
        elapsed_ms = (time.monotonic() - run_start) * 1000.0
        self._record_trace(proposal, exec_result, elapsed_ms, policy_result)

        return exec_result

    # ------------------------------------------------------------------
    # Trace recording
    # ------------------------------------------------------------------

    def _record_trace(
        self,
        proposal: LoanProposalRequest,
        result: ToolExecutionResult,
        latency_ms: float,
        policy_result: Any,
    ) -> None:
        """Build and store an AgentTrace. Failures are logged, never re-raised."""
        try:
            from agentguard.models.actions import AuthorizedTool
            authorized = {t.value for t in AuthorizedTool}
            tool_choice_valid = proposal.tool in authorized

            # Determine policy_compliance
            is_compliant = result.policy_decision == PolicyDecision.ALLOWED or (
                result.policy_decision == PolicyDecision.ESCALATED
                and proposal.tool == AuthorizedTool.ESCALATE_FOR_HUMAN_REVIEW.value
            ) or (
                result.policy_decision == PolicyDecision.ALLOWED
                and proposal.tool == AuthorizedTool.REJECT_LOAN.value
            )

            # Confidence justified: compliant if >= threshold for approve, or escalated/rejected
            conf_justified: Optional[bool] = None
            try:
                conf_val = float(proposal.confidence)
                from agentguard.config import get_settings
                settings = get_settings()
                if proposal.tool == AuthorizedTool.APPROVE_LOAN.value:
                    conf_justified = conf_val >= settings.min_confidence_threshold
                else:
                    conf_justified = True
            except Exception:
                conf_justified = None

            evaluation = EvaluationResult(
                policy_compliance="compliant" if is_compliant else "non_compliant",
                injection_detected=False,  # If guard ran before, its events are in store
                pii_leakage_detected=False,
                tool_choice_valid=tool_choice_valid,
                confidence_justified=conf_justified,
            )

            trace = AgentTrace(
                conversation_id=None,
                agent_id=proposal.agent_id,
                model_name=proposal.metadata.get("source", "unknown"),
                input_text_hash=None,
                llm_call_metadata=sanitize_payload(
                    {k: v for k, v in proposal.metadata.items()
                     if k not in ("reasoning_summary", "evidence")}
                ),
                tool_proposal=sanitize_payload(proposal.model_dump()),
                policy_decision=result.policy_decision.value,
                tool_execution_result=sanitize_payload(result.model_dump()),
                latency_ms=round(latency_ms, 2),
                input_tokens=None,
                output_tokens=None,
                estimated_cost=None,
                evaluation_result=evaluation,
            )
            self.traces.add_trace(trace)

        except Exception as exc:
            logger.error("Failed to record agent trace: %s", exc, exc_info=True)

    # ------------------------------------------------------------------
    # Simulated tool execution
    # ------------------------------------------------------------------

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
