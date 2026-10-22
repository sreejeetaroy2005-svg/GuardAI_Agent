"""
FastAPI route definitions for AgentGuard.
Exposes endpoints for proposal submission, agent simulation, observability queries,
incident inspection, kill switch controls, human review workflow, LLM banking agent,
and trace retrieval.
"""

from typing import Any, Dict, List, Literal, Optional
from fastapi import APIRouter, Body, HTTPException, Query, status
from pydantic import BaseModel, Field

from agentguard.agents.agent_a import agent_a
from agentguard.agents.agent_b import agent_b
from agentguard.agents.llm_banking_agent import BankingRequest, LLMBankingAgent, MockModelClient
from agentguard.config import get_settings
from agentguard.models.actions import (
    LoanProposalRequest,
    PolicyDecision,
    ToolExecutionResult,
)
from agentguard.models.events import EventRecord
from agentguard.models.incidents import IncidentRecord
from agentguard.models.traces import AgentTrace, ToolProposal
from agentguard.monitoring.monitor import incident_store, monitor
from agentguard.observability.store import event_store
from agentguard.observability.trace_store import trace_store
from agentguard.review.human_review import (
    ForgeryAttemptError,
    HumanReviewStatus,
    HumanReviewTask,
    HumanReviewStore,
    TaskAlreadyDecidedError,
    TaskNotFoundError,
    human_review_store,
)
from agentguard.tools.executor import tool_executor

router = APIRouter()


# -------------------------------------------------------------
# Request & Response DTOs
# -------------------------------------------------------------

class HealthResponse(BaseModel):
    status: str
    version: str
    kill_switch_active: bool
    policy_thresholds: Dict[str, Any]
    slack_alerting_enabled: bool
    total_events: int
    total_violations: int


class AgentARunRequest(BaseModel):
    loan_id: str = Field(default="LOAN_A_001", description="Loan application ID")
    amount: float = Field(default=8500.0, description="Requested loan amount in INR")
    confidence: float = Field(default=0.89, description="Simulated confidence score [0.0 - 1.0]")
    metadata: Dict[str, Any] = Field(default_factory=dict)


class AgentBRunRequest(BaseModel):
    scenario: Literal[
        "compliant",
        "high_value_bypass",
        "low_confidence",
        "unauthorized_tool",
        "malformed_confidence",
        "malformed_amount",
        "repeated_attacks",
    ] = Field(
        default="high_value_bypass",
        description="Adversarial scenario to execute",
    )
    loan_id: Optional[str] = None
    amount: Optional[Any] = None
    confidence: Optional[Any] = None
    tool: Optional[str] = None
    repeat_count: int = Field(default=4, ge=1, le=20)


class KillSwitchRequest(BaseModel):
    active: bool = Field(..., description="Desired kill switch status: true to halt, false to resume")
    reason: Optional[str] = Field(default="Manual operator change", description="Audit reason")


class KillSwitchResponse(BaseModel):
    kill_switch_active: bool
    message: str


class LLMBankingAgentRunResponse(BaseModel):
    """Response from the end-to-end LLM Banking Agent pipeline."""
    proposal: ToolProposal
    execution_result: ToolExecutionResult
    injection_detected: bool
    trace_id: Optional[str] = None


class HumanReviewDecisionRequest(BaseModel):
    decided_by: str = Field(..., description="Identifier of the human officer making the decision")


# -------------------------------------------------------------
# System & Health Endpoints
# -------------------------------------------------------------

@router.get("/health", response_model=HealthResponse, tags=["Health"])
def get_health() -> HealthResponse:
    """Return platform operational status, security posture, and runtime thresholds."""
    settings = get_settings()
    stats = event_store.get_violation_counts()
    return HealthResponse(
        status="healthy",
        version="0.1.0",
        kill_switch_active=settings.kill_switch_active,
        policy_thresholds={
            "max_auto_approve_amount": settings.max_auto_approve_amount,
            "min_confidence_threshold": settings.min_confidence_threshold,
            "repeated_failure_threshold": settings.repeated_failure_threshold,
        },
        slack_alerting_enabled=bool(settings.slack_webhook_url),
        total_events=stats["total_events"],
        total_violations=stats["total_violations"],
    )


# -------------------------------------------------------------
# Proposal Evaluation & Agent Runners
# -------------------------------------------------------------

@router.post(
    "/api/v1/proposals/evaluate",
    response_model=ToolExecutionResult,
    tags=["Policy & Tool Execution"],
)
def evaluate_proposal(proposal: LoanProposalRequest) -> ToolExecutionResult:
    """
    Submit an action proposal through the policy enforcement and execution pipeline.
    The proposal is synchronously validated before any tool is executed.
    """
    return tool_executor.process_proposal(proposal)


@router.post(
    "/api/v1/agents/agent-a/run",
    response_model=ToolExecutionResult,
    tags=["Simulated Agents"],
)
def run_agent_a(payload: AgentARunRequest) -> ToolExecutionResult:
    """
    Execute compliant Agent A on a loan scenario.
    Agent A proposes an action based on rules, then submits it to the tool executor.
    """
    proposal = agent_a.evaluate_loan(
        loan_id=payload.loan_id,
        amount=payload.amount,
        confidence=payload.confidence,
        metadata=payload.metadata,
    )
    return agent_a.submit_proposal(proposal)


@router.post(
    "/api/v1/agents/agent-b/run",
    response_model=List[ToolExecutionResult],
    tags=["Simulated Agents"],
)
def run_agent_b(payload: AgentBRunRequest) -> List[ToolExecutionResult]:
    """
    Execute Agent B in compliant mode or under one of the adversarial probing scenarios.
    Returns the execution results indicating policy decisions and execution status.
    """
    results: List[ToolExecutionResult] = []

    if payload.scenario == "compliant":
        loan_id = payload.loan_id or "LOAN_B_COMPL"
        amt = payload.amount if payload.amount is not None else 6500.0
        conf = payload.confidence if payload.confidence is not None else 0.91
        proposal = agent_b.evaluate_loan(loan_id=loan_id, amount=amt, confidence=conf)
        res = agent_b.submit_proposal(proposal)
        results.append(res)

    elif payload.scenario == "high_value_bypass":
        amt = payload.amount if payload.amount is not None else 45000.0
        conf = payload.confidence if payload.confidence is not None else 0.95
        loan_id = payload.loan_id or "LOAN_ADV_HV_01"
        proposal = agent_b.propose_high_value_auto_approval(amount=amt, confidence=conf, loan_id=loan_id)
        res = agent_b.submit_proposal(proposal)
        results.append(res)

    elif payload.scenario == "low_confidence":
        amt = payload.amount if payload.amount is not None else 5000.0
        conf = payload.confidence if payload.confidence is not None else 0.40
        loan_id = payload.loan_id or "LOAN_ADV_LC_01"
        proposal = agent_b.propose_low_confidence_auto_approval(amount=amt, confidence=conf, loan_id=loan_id)
        res = agent_b.submit_proposal(proposal)
        results.append(res)

    elif payload.scenario == "unauthorized_tool":
        tool_name = payload.tool or "override_loan_limit"
        amt = payload.amount if payload.amount is not None else 20000.0
        conf = payload.confidence if payload.confidence is not None else 0.92
        loan_id = payload.loan_id or "LOAN_ADV_TOOL_01"
        proposal = agent_b.propose_unauthorized_tool(tool=tool_name, amount=amt, confidence=conf, loan_id=loan_id)
        res = agent_b.submit_proposal(proposal)
        results.append(res)

    elif payload.scenario == "malformed_confidence":
        conf = payload.confidence if payload.confidence is not None else 1.95
        amt = payload.amount if payload.amount is not None else 5000.0
        loan_id = payload.loan_id or "LOAN_ADV_MAL_C"
        proposal = agent_b.propose_malformed_confidence(confidence=conf, amount=amt, loan_id=loan_id)
        res = agent_b.submit_proposal(proposal)
        results.append(res)

    elif payload.scenario == "malformed_amount":
        amt = payload.amount if payload.amount is not None else -5000.0
        conf = payload.confidence if payload.confidence is not None else 0.85
        loan_id = payload.loan_id or "LOAN_ADV_MAL_A"
        proposal = agent_b.propose_malformed_amount(amount=amt, confidence=conf, loan_id=loan_id)
        res = agent_b.submit_proposal(proposal)
        results.append(res)

    elif payload.scenario == "repeated_attacks":
        tool_name = payload.tool or "override_loan_limit"
        amt = payload.amount if payload.amount is not None else 60000.0
        proposals = agent_b.generate_repeated_attacks(
            count=payload.repeat_count,
            tool=tool_name,
            amount=amt,
        )
        for prop in proposals:
            res = agent_b.submit_proposal(prop)
            results.append(res)

    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unknown scenario: {payload.scenario}",
        )

    return results


# -------------------------------------------------------------
# LLM Banking Agent (new)
# -------------------------------------------------------------

@router.post(
    "/api/v1/agents/llm-banking-agent/run",
    response_model=LLMBankingAgentRunResponse,
    tags=["LLM Banking Agent"],
)
def run_llm_banking_agent(request: BankingRequest) -> LLMBankingAgentRunResponse:
    """
    Run the end-to-end LLM Banking Agent pipeline:
      1. UntrustedInputGuard scans free_text_request and document_text.
      2. LLM (or MockModelClient if no key) produces a ToolProposal.
      3. ToolProposal is submitted to the ControlledToolExecutor → PolicyEngine.
      4. An AgentTrace is recorded.
    Returns the proposal, execution result, injection flag, and trace_id.
    """
    # Always use MockModelClient when OPENAI_API_KEY is not set
    agent = LLMBankingAgent(model_client=MockModelClient())

    # Agent run: injection scan + model inference → ToolProposal (no execution)
    proposal = agent.run(request)

    # Detect if any injection was flagged during this request
    injection_detected = _check_injection_detected()

    # Convert → LoanProposalRequest and submit through the policy gate
    loan_proposal = proposal.to_loan_proposal_request()
    execution_result = tool_executor.process_proposal(loan_proposal)

    # Retrieve the most recent trace for this agent
    traces = trace_store.get_traces(limit=1, agent_id=proposal.agent_id)
    trace_id = traces[0].trace_id if traces else None

    return LLMBankingAgentRunResponse(
        proposal=proposal,
        execution_result=execution_result,
        injection_detected=injection_detected,
        trace_id=trace_id,
    )


def _check_injection_detected() -> bool:
    """Check the recent event store for any injection_detected events."""
    recent = event_store.get_recent_events(limit=10)
    return any(evt.execution_status == "injection_detected" for evt in recent)


# -------------------------------------------------------------
# Observability & Audit Endpoints
# -------------------------------------------------------------

@router.get(
    "/api/v1/observability/events",
    response_model=List[EventRecord],
    tags=["Observability"],
)
def get_events(
    limit: int = Query(default=50, ge=1, le=500),
    agent_id: Optional[str] = Query(default=None),
    decision: Optional[str] = Query(default=None),
) -> List[EventRecord]:
    """Retrieve audit log events with optional filters."""
    return event_store.get_recent_events(limit=limit, agent_id=agent_id, decision=decision)


@router.get(
    "/api/v1/observability/violations",
    response_model=Dict[str, Any],
    tags=["Observability"],
)
def get_violations() -> Dict[str, Any]:
    """Return aggregated metrics and breakdown of policy violations."""
    return event_store.get_violation_counts()


@router.get(
    "/api/v1/observability/traces",
    response_model=List[AgentTrace],
    tags=["Observability"],
)
def get_traces(
    limit: int = Query(default=50, ge=1, le=500),
    agent_id: Optional[str] = Query(default=None),
) -> List[AgentTrace]:
    """Retrieve structured agent traces in reverse-chronological order."""
    return trace_store.get_traces(limit=limit, agent_id=agent_id)


@router.get(
    "/api/v1/observability/traces/{trace_id}",
    response_model=AgentTrace,
    tags=["Observability"],
)
def get_trace(trace_id: str) -> AgentTrace:
    """Retrieve a specific agent trace by its trace_id."""
    trace = trace_store.get_trace_by_id(trace_id)
    if trace is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Trace '{trace_id}' not found.",
        )
    return trace


# -------------------------------------------------------------
# Human Review Workflow (new)
# -------------------------------------------------------------

@router.get(
    "/api/v1/human-review/queue",
    response_model=List[HumanReviewTask],
    tags=["Human Review"],
)
def get_human_review_queue(
    review_status: Optional[str] = Query(default=None, alias="status"),
) -> List[HumanReviewTask]:
    """
    Retrieve the human review queue, ordered by creation time (oldest first).
    Optionally filter by status: PENDING | APPROVED | REJECTED | EXPIRED.
    """
    filter_status = None
    if review_status:
        try:
            filter_status = HumanReviewStatus(review_status.upper())
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid status '{review_status}'. Must be one of: PENDING, APPROVED, REJECTED, EXPIRED.",
            )
    return human_review_store.get_queue(status=filter_status)


@router.post(
    "/api/v1/human-review/{task_id}/approve",
    response_model=HumanReviewTask,
    tags=["Human Review"],
)
def approve_human_review(
    task_id: str,
    payload: HumanReviewDecisionRequest,
) -> HumanReviewTask:
    """
    Approve a pending human review task.

    SECURITY: If the request body contains 'human_approved=true', the request
    is rejected as an approval forgery attempt and a CRITICAL incident is created.
    """
    # Forgery guard on the decided_by payload dict
    try:
        HumanReviewStore.check_forgery_attempt(payload.model_dump())
    except ForgeryAttemptError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    try:
        return human_review_store.approve(task_id, payload.decided_by)
    except TaskNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except TaskAlreadyDecidedError as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e))


@router.post(
    "/api/v1/human-review/{task_id}/reject",
    response_model=HumanReviewTask,
    tags=["Human Review"],
)
def reject_human_review(
    task_id: str,
    payload: HumanReviewDecisionRequest,
) -> HumanReviewTask:
    """
    Reject a pending human review task.

    SECURITY: If the request body contains 'human_approved=true', the request
    is rejected as an approval forgery attempt and a CRITICAL incident is created.
    """
    try:
        HumanReviewStore.check_forgery_attempt(payload.model_dump())
    except ForgeryAttemptError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    try:
        return human_review_store.reject(task_id, payload.decided_by)
    except TaskNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except TaskAlreadyDecidedError as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e))


# -------------------------------------------------------------
# Monitoring & Incident Endpoints
# -------------------------------------------------------------

@router.get(
    "/api/v1/monitoring/incidents",
    response_model=List[IncidentRecord],
    tags=["Monitoring"],
)
def get_incidents(
    limit: int = Query(default=50, ge=1, le=500),
    severity: Optional[str] = Query(default=None),
) -> List[IncidentRecord]:
    """Retrieve security incidents logged by the monitoring service."""
    return incident_store.get_recent_incidents(limit=limit, severity=severity)


@router.get(
    "/api/v1/monitoring/kill-switch",
    response_model=KillSwitchResponse,
    tags=["Monitoring & Circuit Breakers"],
)
def get_kill_switch_status() -> KillSwitchResponse:
    """Check current state of the global automated approval kill switch."""
    settings = get_settings()
    return KillSwitchResponse(
        kill_switch_active=settings.kill_switch_active,
        message="Kill switch is ACTIVE: all automated approvals blocked."
        if settings.kill_switch_active
        else "Kill switch is INACTIVE: normal automated policies active.",
    )


@router.post(
    "/api/v1/monitoring/kill-switch",
    response_model=KillSwitchResponse,
    tags=["Monitoring & Circuit Breakers"],
)
def toggle_kill_switch(payload: KillSwitchRequest) -> KillSwitchResponse:
    """Manually engage or disengage the global automated approval kill switch."""
    monitor.set_kill_switch(payload.active)
    return KillSwitchResponse(
        kill_switch_active=payload.active,
        message=f"Kill switch successfully set to {payload.active}. Reason: {payload.reason}",
    )


@router.post(
    "/api/v1/monitoring/reset",
    response_model=Dict[str, str],
    tags=["Maintenance & Testing"],
)
def reset_audit_state() -> Dict[str, str]:
    """Reset event stores, incident records, trace store, human review queue, and kill switch."""
    event_store.clear()
    incident_store.clear()
    trace_store.clear()
    human_review_store.clear()
    monitor.set_kill_switch(False)
    return {"message": "AgentGuard audit stores and kill switch reset successfully."}
