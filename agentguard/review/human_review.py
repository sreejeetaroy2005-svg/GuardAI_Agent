"""
Human-review workflow for AgentGuard.

When the PolicyEngine returns ESCALATED the ControlledToolExecutor creates a
HumanReviewTask bound to the immutable proposal_id.  Human officers can then
approve or reject the task via the API.

Architectural guarantees:
- Human approval is stored OUTSIDE the agent conversation.
- Approval is always bound to the original immutable proposal_id.
- Any attempt to inject "human_approved=true" into an agent request is
  detected, rejected, and escalated as a CRITICAL security incident
  ("approval_forgery_attempt").
- The HumanReviewStore is purely in-memory (no database required).
"""

from __future__ import annotations

import logging
import threading
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional

from pydantic import BaseModel, Field

logger = logging.getLogger("agentguard.review.human_review")


# ---------------------------------------------------------------------------
# Status enum
# ---------------------------------------------------------------------------

class HumanReviewStatus(str, Enum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"


# ---------------------------------------------------------------------------
# Task model
# ---------------------------------------------------------------------------

class HumanReviewTask(BaseModel):
    """
    A durable human-review record created when a loan proposal is ESCALATED.
    """

    task_id: str = Field(
        default_factory=lambda: f"task_{uuid.uuid4().hex[:16]}",
        description="Unique task identifier.",
    )
    proposal_id: str = Field(
        ...,
        description=(
            "Immutable identifier of the originating ToolProposal. "
            "Human approval is always bound to this ID."
        ),
    )
    agent_id: str = Field(..., description="Agent that produced the proposal.")
    loan_id: str = Field(..., description="Target loan application identifier.")
    amount: float = Field(..., description="Loan amount in INR.")
    confidence: float = Field(..., description="Agent confidence score.")
    reason: str = Field(
        default="Escalated for human review.",
        description="Human-readable reason for escalation.",
    )
    status: HumanReviewStatus = Field(
        default=HumanReviewStatus.PENDING,
        description="Current review status.",
    )
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
    )
    decided_at: Optional[datetime] = Field(
        default=None,
        description="UTC timestamp when the human decision was recorded.",
    )
    decided_by: Optional[str] = Field(
        default=None,
        description="Identifier of the human officer who made the decision.",
    )


# ---------------------------------------------------------------------------
# Custom exceptions
# ---------------------------------------------------------------------------

class ForgeryAttemptError(Exception):
    """
    Raised when an incoming request contains 'human_approved=true',
    indicating an approval forgery attempt.
    """

    def __init__(self, detail: str = "Approval forgery attempt detected.") -> None:
        super().__init__(detail)
        self.detail = detail


class TaskNotFoundError(Exception):
    """Raised when a task_id does not exist in the store."""

    def __init__(self, task_id: str) -> None:
        super().__init__(f"Human review task '{task_id}' not found.")
        self.task_id = task_id


class TaskAlreadyDecidedError(Exception):
    """Raised when an approve/reject is attempted on a non-PENDING task."""

    def __init__(self, task_id: str, current_status: HumanReviewStatus) -> None:
        super().__init__(
            f"Task '{task_id}' is already in terminal status '{current_status.value}'."
        )
        self.task_id = task_id
        self.current_status = current_status


# ---------------------------------------------------------------------------
# Store
# ---------------------------------------------------------------------------

class HumanReviewStore:
    """
    Thread-safe, in-memory store for HumanReviewTask records.

    This is intentionally kept simple (no database) while providing the
    durability guarantees required by the architectural invariants:
    - Tasks are immutably created from a ToolProposal.
    - Only status, decided_at, and decided_by may be mutated post-creation.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._tasks: Dict[str, HumanReviewTask] = {}

    # ------------------------------------------------------------------
    # Creation
    # ------------------------------------------------------------------

    def create_task(
        self,
        proposal_id: str,
        agent_id: str,
        loan_id: str,
        amount: float,
        confidence: float,
        reason: str = "Escalated for human review.",
    ) -> HumanReviewTask:
        """
        Create a new HumanReviewTask bound to *proposal_id*.
        Returns the newly created task.
        """
        task = HumanReviewTask(
            proposal_id=proposal_id,
            agent_id=agent_id,
            loan_id=loan_id,
            amount=amount,
            confidence=confidence,
            reason=reason,
        )
        with self._lock:
            self._tasks[task.task_id] = task
        logger.info(
            "HumanReviewTask created: task_id=%s proposal_id=%s loan_id=%s amount=%.2f",
            task.task_id,
            proposal_id,
            loan_id,
            amount,
        )
        return task

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def get_queue(self, status: Optional[HumanReviewStatus] = None) -> List[HumanReviewTask]:
        """
        Return tasks ordered by created_at ascending.
        Optionally filter by *status*.
        """
        with self._lock:
            tasks = list(self._tasks.values())
        if status is not None:
            tasks = [t for t in tasks if t.status == status]
        return sorted(tasks, key=lambda t: t.created_at)

    def get_task(self, task_id: str) -> Optional[HumanReviewTask]:
        """Return the task with *task_id*, or None if not found."""
        with self._lock:
            return self._tasks.get(task_id)

    # ------------------------------------------------------------------
    # Decision actions
    # ------------------------------------------------------------------

    def approve(self, task_id: str, decided_by: str) -> HumanReviewTask:
        """
        Mark a PENDING task as APPROVED.

        Raises TaskNotFoundError if the task does not exist.
        Raises TaskAlreadyDecidedError if the task is not PENDING.
        """
        return self._decide(task_id, HumanReviewStatus.APPROVED, decided_by)

    def reject(self, task_id: str, decided_by: str) -> HumanReviewTask:
        """
        Mark a PENDING task as REJECTED.

        Raises TaskNotFoundError if the task does not exist.
        Raises TaskAlreadyDecidedError if the task is not PENDING.
        """
        return self._decide(task_id, HumanReviewStatus.REJECTED, decided_by)

    def _decide(
        self,
        task_id: str,
        new_status: HumanReviewStatus,
        decided_by: str,
    ) -> HumanReviewTask:
        with self._lock:
            task = self._tasks.get(task_id)
            if task is None:
                raise TaskNotFoundError(task_id)
            if task.status != HumanReviewStatus.PENDING:
                raise TaskAlreadyDecidedError(task_id, task.status)
            task.status = new_status
            task.decided_at = datetime.now(timezone.utc)
            task.decided_by = decided_by

        logger.info(
            "HumanReviewTask decided: task_id=%s status=%s decided_by=%s",
            task_id,
            new_status.value,
            decided_by,
        )
        return task

    # ------------------------------------------------------------------
    # Forgery guard (class-level utility)
    # ------------------------------------------------------------------

    @staticmethod
    def check_forgery_attempt(body: dict) -> None:
        """
        Inspect *body* for any key that indicates an approval forgery attempt.

        If 'human_approved' exists with a truthy value:
        - Creates a CRITICAL incident in the monitoring store.
        - Raises ForgeryAttemptError.

        This guard must be called before any request processing in approval
        and rejection handler endpoints.
        """
        raw_value = body.get("human_approved")
        if raw_value is None:
            return

        # Any truthy value is treated as a forgery attempt
        is_truthy = raw_value is True or str(raw_value).lower() in (
            "true", "1", "yes", "on"
        )
        if not is_truthy:
            return

        logger.critical(
            "APPROVAL FORGERY ATTEMPT detected: request body contained "
            "'human_approved=%s'. Creating CRITICAL security incident.",
            raw_value,
        )

        # Persist as a CRITICAL incident
        _create_forgery_incident(body)

        raise ForgeryAttemptError(
            "Request rejected: 'human_approved' cannot be set by an agent or "
            "user. Human approval must go through the /human-review API only."
        )

    # ------------------------------------------------------------------
    # Maintenance
    # ------------------------------------------------------------------

    def clear(self) -> None:
        """Clear all tasks (for testing)."""
        with self._lock:
            self._tasks.clear()

    def __len__(self) -> int:
        with self._lock:
            return len(self._tasks)


# ---------------------------------------------------------------------------
# Forgery incident helper (avoids circular import by lazy import)
# ---------------------------------------------------------------------------

def _create_forgery_incident(body: dict) -> None:
    """Write a CRITICAL IncidentRecord for an approval forgery attempt."""
    try:
        from agentguard.models.incidents import IncidentRecord, IncidentSeverity
        from agentguard.monitoring.monitor import incident_store
        from agentguard.config import get_settings

        incident = IncidentRecord(
            severity=IncidentSeverity.CRITICAL,
            agent_id=str(body.get("agent_id", "unknown")),
            correlation_id=str(body.get("correlation_id", f"forgery_{uuid.uuid4().hex[:12]}")),
            reason=(
                "approval_forgery_attempt: Request body contained 'human_approved=true'. "
                "This is a critical security violation. Human approval must go through "
                "the dedicated /human-review API and cannot be injected via agent requests."
            ),
            details={
                "incident_type": "approval_forgery_attempt",
                "body_keys": list(body.keys()),
            },
            kill_switch_triggered=False,
        )
        incident_store.add_incident(incident)

        # Attempt Slack alert (non-blocking)
        from agentguard.monitoring.slack import send_slack_alert
        settings = get_settings()
        send_slack_alert(settings.slack_webhook_url, incident)

    except Exception as exc:  # pragma: no cover
        logger.error("Failed to persist forgery incident: %s", exc, exc_info=True)


# ---------------------------------------------------------------------------
# Global singleton
# ---------------------------------------------------------------------------

human_review_store = HumanReviewStore()
