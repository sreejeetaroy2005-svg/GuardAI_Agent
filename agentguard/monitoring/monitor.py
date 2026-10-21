"""
Monitoring component for AgentGuard.
Detects policy violations, analyzes anomalous patterns (e.g., repeated failed tool calls),
manages incident records, triggers kill switches, and dispatches Slack notifications.

IMPORTANT ARCHITECTURAL INVARIANT:
The monitoring component performs post-event analysis and alerting.
It NEVER stops an already executed action; enforcement and prevention occur strictly
before execution in the synchronous policy engine.
"""

from datetime import datetime, timezone
import logging
import threading
from typing import Any, Dict, List, Optional
from agentguard.config import Settings, get_settings
from agentguard.models.actions import PolicyDecision
from agentguard.models.events import EventRecord
from agentguard.models.incidents import IncidentRecord, IncidentSeverity
from agentguard.monitoring.slack import send_slack_alert
from agentguard.observability.logger import audit_logger
from agentguard.observability.store import EventStore, event_store

logger = logging.getLogger("agentguard.monitoring")


class IncidentStore:
    """Thread-safe storage and query interface for incidents."""

    def __init__(self, max_history: int = 500) -> None:
        self._lock = threading.Lock()
        self._incidents: List[IncidentRecord] = []
        self._max_history = max_history

    def add_incident(self, incident: IncidentRecord) -> None:
        """Store an incident record."""
        with self._lock:
            self._incidents.append(incident)
            if len(self._incidents) > self._max_history:
                self._incidents = self._incidents[-self._max_history :]

    def get_recent_incidents(
        self, limit: int = 50, severity: Optional[str] = None
    ) -> List[IncidentRecord]:
        """Retrieve recent incidents in reverse chronological order."""
        with self._lock:
            filtered = self._incidents
            if severity:
                filtered = [
                    inc for inc in filtered if inc.severity.value.upper() == severity.upper()
                ]
            return list(reversed(filtered[-limit:]))

    def clear(self) -> None:
        """Clear all stored incidents."""
        with self._lock:
            self._incidents.clear()


# Global incident store
incident_store = IncidentStore()


class AgentGuardMonitor:
    """
    Monitoring service that reviews recorded events for violations and patterns.
    """

    def __init__(
        self,
        settings: Optional[Settings] = None,
        store: Optional[EventStore] = None,
        incidents: Optional[IncidentStore] = None,
    ) -> None:
        self.settings = settings or get_settings()
        self.event_store = store or event_store
        self.incident_store = incidents or incident_store

    def process_event(self, event: EventRecord) -> Optional[IncidentRecord]:
        """
        Analyze a recorded event. If the event is a policy violation or part of a
        suspicious pattern, create an incident record and dispatch alerts.
        """
        # Only evaluate finalized events that were blocked
        if event.policy_decision != PolicyDecision.BLOCKED:
            return None

        # Determine severity and trigger conditions
        consecutive_failures = self.event_store.get_consecutive_failure_count(event.agent_id)
        severity = self._classify_severity(event, consecutive_failures)

        should_trip_kill_switch = False
        # Critical violations trigger the automated kill switch
        if severity == IncidentSeverity.CRITICAL:
            self.settings.kill_switch_active = True
            should_trip_kill_switch = True
            logger.critical(
                "CRITICAL violation detected. Automated kill switch has been engaged! Correlation: %s",
                event.correlation_id,
            )

        # Build incident reason
        reason = event.violation_reason or f"Policy rule {event.rule_triggered} violated."
        if consecutive_failures >= self.settings.repeated_failure_threshold:
            reason += (
                f" [Alert: Repeated failure threshold reached: {consecutive_failures} "
                f"consecutive failed attempts by agent '{event.agent_id}']"
            )

        # Construct incident record
        incident = IncidentRecord(
            severity=severity,
            timestamp=datetime.now(timezone.utc),
            agent_id=event.agent_id,
            correlation_id=event.correlation_id,
            reason=reason,
            details={
                "requested_tool": event.requested_tool,
                "loan_id": event.loan_id,
                "loan_amount": event.loan_amount,
                "confidence": event.confidence,
                "rule_triggered": event.rule_triggered,
                "consecutive_failures": consecutive_failures,
            },
            kill_switch_triggered=should_trip_kill_switch,
        )

        # Store incident
        self.incident_store.add_incident(incident)

        # Audit log incident
        audit_logger.warning(
            f"Incident created: {incident.incident_id} [{severity.value}]",
            extra={
                "incident_id": incident.incident_id,
                "severity": severity.value,
                "agent_id": incident.agent_id,
                "correlation_id": incident.correlation_id,
                "violation_reason": incident.reason,
            },
        )

        # Send Slack notification (graceful fallback if unconfigured or network fails)
        sent = send_slack_alert(self.settings.slack_webhook_url, incident)
        incident.slack_notification_sent = sent

        return incident

    def _classify_severity(
        self, event: EventRecord, consecutive_failures: int
    ) -> IncidentSeverity:
        """Classify violation severity based on security impact and pattern behavior."""
        # 1. Unauthorized tool calls (attempting to bypass interface) -> CRITICAL
        if event.rule_triggered == "RULE_TOOL_AUTHORIZATION":
            return IncidentSeverity.CRITICAL

        # 2. Extreme loan amount auto-approval attempt (> 5x threshold) -> CRITICAL
        if event.loan_amount is not None and event.loan_amount >= (
            self.settings.max_auto_approve_amount * 5
        ):
            return IncidentSeverity.CRITICAL

        # 3. Repeated failed attempts exceeding threshold -> HIGH
        if consecutive_failures >= self.settings.repeated_failure_threshold:
            return IncidentSeverity.HIGH

        # 4. Standard amount threshold or malformed input violations -> HIGH
        if event.rule_triggered in ("RULE_MAX_AMOUNT_EXCEEDED", "RULE_INPUT_VALIDATION"):
            return IncidentSeverity.HIGH

        # 5. Low confidence or kill switch -> MEDIUM
        return IncidentSeverity.MEDIUM

    def set_kill_switch(self, active: bool) -> bool:
        """Manually enable or disable the kill switch."""
        self.settings.kill_switch_active = active
        audit_logger.info(
            f"Kill switch state updated: active={active}",
            extra={"kill_switch_active": active},
        )
        return self.settings.kill_switch_active


# Global monitor instance
monitor = AgentGuardMonitor()
