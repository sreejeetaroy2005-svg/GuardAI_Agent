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
from typing import Any, Dict, List, Optional, Tuple
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


# ---------------------------------------------------------------------------
# Behavioral Anomaly Detector
# ---------------------------------------------------------------------------

class BehavioralAnomalyDetector:
    """
    Detects behavioral anomalies in agent activity using a rolling window of
    recent events.

    Checks performed (all thresholds configurable via Settings):
    1. Blocked-request rate in the rolling window.
    2. Unauthorized-tool-call count.
    3. Repeated consecutive failures (existing check, also surfaced here).
    4. Suspicious approval-rate change (near-100% approval after long gap).

    Returns Optional[Tuple[IncidentSeverity, str]] — None means no anomaly.
    """

    def detect(
        self,
        agent_id: str,
        recent_events: List[EventRecord],
        settings: Settings,
    ) -> Optional[Tuple[IncidentSeverity, str]]:
        """
        Analyse *recent_events* (already filtered to the rolling window) for
        the given *agent_id*.  Returns (severity, reason) or None.
        """
        if not recent_events:
            return None

        total = len(recent_events)

        # Count metrics
        blocked_count = sum(
            1 for e in recent_events if e.policy_decision == PolicyDecision.BLOCKED
        )
        unauth_tool_count = sum(
            1 for e in recent_events
            if e.rule_triggered == "RULE_TOOL_AUTHORIZATION"
        )
        allowed_count = sum(
            1 for e in recent_events if e.policy_decision == PolicyDecision.ALLOWED
        )

        # 1. Unauthorized-tool-call threshold (CRITICAL)
        if unauth_tool_count > settings.anomaly_unauth_tool_threshold:
            reason = (
                f"Behavioral anomaly: agent '{agent_id}' made {unauth_tool_count} "
                f"unauthorized tool-call attempts within the last {total} events "
                f"(threshold: >{settings.anomaly_unauth_tool_threshold})."
            )
            return IncidentSeverity.CRITICAL, reason

        # 2. High blocked-request rate (HIGH)
        blocked_rate = blocked_count / total if total > 0 else 0.0
        if total >= 5 and blocked_rate >= settings.anomaly_blocked_rate_threshold:
            reason = (
                f"Behavioral anomaly: agent '{agent_id}' has a blocked-request rate of "
                f"{blocked_rate:.0%} over the last {total} events "
                f"(threshold: {settings.anomaly_blocked_rate_threshold:.0%})."
            )
            return IncidentSeverity.HIGH, reason

        # 3. Suspicious approval-rate change (MEDIUM)
        approval_rate = allowed_count / total if total > 0 else 0.0
        # Flag only if there is at least one non-allowed event to avoid false positives on all-allowed history
        if total >= 5 and approval_rate >= settings.anomaly_approval_rate_threshold and allowed_count < total:
            reason = (
                f"Behavioral anomaly: agent '{agent_id}' has an unusually high "
                f"approval rate of {approval_rate:.0%} over the last {total} events "
                f"(threshold: {settings.anomaly_approval_rate_threshold:.0%}). "
                "This may indicate policy bypass."
            )
            return IncidentSeverity.MEDIUM, reason

        return None


# ---------------------------------------------------------------------------
# Main Monitor
# ---------------------------------------------------------------------------

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
        self._anomaly_detector = BehavioralAnomalyDetector()
        self._consecutive_failures: Dict[str, int] = {}

    def process_event(self, event: EventRecord) -> Optional[IncidentRecord]:
        """
        Analyze a recorded event. If the event is a policy violation or part of a
        suspicious pattern, create an incident record and dispatch alerts.
        """
        # Only evaluate finalized events that were blocked
        if event.policy_decision != PolicyDecision.BLOCKED:
            # Reset consecutive failure counter for this agent on allowed/non‑blocked events
            self._consecutive_failures[event.agent_id] = 0
            # Still run behavioral anomaly detection for all event types
            self._check_behavioral_anomalies(event)
            return None

        # Determine severity and trigger conditions
        # Increment failure counter for this blocked event before classification
        consecutive_failures = self._consecutive_failures.get(event.agent_id, 0) + 1
        self._consecutive_failures[event.agent_id] = consecutive_failures
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

        # Run behavioral anomaly detection before storing primary incident
        self._check_behavioral_anomalies(event)

        # Store incident (single insertion)
        self.incident_store.add_incident(incident)

        # Audit log incident (single insertion)
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

        # No additional increment needed; counter already updated earlier
        return incident

    def _check_behavioral_anomalies(self, event: EventRecord) -> None:
        """
        Run behavioral anomaly detection against the rolling window for this agent.
        If an anomaly is found, create an incident.  CRITICAL anomalies activate the
        kill switch.
        """
        try:
            # Fetch rolling window for this agent
            recent = self.event_store.get_recent_events(
                limit=self.settings.anomaly_tool_call_window,
                agent_id=event.agent_id,
            )

            result = self._anomaly_detector.detect(event.agent_id, recent, self.settings)
            if result is None:
                return

            severity, reason = result

            # Activate kill switch if CRITICAL anomaly
            if severity == IncidentSeverity.CRITICAL and not self.settings.kill_switch_active:
                self.settings.kill_switch_active = True
                logger.critical(
                    "Behavioral anomaly CRITICAL: kill switch engaged for agent '%s'. "
                    "Reason: %s",
                    event.agent_id,
                    reason,
                )

            anomaly_incident = IncidentRecord(
                severity=severity,
                timestamp=datetime.now(timezone.utc),
                agent_id=event.agent_id,
                correlation_id=event.correlation_id,
                reason=reason,
                details={
                    "detection_type": "behavioral_anomaly",
                    "window_size": self.settings.anomaly_tool_call_window,
                    "consecutive_failures": self._consecutive_failures.get(event.agent_id, 0),
                },
                kill_switch_triggered=(severity == IncidentSeverity.CRITICAL),
            )
            self.incident_store.add_incident(anomaly_incident)

            audit_logger.warning(
                f"Behavioral anomaly incident: {anomaly_incident.incident_id} [{severity.value}]",
                extra={
                    "incident_id": anomaly_incident.incident_id,
                    "severity": severity.value,
                    "agent_id": event.agent_id,
                    "reason": reason,
                },
            )

            # Non-blocking Slack alert
            sent = send_slack_alert(self.settings.slack_webhook_url, anomaly_incident)
            anomaly_incident.slack_notification_sent = sent

        except Exception as exc:
            logger.error(
                "Behavioral anomaly detection failed: %s", exc, exc_info=True
            )

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
