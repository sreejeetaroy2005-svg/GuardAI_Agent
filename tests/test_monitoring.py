"""
Unit tests for the AgentGuard Monitoring & Alerting component.
Verifies incident creation, severity classification, Slack webhook mocking and resilience,
repeated failure detection, and kill switch circuit breaking.
"""

from unittest.mock import MagicMock, patch
import httpx
import pytest

from agentguard.config import Settings
from agentguard.models.actions import PolicyDecision
from agentguard.models.events import EventRecord
from agentguard.models.incidents import IncidentSeverity
from agentguard.monitoring.monitor import AgentGuardMonitor, IncidentStore
from agentguard.monitoring.slack import send_slack_alert
from agentguard.observability.store import EventStore


class TestAgentGuardMonitor:
    def test_creates_incident_on_blocked_event(self, clean_settings: Settings):
        store = EventStore()
        incidents = IncidentStore()
        monitor = AgentGuardMonitor(settings=clean_settings, store=store, incidents=incidents)

        event = EventRecord(
            correlation_id="corr_test_01",
            agent_id="agent_b",
            requested_tool="approve_loan",
            loan_amount=25000.0,
            confidence=0.90,
            policy_decision=PolicyDecision.BLOCKED,
            execution_status="blocked",
            violation_reason="Loan amount exceeds limit",
            rule_triggered="RULE_MAX_AMOUNT_EXCEEDED",
        )
        store.record_event(event)

        incident = monitor.process_event(event)

        assert incident is not None
        assert incident.agent_id == "agent_b"
        assert incident.correlation_id == "corr_test_01"
        assert incident.severity == IncidentSeverity.HIGH
        assert len(incidents.get_recent_incidents()) == 1

    def test_ignores_allowed_event(self, clean_settings: Settings):
        store = EventStore()
        incidents = IncidentStore()
        monitor = AgentGuardMonitor(settings=clean_settings, store=store, incidents=incidents)

        event = EventRecord(
            correlation_id="corr_test_ok",
            agent_id="agent_a",
            requested_tool="approve_loan",
            loan_amount=5000.0,
            confidence=0.90,
            policy_decision=PolicyDecision.ALLOWED,
            execution_status="executed",
        )
        store.record_event(event)

        incident = monitor.process_event(event)
        assert incident is None
        assert len(incidents.get_recent_incidents()) == 0

    def test_unauthorized_tool_triggers_critical_and_activates_kill_switch(self, clean_settings: Settings):
        store = EventStore()
        incidents = IncidentStore()
        clean_settings.kill_switch_active = False
        monitor = AgentGuardMonitor(settings=clean_settings, store=store, incidents=incidents)

        event = EventRecord(
            correlation_id="corr_unauth",
            agent_id="agent_b",
            requested_tool="override_loan_limit",
            loan_amount=10000.0,
            confidence=0.90,
            policy_decision=PolicyDecision.BLOCKED,
            execution_status="blocked",
            rule_triggered="RULE_TOOL_AUTHORIZATION",
        )
        store.record_event(event)

        incident = monitor.process_event(event)

        assert incident is not None
        assert incident.severity == IncidentSeverity.CRITICAL
        assert incident.kill_switch_triggered is True
        assert clean_settings.kill_switch_active is True

    def test_repeated_failures_escalate_severity(self, clean_settings: Settings):
        store = EventStore()
        incidents = IncidentStore()
        clean_settings.repeated_failure_threshold = 3
        monitor = AgentGuardMonitor(settings=clean_settings, store=store, incidents=incidents)

        # Simulate 3 consecutive failures
        for i in range(3):
            event = EventRecord(
                correlation_id=f"c_{i}",
                agent_id="agent_b",
                requested_tool="approve_loan",
                loan_amount=5000.0,
                confidence=0.50,
                policy_decision=PolicyDecision.BLOCKED,
                execution_status="blocked",
                rule_triggered="RULE_LOW_CONFIDENCE",
            )
            store.record_event(event)
            incident = monitor.process_event(event)

        assert incident is not None
        assert incident.severity == IncidentSeverity.HIGH
        assert "Repeated failure threshold reached" in incident.reason


class TestSlackAlerting:
    def test_slack_skipped_gracefully_when_unconfigured(self, clean_settings: Settings):
        clean_settings.slack_webhook_url = None
        store = EventStore()
        incidents = IncidentStore()
        monitor = AgentGuardMonitor(settings=clean_settings, store=store, incidents=incidents)

        event = EventRecord(
            correlation_id="c_no_slack",
            agent_id="agent_b",
            requested_tool="approve_loan",
            loan_amount=15000.0,
            policy_decision=PolicyDecision.BLOCKED,
            execution_status="blocked",
            rule_triggered="RULE_MAX_AMOUNT_EXCEEDED",
        )
        store.record_event(event)

        incident = monitor.process_event(event)
        assert incident is not None
        assert incident.slack_notification_sent is False

    @patch("agentguard.monitoring.slack.httpx.post")
    def test_slack_dispatched_successfully_when_configured(self, mock_post, clean_settings: Settings):
        clean_settings.slack_webhook_url = "https://hooks.slack.com/services/TEST/TOKEN/123"
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response

        store = EventStore()
        incidents = IncidentStore()
        monitor = AgentGuardMonitor(settings=clean_settings, store=store, incidents=incidents)

        event = EventRecord(
            correlation_id="c_slack_ok",
            agent_id="agent_b",
            requested_tool="disburse_funds",
            policy_decision=PolicyDecision.BLOCKED,
            execution_status="blocked",
            rule_triggered="RULE_TOOL_AUTHORIZATION",
        )
        store.record_event(event)

        incident = monitor.process_event(event)

        assert incident is not None
        assert incident.slack_notification_sent is True
        assert mock_post.called
        assert mock_post.call_args[0][0] == clean_settings.slack_webhook_url

    @patch("agentguard.monitoring.slack.httpx.post")
    def test_slack_failure_handled_gracefully_without_crashing(self, mock_post, clean_settings: Settings):
        clean_settings.slack_webhook_url = "https://hooks.slack.com/services/TEST/TOKEN/123"
        # Simulate network timeout or failure
        mock_post.side_effect = httpx.ConnectTimeout("Slack endpoint unreachable")

        store = EventStore()
        incidents = IncidentStore()
        monitor = AgentGuardMonitor(settings=clean_settings, store=store, incidents=incidents)

        event = EventRecord(
            correlation_id="c_slack_fail",
            agent_id="agent_b",
            requested_tool="override_loan_limit",
            policy_decision=PolicyDecision.BLOCKED,
            execution_status="blocked",
            rule_triggered="RULE_TOOL_AUTHORIZATION",
        )
        store.record_event(event)

        # Must not raise an exception
        incident = monitor.process_event(event)

        assert incident is not None
        assert incident.slack_notification_sent is False
