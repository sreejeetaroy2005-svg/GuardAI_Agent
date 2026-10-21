"""
Unit tests for the Observability Layer.
Tests structured JSON logging, secret/PII redaction, correlation tracking,
and event store querying.
"""

import json
import logging
import pytest

from agentguard.models.actions import PolicyDecision
from agentguard.models.events import EventRecord
from agentguard.observability.logger import JSONLogFormatter
from agentguard.observability.sanitizer import sanitize_payload, sanitize_string
from agentguard.observability.store import EventStore


class TestSanitizer:
    def test_redacts_sensitive_keys(self):
        payload = {
            "user_id": "usr_123",
            "password": "SuperSecretPassword123",
            "api_key": "sk-1234567890abcdef",
            "auth_token": "Bearer eyJhbGciOi...",
            "metadata": {
                "account_number": "123456789012",
                "nested_token": "secret_abc",
                "safe_note": "Normal comment",
            },
        }

        sanitized = sanitize_payload(payload)

        assert sanitized["user_id"] == "usr_123"
        assert sanitized["password"] == "[REDACTED]"
        assert sanitized["api_key"] == "[REDACTED]"
        assert sanitized["auth_token"] == "[REDACTED]"
        assert sanitized["metadata"]["account_number"] == "[REDACTED]"
        assert sanitized["metadata"]["nested_token"] == "[REDACTED]"
        assert sanitized["metadata"]["safe_note"] == "Normal comment"

    def test_redacts_sensitive_string_patterns(self):
        raw_text = "Contact john.doe@example.com with card 4111 2222 3333 4444 and Bearer abc.123.xyz"
        sanitized = sanitize_string(raw_text)

        assert "john.doe@example.com" not in sanitized
        assert "[REDACTED_EMAIL]" in sanitized
        assert "4111 2222 3333 4444" not in sanitized
        assert "[REDACTED_CARD]" in sanitized
        assert "Bearer [REDACTED_TOKEN]" in sanitized


class TestJSONLogFormatter:
    def test_formatter_outputs_valid_json_with_metadata(self):
        formatter = JSONLogFormatter()
        record = logging.LogRecord(
            name="agentguard.test",
            level=logging.WARNING,
            pathname=__file__,
            lineno=10,
            msg="Policy violation detected",
            args=(),
            exc_info=None,
        )
        record.correlation_id = "corr_12345"
        record.agent_id = "agent_b"
        record.requested_tool = "approve_loan"
        record.policy_decision = "BLOCKED"
        record.violation_reason = "Amount exceeded"

        formatted = formatter.format(record)
        data = json.loads(formatted)

        assert data["level"] == "WARNING"
        assert data["message"] == "Policy violation detected"
        assert data["correlation_id"] == "corr_12345"
        assert data["agent_id"] == "agent_b"
        assert data["policy_decision"] == "BLOCKED"
        assert data["violation_reason"] == "Amount exceeded"
        assert "timestamp" in data


class TestEventStore:
    def test_store_and_retrieve_events(self):
        store = EventStore()
        evt1 = EventRecord(
            correlation_id="c1",
            agent_id="agent_a",
            requested_tool="approve_loan",
            loan_amount=5000.0,
            policy_decision=PolicyDecision.ALLOWED,
            execution_status="executed",
        )
        evt2 = EventRecord(
            correlation_id="c2",
            agent_id="agent_b",
            requested_tool="override_loan_limit",
            loan_amount=50000.0,
            policy_decision=PolicyDecision.BLOCKED,
            execution_status="blocked",
            rule_triggered="RULE_TOOL_AUTHORIZATION",
        )

        store.record_event(evt1)
        store.record_event(evt2)

        # Retrieve recent (reverse order)
        recent = store.get_recent_events(limit=10)
        assert len(recent) == 2
        assert recent[0].correlation_id == "c2"
        assert recent[1].correlation_id == "c1"

        # Filter by agent
        agent_b_events = store.get_recent_events(agent_id="agent_b")
        assert len(agent_b_events) == 1
        assert agent_b_events[0].agent_id == "agent_b"

        # Filter by decision
        blocked_events = store.get_recent_events(decision="BLOCKED")
        assert len(blocked_events) == 1
        assert blocked_events[0].policy_decision == PolicyDecision.BLOCKED

    def test_violation_counts_aggregation(self):
        store = EventStore()
        store.record_event(
            EventRecord(
                correlation_id="c1",
                agent_id="agent_a",
                requested_tool="approve_loan",
                policy_decision=PolicyDecision.ALLOWED,
                execution_status="executed",
            )
        )
        store.record_event(
            EventRecord(
                correlation_id="c2",
                agent_id="agent_b",
                requested_tool="approve_loan",
                policy_decision=PolicyDecision.BLOCKED,
                execution_status="blocked",
                rule_triggered="RULE_MAX_AMOUNT_EXCEEDED",
            )
        )
        store.record_event(
            EventRecord(
                correlation_id="c3",
                agent_id="agent_b",
                requested_tool="disburse_funds",
                policy_decision=PolicyDecision.BLOCKED,
                execution_status="blocked",
                rule_triggered="RULE_TOOL_AUTHORIZATION",
            )
        )

        metrics = store.get_violation_counts()
        assert metrics["total_events"] == 3
        assert metrics["total_violations"] == 2
        assert metrics["decisions"]["ALLOWED"] == 1
        assert metrics["decisions"]["BLOCKED"] == 2
        assert metrics["violations_by_rule"]["RULE_MAX_AMOUNT_EXCEEDED"] == 1
        assert metrics["violations_by_rule"]["RULE_TOOL_AUTHORIZATION"] == 1
        assert metrics["violations_by_agent"]["agent_b"] == 2

    def test_consecutive_failure_count(self):
        store = EventStore()
        store.record_event(
            EventRecord(
                correlation_id="c1",
                agent_id="agent_b",
                requested_tool="approve_loan",
                policy_decision=PolicyDecision.BLOCKED,
                execution_status="blocked",
            )
        )
        store.record_event(
            EventRecord(
                correlation_id="c2",
                agent_id="agent_b",
                requested_tool="approve_loan",
                policy_decision=PolicyDecision.BLOCKED,
                execution_status="blocked",
            )
        )
        assert store.get_consecutive_failure_count("agent_b") == 2

        # Reset count upon an allowed event
        store.record_event(
            EventRecord(
                correlation_id="c3",
                agent_id="agent_b",
                requested_tool="reject_loan",
                policy_decision=PolicyDecision.ALLOWED,
                execution_status="executed",
            )
        )
        assert store.get_consecutive_failure_count("agent_b") == 0
