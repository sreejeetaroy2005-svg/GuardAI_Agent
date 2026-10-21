"""
In-memory thread-safe store for audit events and observability metrics.
"""

from collections import Counter
from datetime import datetime, timezone
import threading
from typing import Any, Dict, List, Optional
from agentguard.models.actions import PolicyDecision
from agentguard.models.events import EventRecord


class EventStore:
    """Thread-safe storage and query interface for AgentGuard audit events."""

    def __init__(self, max_history: int = 1000) -> None:
        self._lock = threading.Lock()
        self._events: List[EventRecord] = []
        self._max_history = max_history

    def record_event(self, event: EventRecord) -> None:
        """Append an event to the audit store."""
        with self._lock:
            self._events.append(event)
            # Retain only the most recent entries if store exceeds capacity
            if len(self._events) > self._max_history:
                self._events = self._events[-self._max_history :]

    def get_recent_events(
        self,
        limit: int = 50,
        agent_id: Optional[str] = None,
        decision: Optional[str] = None,
    ) -> List[EventRecord]:
        """Retrieve recent events in reverse chronological order with optional filtering."""
        with self._lock:
            filtered = self._events
            if agent_id:
                filtered = [e for e in filtered if e.agent_id == agent_id]
            if decision:
                filtered = [
                    e
                    for e in filtered
                    if str(e.policy_decision).upper() == decision.upper()
                    or e.policy_decision.value.upper() == decision.upper()
                ]
            # Return copies in reverse chronological order
            return list(reversed(filtered[-limit:]))

    def get_events_by_correlation_id(self, correlation_id: str) -> List[EventRecord]:
        """Retrieve all events associated with a specific correlation ID."""
        with self._lock:
            return [e for e in self._events if e.correlation_id == correlation_id]

    def get_violation_counts(self) -> Dict[str, Any]:
        """
        Aggregate violation statistics:
        - Total recorded events
        - Total allowed, blocked, escalated counts
        - Breakdown of violations by rule
        - Breakdown of violations by agent
        """
        with self._lock:
            total_events = len(self._events)
            decision_counts: Counter[str] = Counter()
            rule_counts: Counter[str] = Counter()
            agent_violation_counts: Counter[str] = Counter()

            for evt in self._events:
                # Count status
                decision_counts[evt.policy_decision.value] += 1

                # If blocked or rule triggered, track violation breakdown
                if evt.policy_decision == PolicyDecision.BLOCKED:
                    if evt.rule_triggered:
                        rule_counts[evt.rule_triggered] += 1
                    else:
                        rule_counts["UNKNOWN_VIOLATION"] += 1
                    agent_violation_counts[evt.agent_id] += 1

            return {
                "total_events": total_events,
                "decisions": dict(decision_counts),
                "violations_by_rule": dict(rule_counts),
                "violations_by_agent": dict(agent_violation_counts),
                "total_violations": sum(rule_counts.values()),
            }

    def get_consecutive_failure_count(self, agent_id: str) -> int:
        """
        Count consecutive blocked/failed actions for a specific agent
        from the most recent event backwards.
        """
        with self._lock:
            count = 0
            for evt in reversed(self._events):
                if evt.agent_id == agent_id:
                    if evt.policy_decision == PolicyDecision.BLOCKED:
                        count += 1
                    else:
                        break
            return count

    def clear(self) -> None:
        """Clear all stored events (primarily for testing)."""
        with self._lock:
            self._events.clear()


# Global singleton instance
event_store = EventStore()
