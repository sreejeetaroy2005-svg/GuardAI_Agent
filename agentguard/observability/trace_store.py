"""
Thread-safe in-memory store for AgentTrace records.

Every agent run produces exactly one AgentTrace which is stored here.
All stored traces are sanitized (PII/secrets redacted) before persistence.
"""

from __future__ import annotations

import threading
from typing import Dict, List, Optional

from agentguard.models.traces import AgentTrace
from agentguard.observability.sanitizer import sanitize_payload


class TraceStore:
    """Thread-safe storage and query interface for AgentTrace records."""

    def __init__(self, max_history: int = 1000) -> None:
        self._lock = threading.Lock()
        self._traces: Dict[str, AgentTrace] = {}
        self._order: List[str] = []   # insertion-ordered trace_ids
        self._max_history = max_history

    def add_trace(self, trace: AgentTrace) -> None:
        """
        Persist *trace* after sanitizing mutable dict fields.
        Enforces max_history by evicting the oldest trace when capacity is
        exceeded.
        """
        # Sanitize mutable dict payloads in-place before storing
        trace.llm_call_metadata = sanitize_payload(trace.llm_call_metadata)
        if trace.tool_proposal:
            trace.tool_proposal = sanitize_payload(trace.tool_proposal)
        if trace.tool_execution_result:
            trace.tool_execution_result = sanitize_payload(trace.tool_execution_result)

        with self._lock:
            self._traces[trace.trace_id] = trace
            self._order.append(trace.trace_id)
            if len(self._order) > self._max_history:
                oldest = self._order.pop(0)
                self._traces.pop(oldest, None)

    def get_traces(
        self,
        limit: int = 50,
        agent_id: Optional[str] = None,
    ) -> List[AgentTrace]:
        """
        Return traces in reverse-chronological order (most recent first).
        Optionally filter by *agent_id*.
        """
        with self._lock:
            ordered = [self._traces[tid] for tid in reversed(self._order)
                       if tid in self._traces]
        if agent_id:
            ordered = [t for t in ordered if t.agent_id == agent_id]
        return ordered[:limit]

    def get_trace_by_id(self, trace_id: str) -> Optional[AgentTrace]:
        """Return the trace with *trace_id*, or None."""
        with self._lock:
            return self._traces.get(trace_id)

    def clear(self) -> None:
        """Clear all stored traces (primarily for testing)."""
        with self._lock:
            self._traces.clear()
            self._order.clear()

    def __len__(self) -> int:
        with self._lock:
            return len(self._traces)


# Global singleton
trace_store = TraceStore()
