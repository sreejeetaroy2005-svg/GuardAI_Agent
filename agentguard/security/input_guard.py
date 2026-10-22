"""
UntrustedInputGuard for AgentGuard.

Detects common prompt-injection patterns in user-supplied free text and document
content.  When an injection is detected the guard:
  1. Records a SecurityEvent (severity HIGH) to the observability store.
  2. Returns an InjectionScanResult with full details.

Architectural guarantees:
- The guard NEVER modifies policy thresholds, tool permissions, confidence scores,
  agent roles, or kill-switch state.
- Detection is purely informational; the request continues through the normal
  policy pipeline unchanged.
- The guard is synchronous and deterministic (regex-based, no LLM).
"""

from __future__ import annotations

import hashlib
import logging
import re
import uuid
from datetime import datetime, timezone
from typing import List, Optional

from pydantic import BaseModel, Field

logger = logging.getLogger("agentguard.security.input_guard")


# ---------------------------------------------------------------------------
# Injection pattern catalogue
# ---------------------------------------------------------------------------

_RAW_PATTERNS: List[str] = [
    r"ignore\s+(previous|prior|all)\s+instructions?",
    r"you\s+are\s+now\s+(an?\s+)?administrator",
    r"disable\s+monitoring",
    r"approve\s+this\s+loan",
    r"override\s+policy",
    r"act\s+as\s+(bank\s+)?admin",
    r"disregard\s+(previous|prior|all)\s+instructions?",
    r"forget\s+(everything|all)\s+(above|previous)",
    r"new\s+system\s+prompt",
    r"jailbreak",
    r"bypass\s+(security|policy|restrictions?|controls?)",
    r"execute\s+(this\s+)?command",
    r"you\s+are\s+now\s+in\s+(developer|god|admin)\s+mode",
    r"human_approved\s*=\s*true",
]

INJECTION_PATTERNS: List[re.Pattern[str]] = [
    re.compile(p, re.IGNORECASE | re.DOTALL) for p in _RAW_PATTERNS
]


# ---------------------------------------------------------------------------
# Result model
# ---------------------------------------------------------------------------

class InjectionScanResult(BaseModel):
    """Result of scanning a single text field for injection patterns."""

    detected: bool = Field(
        ...,
        description="True if one or more injection patterns were matched.",
    )
    source: str = Field(
        ...,
        description="Label identifying the scanned field (e.g., 'free_text_request', 'document_text').",
    )
    patterns_matched: List[str] = Field(
        default_factory=list,
        description="List of raw pattern strings that triggered a match.",
    )
    input_text_hash: str = Field(
        ...,
        description="SHA-256 hex digest of the (sanitized) scanned text for audit traceability.",
    )
    scanned_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
    )

    @property
    def is_clean(self) -> bool:
        """Convenience inverse of `detected`."""
        return not self.detected


# ---------------------------------------------------------------------------
# Security event – lightweight record written to the observability store
# ---------------------------------------------------------------------------

class SecurityEvent(BaseModel):
    """Structured record of a detected security event, stored in the event store."""

    event_id: str = Field(
        default_factory=lambda: f"sec_{uuid.uuid4().hex[:12]}",
    )
    severity: str = Field(default="HIGH")
    event_type: str = Field(default="prompt_injection_detected")
    source: str = Field(...)
    patterns_matched: List[str] = Field(default_factory=list)
    input_text_hash: str = Field(...)
    agent_id: Optional[str] = Field(default=None)
    correlation_id: Optional[str] = Field(default=None)
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
    )
    note: str = Field(
        default=(
            "Injection detected; request continues through normal policy pipeline. "
            "Input cannot alter policy thresholds, tool permissions, confidence scores, "
            "agent role, or kill-switch state."
        )
    )


# ---------------------------------------------------------------------------
# Main guard class
# ---------------------------------------------------------------------------

class UntrustedInputGuard:
    """
    Scan user-supplied text for prompt-injection patterns.

    Usage::

        guard = UntrustedInputGuard()
        result = guard.scan(text="ignore previous instructions", source="free_text_request")
        if result.detected:
            # SecurityEvent already written to the observability store
            ...
    """

    def __init__(
        self,
        patterns: Optional[List[re.Pattern[str]]] = None,
    ) -> None:
        self._patterns = patterns if patterns is not None else INJECTION_PATTERNS

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan(
        self,
        text: str,
        source: str,
        agent_id: Optional[str] = None,
        correlation_id: Optional[str] = None,
    ) -> InjectionScanResult:
        """
        Scan *text* for injection patterns.

        Always returns an `InjectionScanResult`.  If injection is detected a
        `SecurityEvent` is written to the observability store and a WARNING is
        emitted to the structured audit log.

        Parameters
        ----------
        text:           The raw user-controlled string to inspect.
        source:         A label for the field being inspected (used in the
                        SecurityEvent and audit log).
        agent_id:       Optional agent identifier for correlation.
        correlation_id: Optional correlation ID for the current request.
        """
        if not isinstance(text, str):
            text = str(text)

        text_hash = _sha256(text)
        matched: List[str] = []

        for pattern in self._patterns:
            if pattern.search(text):
                matched.append(pattern.pattern)

        result = InjectionScanResult(
            detected=bool(matched),
            source=source,
            patterns_matched=matched,
            input_text_hash=text_hash,
        )

        if result.detected:
            self._record_security_event(result, agent_id, correlation_id)

        return result

    def scan_many(
        self,
        fields: dict[str, str],
        agent_id: Optional[str] = None,
        correlation_id: Optional[str] = None,
    ) -> List[InjectionScanResult]:
        """
        Scan multiple labelled text fields and return a result per field.
        Convenience wrapper around `scan`.
        """
        results: List[InjectionScanResult] = []
        for source, text in fields.items():
            if text:
                results.append(self.scan(text, source, agent_id, correlation_id))
        return results

    def any_injection(self, results: List[InjectionScanResult]) -> bool:
        """Return True if any result in *results* has detected=True."""
        return any(r.detected for r in results)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _record_security_event(
        self,
        result: InjectionScanResult,
        agent_id: Optional[str],
        correlation_id: Optional[str],
    ) -> None:
        """Write a SecurityEvent to the observability store and audit log."""
        sec_event = SecurityEvent(
            source=result.source,
            patterns_matched=result.patterns_matched,
            input_text_hash=result.input_text_hash,
            agent_id=agent_id,
            correlation_id=correlation_id,
        )

        # Structured audit log warning
        logger.warning(
            "PROMPT INJECTION DETECTED in field '%s' – severity HIGH. "
            "Request continues through normal policy pipeline.",
            result.source,
            extra={
                "event_id": sec_event.event_id,
                "severity": sec_event.severity,
                "event_type": sec_event.event_type,
                "source": result.source,
                "patterns_matched": result.patterns_matched,
                "input_text_hash": result.input_text_hash,
                "agent_id": agent_id,
                "correlation_id": correlation_id,
            },
        )

        # Persist to the observability store as a structured security record.
        # We import lazily to avoid circular imports at module load time.
        try:
            from agentguard.observability.store import event_store
            from agentguard.models.events import EventRecord
            from agentguard.models.actions import PolicyDecision

            security_record = EventRecord(
                correlation_id=correlation_id or f"sec_{sec_event.event_id}",
                agent_id=agent_id or "unknown",
                requested_tool="[none – input_guard scan]",
                policy_decision=PolicyDecision.BLOCKED,  # Provisional; policy runs later
                execution_status="injection_detected",
                violation_reason=(
                    f"Prompt injection detected in '{result.source}': "
                    f"patterns={result.patterns_matched}"
                ),
                metadata={
                    "event_type": sec_event.event_type,
                    "severity": sec_event.severity,
                    "source": result.source,
                    "patterns_matched": result.patterns_matched,
                    "input_text_hash": result.input_text_hash,
                },
            )
            event_store.record_event(security_record)
        except Exception as exc:  # pragma: no cover
            logger.error(
                "Failed to persist security event to store: %s", exc, exc_info=True
            )


# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------

def _sha256(text: str) -> str:
    """Return the SHA-256 hex digest of *text* encoded as UTF-8."""
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


# Module-level singleton
input_guard = UntrustedInputGuard()
