"""
Structured JSON logging for AgentGuard.
Outputs single-line JSON log entries enriched with correlation ID, agent ID, and sanitized payload.
"""

from datetime import datetime, timezone
import json
import logging
from typing import Any, Dict, Optional
from agentguard.observability.sanitizer import sanitize_payload


class JSONLogFormatter(logging.Formatter):
    """Formats log records as structured, single-line JSON objects."""

    def format(self, record: logging.LogRecord) -> str:
        log_payload: Dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        # Enrich with contextual attributes if present on the record
        for attr in [
            "correlation_id",
            "agent_id",
            "requested_tool",
            "loan_id",
            "loan_amount",
            "confidence",
            "policy_decision",
            "execution_status",
            "violation_reason",
            "rule_triggered",
            "incident_id",
            "severity",
        ]:
            val = getattr(record, attr, None)
            if val is not None:
                log_payload[attr] = val

        # Include extra payload if present
        extra = getattr(record, "extra_payload", None)
        if isinstance(extra, dict):
            log_payload["details"] = extra

        # Sanitize entire output against secrets and PII
        sanitized_payload = sanitize_payload(log_payload)
        return json.dumps(sanitized_payload, default=str)


def setup_logger(name: str = "agentguard", level: str = "INFO") -> logging.Logger:
    """Configures and returns a structured JSON logger."""
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))

    # Avoid duplicate handlers if already initialized
    if not any(isinstance(h, logging.StreamHandler) for h in logger.handlers):
        handler = logging.StreamHandler()
        handler.setFormatter(JSONLogFormatter())
        logger.addHandler(handler)

    logger.propagate = False
    return logger


# Default logger instance
audit_logger = setup_logger("agentguard.audit")
