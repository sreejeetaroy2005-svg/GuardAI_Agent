"""
Sanitization utility to ensure logs, audit records, and alerts never contain secrets or unnecessary PII.
"""

import re
from typing import Any, Dict, List, Union

# Common PII and Secret patterns
SENSITIVE_KEY_PATTERNS = [
    re.compile(r"password", re.IGNORECASE),
    re.compile(r"secret", re.IGNORECASE),
    re.compile(r"token", re.IGNORECASE),
    re.compile(r"key", re.IGNORECASE),
    re.compile(r"auth", re.IGNORECASE),
    re.compile(r"ssn", re.IGNORECASE),
    re.compile(r"aadhaar", re.IGNORECASE),
    re.compile(r"pan_number", re.IGNORECASE),
    re.compile(r"card_number", re.IGNORECASE),
    re.compile(r"cvv", re.IGNORECASE),
    re.compile(r"account_number", re.IGNORECASE),
]

# Sensitive value patterns (emails, credit cards, standard tokens)
EMAIL_PATTERN = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")
CREDIT_CARD_PATTERN = re.compile(r"\b(?:\d{4}[ -]?){3}\d{4}\b")
BEARER_PATTERN = re.compile(r"Bearer\s+[A-Za-z0-9\-\._~\+\/]+=*", re.IGNORECASE)

REDACTED_TEXT = "[REDACTED]"


def sanitize_string(value: str) -> str:
    """Scrub sensitive string contents such as emails, bearer tokens, or card numbers."""
    if not isinstance(value, str):
        return value
    sanitized = EMAIL_PATTERN.sub("[REDACTED_EMAIL]", value)
    sanitized = CREDIT_CARD_PATTERN.sub("[REDACTED_CARD]", sanitized)
    sanitized = BEARER_PATTERN.sub("Bearer [REDACTED_TOKEN]", sanitized)
    return sanitized


def sanitize_payload(data: Any) -> Any:
    """
    Recursively sanitize dictionaries, lists, and primitives,
    redacting values associated with sensitive keys or matching sensitive regexes.
    """
    if isinstance(data, dict):
        sanitized_dict: Dict[str, Any] = {}
        for k, v in data.items():
            # Check if key matches sensitive key patterns
            if any(pattern.search(str(k)) for pattern in SENSITIVE_KEY_PATTERNS):
                sanitized_dict[k] = REDACTED_TEXT
            else:
                sanitized_dict[k] = sanitize_payload(v)
        return sanitized_dict
    elif isinstance(data, list):
        return [sanitize_payload(item) for item in data]
    elif isinstance(data, str):
        return sanitize_string(data)
    else:
        return data
