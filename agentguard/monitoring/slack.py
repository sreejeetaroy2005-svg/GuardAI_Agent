"""
Slack webhook integration for AgentGuard alerts.
Sends formatted alerts to Slack when configured, and falls back gracefully to local logging.
"""

import logging
from typing import Optional
import httpx
from agentguard.models.incidents import IncidentRecord

logger = logging.getLogger("agentguard.monitoring.slack")


def send_slack_alert(webhook_url: Optional[str], incident: IncidentRecord) -> bool:
    """
    Dispatch an incident notification to a Slack incoming webhook.

    Guarantees:
    - If webhook_url is None or empty: logs locally, does not raise.
    - If Slack network or HTTP request fails: logs warning locally, does not raise.
    - Never raises an unhandled exception that could disrupt application flow.
    """
    if not webhook_url or not webhook_url.strip():
        logger.info(
            "Slack webhook not configured; alert recorded locally. Incident ID: %s",
            incident.incident_id,
        )
        return False

    # Slack message payload with structured blocks
    severity_emoji = {
        "LOW": "ℹ️",
        "MEDIUM": "⚠️",
        "HIGH": "🚨",
        "CRITICAL": "🔥",
    }.get(incident.severity.value, "⚠️")

    payload = {
        "text": f"{severity_emoji} *AgentGuard Incident Alert [{incident.severity.value}]*: {incident.reason}",
        "blocks": [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"{severity_emoji} AgentGuard Security Alert - {incident.severity.value}",
                    "emoji": True,
                },
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Incident ID:*\n`{incident.incident_id}`"},
                    {"type": "mrkdwn", "text": f"*Agent ID:*\n`{incident.agent_id}`"},
                    {"type": "mrkdwn", "text": f"*Correlation ID:*\n`{incident.correlation_id}`"},
                    {"type": "mrkdwn", "text": f"*Severity:*\n*{incident.severity.value}*"},
                ],
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Violation Reason:*\n{incident.reason}",
                },
            },
        ],
    }

    if incident.kill_switch_triggered:
        payload["blocks"].append(
            {
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": "🛑 *KILL SWITCH ACTIVATED*: Automated loan approvals have been halted system-wide.",
                    }
                ],
            }
        )

    try:
        # Synchronous POST to Slack webhook with reasonable timeout
        response = httpx.post(webhook_url, json=payload, timeout=4.0)
        if response.status_code == 200:
            logger.info("Slack alert successfully delivered for incident %s", incident.incident_id)
            return True
        else:
            logger.warning(
                "Slack webhook responded with non-200 code: %d %s",
                response.status_code,
                response.text,
            )
            return False
    except httpx.RequestError as exc:
        logger.warning(
            "Network error communicating with Slack webhook (%s): %s. Alert recorded locally.",
            webhook_url,
            exc,
        )
        return False
    except Exception as exc:
        logger.warning(
            "Unexpected error sending Slack notification for incident %s: %s",
            incident.incident_id,
            exc,
        )
        return False
