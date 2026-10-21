"""
Integration tests for FastAPI endpoints in AgentGuard.
Validates HTTP request and response structures, error handling,
agent runs, and observability endpoints using FastAPI TestClient.
"""

from fastapi.testclient import TestClient
import pytest


class TestHealthEndpoint:
    def test_health_check_returns_healthy_status(self, client: TestClient):
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert "version" in data
        assert "kill_switch_active" in data
        assert data["policy_thresholds"]["max_auto_approve_amount"] == 10000.0
        assert data["policy_thresholds"]["min_confidence_threshold"] == 0.80


class TestProposalEvaluationEndpoint:
    def test_evaluate_valid_proposal(self, client: TestClient):
        payload = {
            "correlation_id": "api_test_01",
            "agent_id": "test_agent",
            "tool": "approve_loan",
            "loan_id": "LOAN_API_01",
            "amount": 7500.0,
            "confidence": 0.88,
            "metadata": {"source": "api_test"},
        }
        response = client.post("/api/v1/proposals/evaluate", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert data["executed"] is True
        assert data["policy_decision"] == "ALLOWED"
        assert data["result_data"]["status"] == "APPROVED"

    def test_evaluate_blocked_proposal(self, client: TestClient):
        payload = {
            "correlation_id": "api_test_02",
            "agent_id": "test_agent",
            "tool": "approve_loan",
            "loan_id": "LOAN_API_02",
            "amount": 25000.0,
            "confidence": 0.95,
        }
        response = client.post("/api/v1/proposals/evaluate", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert data["executed"] is False
        assert data["policy_decision"] == "BLOCKED"
        assert "exceeds autonomous limit" in data["violation_reason"].lower()


class TestAgentEndpoints:
    def test_run_agent_a_eligible(self, client: TestClient):
        payload = {
            "loan_id": "LOAN_A_TEST",
            "amount": 9000.0,
            "confidence": 0.92,
        }
        response = client.post("/api/v1/agents/agent-a/run", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert data["executed"] is True
        assert data["policy_decision"] == "ALLOWED"

    def test_run_agent_a_high_value_escalates(self, client: TestClient):
        payload = {
            "loan_id": "LOAN_A_HV",
            "amount": 40000.0,
            "confidence": 0.99,
        }
        response = client.post("/api/v1/agents/agent-a/run", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert data["executed"] is False
        assert data["policy_decision"] == "ESCALATED"
        assert data["result_data"]["routing"] == "HUMAN_APPROVAL_QUEUE"

    @pytest.mark.parametrize(
        "scenario,expected_decision,expected_executed",
        [
            ("compliant", "ALLOWED", True),
            ("high_value_bypass", "BLOCKED", False),
            ("low_confidence", "BLOCKED", False),
            ("unauthorized_tool", "BLOCKED", False),
            ("malformed_confidence", "BLOCKED", False),
            ("malformed_amount", "BLOCKED", False),
        ],
    )
    def test_run_agent_b_scenarios(
        self, client: TestClient, scenario: str, expected_decision: str, expected_executed: bool
    ):
        payload = {"scenario": scenario}
        response = client.post("/api/v1/agents/agent-b/run", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 1
        assert data[0]["policy_decision"] == expected_decision
        assert data[0]["executed"] is expected_executed

    def test_run_agent_b_repeated_attacks(self, client: TestClient):
        payload = {"scenario": "repeated_attacks", "repeat_count": 3}
        response = client.post("/api/v1/agents/agent-b/run", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 3
        for item in data:
            assert item["policy_decision"] == "BLOCKED"
            assert item["executed"] is False


class TestObservabilityAndMonitoringEndpoints:
    def test_events_and_violations_endpoints(self, client: TestClient):
        # Generate some events first
        client.post("/api/v1/agents/agent-a/run", json={"amount": 5000.0, "confidence": 0.90})
        client.post("/api/v1/agents/agent-b/run", json={"scenario": "high_value_bypass"})

        # Get events
        events_resp = client.get("/api/v1/observability/events?limit=10")
        assert events_resp.status_code == 200
        events = events_resp.json()
        assert len(events) >= 2

        # Get violations
        violations_resp = client.get("/api/v1/observability/violations")
        assert violations_resp.status_code == 200
        metrics = violations_resp.json()
        assert metrics["total_events"] >= 2
        assert metrics["total_violations"] >= 1

        # Get incidents
        incidents_resp = client.get("/api/v1/monitoring/incidents")
        assert incidents_resp.status_code == 200
        incidents = incidents_resp.json()
        assert len(incidents) >= 1

    def test_kill_switch_endpoints(self, client: TestClient):
        # Check initial
        get_resp = client.get("/api/v1/monitoring/kill-switch")
        assert get_resp.status_code == 200
        assert get_resp.json()["kill_switch_active"] is False

        # Activate
        toggle_resp = client.post(
            "/api/v1/monitoring/kill-switch",
            json={"active": True, "reason": "Emergency security testing"},
        )
        assert toggle_resp.status_code == 200
        assert toggle_resp.json()["kill_switch_active"] is True

        # Verify automated approval is blocked while kill switch active
        eval_resp = client.post(
            "/api/v1/agents/agent-a/run",
            json={"amount": 5000.0, "confidence": 0.95},
        )
        assert eval_resp.json()["policy_decision"] == "BLOCKED"
        assert eval_resp.json()["executed"] is False

        # Deactivate
        toggle_off = client.post(
            "/api/v1/monitoring/kill-switch",
            json={"active": False, "reason": "Testing complete"},
        )
        assert toggle_off.status_code == 200
        assert toggle_off.json()["kill_switch_active"] is False

    def test_reset_endpoint(self, client: TestClient):
        # Trigger an action
        client.post("/api/v1/agents/agent-b/run", json={"scenario": "high_value_bypass"})

        # Reset
        reset_resp = client.post("/api/v1/monitoring/reset")
        assert reset_resp.status_code == 200

        # Verify stores cleared
        events = client.get("/api/v1/observability/events").json()
        incidents = client.get("/api/v1/monitoring/incidents").json()
        assert len(events) == 0
        assert len(incidents) == 0
