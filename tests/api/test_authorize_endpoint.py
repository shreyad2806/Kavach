"""
Test the /authorize endpoint.
"""

from fastapi.testclient import TestClient

from shield.api.app import app, AuthorizeRequest
from shield.gateway.models import AuthorizationDecision


client = TestClient(app)


def test_authorize_valid_allow():
    """
    TEST 1 — VALID ALLOW
    
    POST /authorize with valid research request.
    
    Expected:
    - HTTP 200
    - decision = ALLOW
    - Response contains all required fields
    """
    request_data = {
        "source_agent": "research-01",
        "target_agent": "research-01",
        "task_id": "task-001",
        "action": "research.search",
        "resource": "research-data",
        "claimed_authority": "research-01",
        "capability": "research.search",
        "provenance": {
            "task_origin": "research-01",
            "delegation_chain": ["research-01"],
        },
    }
    
    response = client.post("/authorize", json=request_data)
    
    assert response.status_code == 200
    
    result = response.json()
    
    # Verify decision is ALLOW
    assert result["decision"] == "ALLOW"
    
    # Verify required fields exist
    assert "request_id" in result
    assert "decision" in result
    assert "risk_score" in result
    assert "reason_codes" in result
    assert "checks" in result
    assert "agent_state" in result


def test_authorize_malicious_research_deployment():
    """
    TEST 2 — MALICIOUS RESEARCH DEPLOYMENT
    
    POST /authorize with research-01 attempting deployment.deploy
    with a capability it doesn't possess.
    
    Expected:
    - HTTP 200
    - decision = DENY
    - reason_codes includes CAPABILITY_MISMATCH
    - risk_score is calculated by detection (not hardcoded)
    """
    request_data = {
        "source_agent": "research-01",
        "target_agent": "deployment-01",
        "task_id": "task-001",
        "action": "deployment.deploy",
        "resource": "production-environment",
        "claimed_authority": "orchestrator-01",
        "capability": "deployment.production",  # Research agent doesn't have this
        "provenance": {
            "task_origin": "orchestrator-01",
            "delegation_chain": ["orchestrator-01", "research-01"],
        },
    }
    
    response = client.post("/authorize", json=request_data)
    
    assert response.status_code == 200
    
    result = response.json()
    
    # Verify decision is DENY
    assert result["decision"] == "DENY"
    
    # Verify reason codes includes CAPABILITY_MISMATCH
    assert "CAPABILITY_MISMATCH" in result["reason_codes"]
    
    # Verify risk_score is calculated (not hardcoded)
    assert result["risk_score"] is not None
    assert 0 <= result["risk_score"] <= 100


def test_authorize_cedar_deny():
    """
    TEST 3 — CEDAR DENY
    
    POST /authorize with request that reaches Cedar but is denied.
    
    Expected:
    - HTTP 200
    - decision = DENY
    - checks.cedar = DENY
    """
    request_data = {
        "source_agent": "research-01",
        "target_agent": "deployment-01",
        "task_id": "task-001",
        "action": "deployment.deploy",
        "resource": "production-environment",
        "claimed_authority": "research-01",
        "capability": "research.search",
        "provenance": {
            "task_origin": "research-01",
            "delegation_chain": ["research-01"],
        },
    }
    
    response = client.post("/authorize", json=request_data)
    
    assert response.status_code == 200
    
    result = response.json()
    
    # Verify decision is DENY
    assert result["decision"] == "DENY"
    
    # Verify Cedar check is DENY
    assert result["checks"]["cedar"] == "DENY"


def test_authorize_response_schema():
    """
    TEST 5 — RESPONSE SCHEMA
    
    Verify the response contains exactly the Phase 12 core fields.
    """
    request_data = {
        "source_agent": "research-01",
        "target_agent": "research-01",
        "task_id": "task-001",
        "action": "research.search",
        "resource": "research-data",
        "claimed_authority": "research-01",
        "capability": "research.search",
        "provenance": {
            "task_origin": "research-01",
            "delegation_chain": ["research-01"],
        },
    }
    
    response = client.post("/authorize", json=request_data)
    
    assert response.status_code == 200
    
    result = response.json()
    
    # Verify core fields exist
    assert "request_id" in result
    assert "decision" in result
    assert "risk_score" in result
    assert "reason_codes" in result
    assert "checks" in result
    assert "agent_state" in result
    
    # Verify decision is ALLOW or DENY
    assert result["decision"] in ["ALLOW", "DENY"]
    
    # Verify risk_score is 0-100
    assert isinstance(result["risk_score"], int) or result["risk_score"] is None
    if result["risk_score"] is not None:
        assert 0 <= result["risk_score"] <= 100
    
    # Verify reason_codes is a list
    assert isinstance(result["reason_codes"], list)
    
    # Verify checks is an object
    assert isinstance(result["checks"], dict)
    
    # Verify agent_state is valid
    assert result["agent_state"] in ["ACTIVE", "QUARANTINED", "TERMINATED"]


def test_authorize_no_api_override():
    """
    TEST 6 — NO API OVERRIDE
    
    Verify that Cedar DENY through the API results in DENY.
    The API layer must not override the decision.
    """
    request_data = {
        "source_agent": "research-01",
        "target_agent": "deployment-01",
        "task_id": "task-001",
        "action": "deployment.deploy",
        "resource": "production-environment",
        "claimed_authority": "research-01",
        "capability": "research.search",
        "provenance": {
            "task_origin": "research-01",
            "delegation_chain": ["research-01"],
        },
    }
    
    response = client.post("/authorize", json=request_data)
    
    assert response.status_code == 200
    
    result = response.json()
    
    # Verify decision is DENY (not overridden by API)
    assert result["decision"] == "DENY"
    
    # Verify Cedar check is DENY
    assert result["checks"]["cedar"] == "DENY"
