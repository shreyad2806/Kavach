"""
Test request validation for the /authorize endpoint.
"""

from fastapi.testclient import TestClient

from shield.api.app import app

client = TestClient(app)


def test_authorize_missing_source_agent():
    """
    TEST 4 — INVALID BODY
    
    POST /authorize with missing source_agent.
    
    Expected:
    - HTTP 422 (validation error)
    """
    request_data = {
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
    
    assert response.status_code == 422


def test_authorize_invalid_action():
    """
    TEST 4 — INVALID BODY
    
    POST /authorize with invalid action.
    
    Expected:
    - HTTP 422 (validation error)
    """
    request_data = {
        "source_agent": "research-01",
        "target_agent": "research-01",
        "task_id": "task-001",
        "action": "invalid.action",
        "resource": "research-data",
        "claimed_authority": "research-01",
        "capability": "research.search",
        "provenance": {
            "task_origin": "research-01",
            "delegation_chain": ["research-01"],
        },
    }
    
    response = client.post("/authorize", json=request_data)
    
    assert response.status_code == 422


def test_authorize_invalid_resource():
    """
    TEST 4 — INVALID BODY
    
    POST /authorize with invalid resource.
    
    Expected:
    - HTTP 422 (validation error)
    """
    request_data = {
        "source_agent": "research-01",
        "target_agent": "research-01",
        "task_id": "task-001",
        "action": "research.search",
        "resource": "invalid-resource",
        "claimed_authority": "research-01",
        "capability": "research.search",
        "provenance": {
            "task_origin": "research-01",
            "delegation_chain": ["research-01"],
        },
    }
    
    response = client.post("/authorize", json=request_data)
    
    assert response.status_code == 422


def test_authorize_invalid_capability():
    """
    TEST 4 — INVALID BODY
    
    POST /authorize with invalid capability.
    
    Expected:
    - HTTP 422 (validation error)
    """
    request_data = {
        "source_agent": "research-01",
        "target_agent": "research-01",
        "task_id": "task-001",
        "action": "research.search",
        "resource": "research-data",
        "claimed_authority": "research-01",
        "capability": "invalid.capability",
        "provenance": {
            "task_origin": "research-01",
            "delegation_chain": ["research-01"],
        },
    }
    
    response = client.post("/authorize", json=request_data)
    
    assert response.status_code == 422


def test_authorize_malformed_provenance():
    """
    TEST 4 — INVALID BODY
    
    POST /authorize with malformed provenance.
    
    Expected:
    - HTTP 422 (validation error)
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
            "task_origin": "invalid-agent",
            "delegation_chain": ["research-01"],
        },
    }
    
    response = client.post("/authorize", json=request_data)
    
    assert response.status_code == 422
