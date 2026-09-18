"""
Test the /health endpoint.
"""

from fastapi.testclient import TestClient

from shield.api.app import app

client = TestClient(app)


def test_health_endpoint():
    """
    TEST 7 — HEALTH
    
    GET /health
    
    Expected:
    - HTTP 200
    - Response: {"status": "ok"}
    """
    response = client.get("/health")
    
    assert response.status_code == 200
    
    result = response.json()
    
    assert result["status"] == "ok"
