"""
Test the mock Research Agent against the Kavach authorization gateway.

These tests exercise end-to-end behavior through:
Mock Agent → POST /authorize → Kavach → Decision → Mock Agent
"""

from fastapi.testclient import TestClient

from shield.api.app import app, get_identity_service
from shield.detection.signals import SIGNAL_WEIGHTS
from shield.gateway.models import ReasonCode
from shield.identity.models import AgentId, SecurityState
from shield.identity.service import IdentityService
from tests.mock_agents.research_agent import MockResearchAgent


client = TestClient(app)


def test_request_a_normal_research_is_allowed():
    """
    TEST REQUEST A — NORMAL RESEARCH
    
    Legitimate research activity should be ALLOWED.
    
    Assert:
    - HTTP 200
    - decision == ALLOW
    - request_id exists
    - agent_state == ACTIVE
    """
    agent = MockResearchAgent(client)
    result = agent.request_a_normal_research()
    
    assert result["decision"] == "ALLOW"
    assert "request_id" in result
    assert result["agent_state"] == "ACTIVE"


def test_request_b_research_production_deploy_is_denied():
    """
    TEST REQUEST B — PRODUCTION DEPLOYMENT ATTEMPT
    
    Research agent attempting deployment.deploy should be DENIED.
    
    Assert:
    - HTTP 200
    - decision == DENY
    - CAPABILITY_MISMATCH in reason_codes
    - PRIVILEGE_ESCALATION in reason_codes
    - POLICY_DENIED in reason_codes
    - risk_score equals the actual sum of triggered detection signals
    """
    agent = MockResearchAgent(client)
    result = agent.request_b_production_deployment()
    
    assert result["decision"] == "DENY"
    assert "CAPABILITY_MISMATCH" in result["reason_codes"]
    assert "PRIVILEGE_ESCALATION" in result["reason_codes"]
    assert "POLICY_DENIED" in result["reason_codes"]
    
    # Calculate sum of triggered detection signals based on Phase 11 weights
    expected_risk = sum(
        SIGNAL_WEIGHTS[ReasonCode(code)]
        for code in result["reason_codes"]
        if code in [r.value for r in ReasonCode] and ReasonCode(code) in SIGNAL_WEIGHTS
    )
    assert result["risk_score"] == expected_risk


def test_request_c_authority_mismatch_is_denied():
    """
    TEST REQUEST C — AUTHORITY MISMATCH
    
    Claimed authority not in delegation chain should be DENIED.
    
    Assert:
    - HTTP 200
    - decision == DENY
    - AUTHORITY_MISMATCH in reason_codes
    """
    agent = MockResearchAgent(client)
    result = agent.request_c_authority_mismatch()
    
    assert result["decision"] == "DENY"
    assert "AUTHORITY_MISMATCH" in result["reason_codes"]


def test_request_d_unknown_agent_is_denied():
    """
    TEST REQUEST D — UNKNOWN AGENT
    
    Unknown agent cannot receive ALLOW.
    
    Assert:
    - unknown agent cannot receive ALLOW
    - expected identity failure behavior is preserved
    
    Note: If ActionRequest constrains source_agent to known IDs,
    this will fail validation (HTTP 422) before reaching Kavach.
    This is acceptable as it prevents unknown agents from receiving ALLOW.
    """
    agent = MockResearchAgent(client)
    result = agent.request_d_unknown_agent()
    
    # If validation failed at API boundary, that's acceptable
    if result.get("status") == "validation_failed":
        # Unknown agent was rejected before reaching Kavach
        assert True
    else:
        # Request reached Kavach and was denied
        assert result["decision"] == "DENY"
        assert "IDENTITY_FAILURE" in result["reason_codes"]


def test_request_e_quarantined_research_is_denied():
    """
    TEST REQUEST E — QUARANTINED RESEARCH AGENT
    
    Normal research request from quarantined agent should be DENY.
    
    Assert:
    - HTTP 200
    - decision == DENY
    - AGENT_QUARANTINED in reason_codes
    - agent_state == QUARANTINED
    
    After test: restore research-01 to ACTIVE and clear dependency override.
    """
    identity_service = IdentityService()
    app.dependency_overrides[get_identity_service] = lambda: identity_service
    
    # Save original state
    original_state = identity_service.get_agent(AgentId.RESEARCH_01).state
    
    try:
        # Set research-01 to QUARANTINED
        identity_service.set_state(AgentId.RESEARCH_01, SecurityState.QUARANTINED)
        
        # Send request
        agent = MockResearchAgent(client)
        result = agent.request_e_quarantined_agent()
        
        assert result["decision"] == "DENY"
        assert "AGENT_QUARANTINED" in result["reason_codes"]
        assert result["agent_state"] == "QUARANTINED"
        
    finally:
        # Restore research-01 to original state
        identity_service.set_state(AgentId.RESEARCH_01, original_state)
        app.dependency_overrides.clear()
        
        # Verify restoration
        current_state = identity_service.get_agent(AgentId.RESEARCH_01).state
        assert current_state == original_state
        assert current_state == SecurityState.ACTIVE
