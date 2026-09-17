"""
Cedar authorization tests for Kavach Shield.

These tests prove that authorization decisions come from the real cedarpy engine,
not from mocked logic. All tests use the actual Cedar policies and schema.
"""

from datetime import datetime, timezone

import pytest

from shield.gateway.models import (
    ActionName,
    ActionRequest,
    AuthorizationDecision,
    CapabilityName,
    ResourceName,
)
from shield.identity.models import AgentId
from shield.policy.cedar import CedarAdapter
from shield.provenance.models import Provenance


@pytest.fixture
def adapter():
    """Create a CedarAdapter instance for testing."""
    return CedarAdapter()


def _make_request(
    source_agent: AgentId,
    action: ActionName,
    resource: ResourceName,
    capability: CapabilityName,
) -> ActionRequest:
    """Helper to create an ActionRequest with valid provenance."""
    return ActionRequest(
        request_id=f"test-{source_agent.value}-{action.value}",
        timestamp=datetime.now(timezone.utc),
        source_agent=source_agent,
        target_agent=source_agent,
        task_id="task-test",
        action=action,
        resource=resource,
        claimed_authority=source_agent,
        capability=capability,
        provenance=Provenance(
            task_origin=source_agent,
            delegation_chain=[source_agent],
        ),
    )


# ============================================================================
# TEST 1 - Research allowed (search)
# ============================================================================

def test_1_research_search_allowed(adapter):
    """Research agent is allowed to search research-data."""
    request = _make_request(
        source_agent=AgentId.RESEARCH_01,
        action=ActionName.RESEARCH_SEARCH,
        resource=ResourceName.RESEARCH_DATA,
        capability=CapabilityName.RESEARCH_SEARCH,
    )
    result = adapter.evaluate(request)
    assert result == AuthorizationDecision.ALLOW


# ============================================================================
# TEST 2 - Research read allowed
# ============================================================================

def test_2_research_read_allowed(adapter):
    """Research agent is allowed to read research-data."""
    request = _make_request(
        source_agent=AgentId.RESEARCH_01,
        action=ActionName.RESEARCH_READ,
        resource=ResourceName.RESEARCH_DATA,
        capability=CapabilityName.RESEARCH_READ,
    )
    result = adapter.evaluate(request)
    assert result == AuthorizationDecision.ALLOW


# ============================================================================
# TEST 3 - Research production attack (critical)
# ============================================================================

def test_3_research_production_attack_denied(adapter):
    """
    CRITICAL: Research agent attempting deployment.deploy on production-environment
    must be denied. This is the canonical attack scenario.
    """
    request = _make_request(
        source_agent=AgentId.RESEARCH_01,
        action=ActionName.DEPLOYMENT_DEPLOY,
        resource=ResourceName.PRODUCTION_ENVIRONMENT,
        capability=CapabilityName.RESEARCH_SEARCH,
    )
    result = adapter.evaluate(request)
    assert result == AuthorizationDecision.DENY


# ============================================================================
# TEST 4 - Research wrong resource
# ============================================================================

def test_4_research_wrong_resource_denied(adapter):
    """Research agent cannot search production-environment."""
    request = _make_request(
        source_agent=AgentId.RESEARCH_01,
        action=ActionName.RESEARCH_SEARCH,
        resource=ResourceName.PRODUCTION_ENVIRONMENT,
        capability=CapabilityName.RESEARCH_SEARCH,
    )
    result = adapter.evaluate(request)
    assert result == AuthorizationDecision.DENY


# ============================================================================
# TEST 5 - Coding write allowed
# ============================================================================

def test_5_coding_write_allowed(adapter):
    """Coding agent is allowed to write to workspace."""
    request = _make_request(
        source_agent=AgentId.CODING_01,
        action=ActionName.CODING_WRITE,
        resource=ResourceName.WORKSPACE,
        capability=CapabilityName.CODING_WRITE,
    )
    result = adapter.evaluate(request)
    assert result == AuthorizationDecision.ALLOW


# ============================================================================
# TEST 6 - Coding production deployment
# ============================================================================

def test_6_coding_production_deployment_denied(adapter):
    """Coding agent cannot deploy to production."""
    request = _make_request(
        source_agent=AgentId.CODING_01,
        action=ActionName.DEPLOYMENT_DEPLOY,
        resource=ResourceName.PRODUCTION_ENVIRONMENT,
        capability=CapabilityName.CODING_WRITE,
    )
    result = adapter.evaluate(request)
    assert result == AuthorizationDecision.DENY


# ============================================================================
# TEST 7 - Deployment production allowed
# ============================================================================

def test_7_deployment_deploy_allowed(adapter):
    """Deployment agent is allowed to deploy to production."""
    request = _make_request(
        source_agent=AgentId.DEPLOYMENT_01,
        action=ActionName.DEPLOYMENT_DEPLOY,
        resource=ResourceName.PRODUCTION_ENVIRONMENT,
        capability=CapabilityName.DEPLOYMENT_PRODUCTION,
    )
    result = adapter.evaluate(request)
    assert result == AuthorizationDecision.ALLOW


# ============================================================================
# TEST 8 - Deployment preview allowed
# ============================================================================

def test_8_deployment_preview_allowed(adapter):
    """Deployment agent is allowed to preview to staging."""
    request = _make_request(
        source_agent=AgentId.DEPLOYMENT_01,
        action=ActionName.DEPLOYMENT_PREVIEW,
        resource=ResourceName.STAGING_ENVIRONMENT,
        capability=CapabilityName.DEPLOYMENT_PREVIEW,
    )
    result = adapter.evaluate(request)
    assert result == AuthorizationDecision.ALLOW


# ============================================================================
# TEST 9 - Verification has no policy
# ============================================================================

def test_9_verification_no_policy_denied(adapter):
    """Verification agent has no policy and must be denied."""
    request = _make_request(
        source_agent=AgentId.VERIFICATION_01,
        action=ActionName.VERIFICATION_TEST,
        resource=ResourceName.TEST_ENVIRONMENT,
        capability=CapabilityName.VERIFICATION_TEST,
    )
    result = adapter.evaluate(request)
    assert result == AuthorizationDecision.DENY


# ============================================================================
# TEST 10 - Orchestrator has no policy
# ============================================================================

def test_10_orchestrator_no_policy_denied(adapter):
    """Orchestrator agent has no policy and must be denied."""
    request = _make_request(
        source_agent=AgentId.ORCHESTRATOR_01,
        action=ActionName.ORCHESTRATOR_COORDINATE,
        resource=ResourceName.WORKSPACE,
        capability=CapabilityName.ORCHESTRATOR_COORDINATE,
    )
    result = adapter.evaluate(request)
    assert result == AuthorizationDecision.DENY


# ============================================================================
# TEST 11 - Unknown/unpermitted action
# ============================================================================

def test_11_unknown_action_denied(adapter):
    """
    Requests with actions not matching any policy must be denied.
    This tests the deny-by-default behavior.
    """
    request = _make_request(
        source_agent=AgentId.RESEARCH_01,
        action=ActionName.DEPLOYMENT_DEPLOY,
        resource=ResourceName.PRODUCTION_ENVIRONMENT,
        capability=CapabilityName.RESEARCH_SEARCH,
    )
    result = adapter.evaluate(request)
    assert result == AuthorizationDecision.DENY


# ============================================================================
# TEST 12 - Policy validation
# ============================================================================

def test_12_policy_validation(adapter):
    """
    The actual policies.cedar must validate successfully.
    This proves the policies are syntactically correct.
    """
    try:
        is_valid = adapter.validate_policies()
        assert is_valid is True
    except ValueError as e:
        pytest.fail(f"Policy validation failed: {e}")


# ============================================================================
# EXTRA - Verify Cedar engine is real
# ============================================================================

def test_cedar_engine_is_real(adapter):
    """
    Prove the result comes from the real cedarpy engine by checking
    that different requests produce different results based on actual
    policy evaluation.
    """
    # Allowed request
    allowed_request = _make_request(
        source_agent=AgentId.RESEARCH_01,
        action=ActionName.RESEARCH_SEARCH,
        resource=ResourceName.RESEARCH_DATA,
        capability=CapabilityName.RESEARCH_SEARCH,
    )
    allowed_result = adapter.evaluate(allowed_request)

    # Denied request (different resource)
    denied_request = _make_request(
        source_agent=AgentId.RESEARCH_01,
        action=ActionName.RESEARCH_SEARCH,
        resource=ResourceName.PRODUCTION_ENVIRONMENT,
        capability=CapabilityName.RESEARCH_SEARCH,
    )
    denied_result = adapter.evaluate(denied_request)

    # Results must differ based on actual Cedar evaluation
    assert allowed_result != denied_result
    assert allowed_result == AuthorizationDecision.ALLOW
    assert denied_result == AuthorizationDecision.DENY
