"""
Research agent Cedar authorization tests.

Tests the Cedar policies governing research-01 agent actions.
Research-01 has permit policies for:
- research.search on research-data
- research.read on research-data

All other actions/resources are denied by default.
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
# TEST 1 - Research search allowed
# ============================================================================

def test_1_research_search_allowed(adapter):
    """research-01 | research.search | research-data => ALLOW."""
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
    """research-01 | research.read | research-data => ALLOW."""
    request = _make_request(
        source_agent=AgentId.RESEARCH_01,
        action=ActionName.RESEARCH_READ,
        resource=ResourceName.RESEARCH_DATA,
        capability=CapabilityName.RESEARCH_READ,
    )
    result = adapter.evaluate(request)
    assert result == AuthorizationDecision.ALLOW


# ============================================================================
# TEST 3 - Research attempting production deployment => DENY
# ============================================================================

def test_3_research_production_deploy_denied(adapter):
    """research-01 | deployment.deploy | production-environment => DENY."""
    request = _make_request(
        source_agent=AgentId.RESEARCH_01,
        action=ActionName.DEPLOYMENT_DEPLOY,
        resource=ResourceName.PRODUCTION_ENVIRONMENT,
        capability=CapabilityName.RESEARCH_SEARCH,
    )
    result = adapter.evaluate(request)
    assert result == AuthorizationDecision.DENY


# ============================================================================
# TEST - Research action on wrong resource => DENY
# ============================================================================

def test_research_search_wrong_resource_denied(adapter):
    """research-01 | research.search | production-environment => DENY.

    Research action on the wrong resource must DENY.
    """
    request = _make_request(
        source_agent=AgentId.RESEARCH_01,
        action=ActionName.RESEARCH_SEARCH,
        resource=ResourceName.PRODUCTION_ENVIRONMENT,
        capability=CapabilityName.RESEARCH_SEARCH,
    )
    result = adapter.evaluate(request)
    assert result == AuthorizationDecision.DENY


def test_research_read_wrong_resource_denied(adapter):
    """research-01 | research.read | workspace => DENY.

    Research action on the wrong resource must DENY.
    """
    request = _make_request(
        source_agent=AgentId.RESEARCH_01,
        action=ActionName.RESEARCH_READ,
        resource=ResourceName.WORKSPACE,
        capability=CapabilityName.RESEARCH_READ,
    )
    result = adapter.evaluate(request)
    assert result == AuthorizationDecision.DENY
