"""
Deployment agent Cedar authorization tests.

Tests the Cedar policies governing deployment-01 agent actions.
Deployment-01 has permit policies for:
- deployment.preview on staging-environment
- deployment.deploy on production-environment

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
# TEST 6 - Deployment preview allowed
# ============================================================================

def test_6_deployment_preview_allowed(adapter):
    """deployment-01 | deployment.preview | staging-environment => ALLOW."""
    request = _make_request(
        source_agent=AgentId.DEPLOYMENT_01,
        action=ActionName.DEPLOYMENT_PREVIEW,
        resource=ResourceName.STAGING_ENVIRONMENT,
        capability=CapabilityName.DEPLOYMENT_PREVIEW,
    )
    result = adapter.evaluate(request)
    assert result == AuthorizationDecision.ALLOW


# ============================================================================
# TEST 7 - Deployment production allowed
# ============================================================================

def test_7_deployment_production_allowed(adapter):
    """deployment-01 | deployment.deploy | production-environment => ALLOW."""
    request = _make_request(
        source_agent=AgentId.DEPLOYMENT_01,
        action=ActionName.DEPLOYMENT_DEPLOY,
        resource=ResourceName.PRODUCTION_ENVIRONMENT,
        capability=CapabilityName.DEPLOYMENT_PRODUCTION,
    )
    result = adapter.evaluate(request)
    assert result == AuthorizationDecision.ALLOW


# ============================================================================
# TEST - Deployment preview against production must DENY
# ============================================================================

def test_deployment_preview_wrong_resource_denied(adapter):
    """deployment-01 | deployment.preview | production-environment => DENY.

    Deployment preview against production-environment must DENY.
    """
    request = _make_request(
        source_agent=AgentId.DEPLOYMENT_01,
        action=ActionName.DEPLOYMENT_PREVIEW,
        resource=ResourceName.PRODUCTION_ENVIRONMENT,
        capability=CapabilityName.DEPLOYMENT_PREVIEW,
    )
    result = adapter.evaluate(request)
    assert result == AuthorizationDecision.DENY


# ============================================================================
# TEST - Deployment deploy against staging must DENY
# ============================================================================

def test_deployment_deploy_wrong_resource_denied(adapter):
    """deployment-01 | deployment.deploy | staging-environment => DENY.

    Deployment deploy against staging-environment must DENY.
    """
    request = _make_request(
        source_agent=AgentId.DEPLOYMENT_01,
        action=ActionName.DEPLOYMENT_DEPLOY,
        resource=ResourceName.STAGING_ENVIRONMENT,
        capability=CapabilityName.DEPLOYMENT_PRODUCTION,
    )
    result = adapter.evaluate(request)
    assert result == AuthorizationDecision.DENY


# ============================================================================
# TEST - Deployment action on wrong resource => DENY
# ============================================================================

def test_deployment_preview_workspace_denied(adapter):
    """deployment-01 | deployment.preview | workspace => DENY.

    Deployment action on the wrong resource must DENY.
    """
    request = _make_request(
        source_agent=AgentId.DEPLOYMENT_01,
        action=ActionName.DEPLOYMENT_PREVIEW,
        resource=ResourceName.WORKSPACE,
        capability=CapabilityName.DEPLOYMENT_PREVIEW,
    )
    result = adapter.evaluate(request)
    assert result == AuthorizationDecision.DENY
