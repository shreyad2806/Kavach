"""
Default deny Cedar authorization tests.

Tests that agents without permit policies are denied by default.
Cedar is deny-by-default: any request without a matching permit is denied.

Agents without policies:
- orchestrator-01
- verification-01

Resource boundary tests:
- Research action on the wrong resource => DENY
- Coding action on the wrong resource => DENY
- Deployment preview against production => DENY
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
# TEST 8 - Verification attempting production deployment => DENY
# ============================================================================

def test_8_verification_deploy_denied(adapter):
    """verification-01 | deployment.deploy | production-environment => DENY."""
    request = _make_request(
        source_agent=AgentId.VERIFICATION_01,
        action=ActionName.DEPLOYMENT_DEPLOY,
        resource=ResourceName.PRODUCTION_ENVIRONMENT,
        capability=CapabilityName.VERIFICATION_TEST,
    )
    result = adapter.evaluate(request)
    assert result == AuthorizationDecision.DENY


# ============================================================================
# TEST 9 - Unknown/unpermitted principal => DENY
# ============================================================================

def test_9_orchestrator_no_policy_denied(adapter):
    """orchestrator-01 | orchestrator.coordinate | workspace => DENY.

    Orchestrator has no Cedar permit policy.
    """
    request = _make_request(
        source_agent=AgentId.ORCHESTRATOR_01,
        action=ActionName.ORCHESTRATOR_COORDINATE,
        resource=ResourceName.WORKSPACE,
        capability=CapabilityName.ORCHESTRATOR_COORDINATE,
    )
    result = adapter.evaluate(request)
    assert result == AuthorizationDecision.DENY


def test_9_verification_no_policy_denied(adapter):
    """verification-01 | verification.test | test-environment => DENY.

    Verification has no Cedar permit policy.
    """
    request = _make_request(
        source_agent=AgentId.VERIFICATION_01,
        action=ActionName.VERIFICATION_TEST,
        resource=ResourceName.TEST_ENVIRONMENT,
        capability=CapabilityName.VERIFICATION_TEST,
    )
    result = adapter.evaluate(request)
    assert result == AuthorizationDecision.DENY


def test_9_orchestrator_delegate_denied(adapter):
    """orchestrator-01 | orchestrator.delegate | research-data => DENY.

    Orchestrator delegate action has no Cedar permit policy.
    """
    request = _make_request(
        source_agent=AgentId.ORCHESTRATOR_01,
        action=ActionName.ORCHESTRATOR_DELEGATE,
        resource=ResourceName.RESEARCH_DATA,
        capability=CapabilityName.ORCHESTRATOR_DELEGATE,
    )
    result = adapter.evaluate(request)
    assert result == AuthorizationDecision.DENY


# ============================================================================
# TEST - Canonical unpermitted action with agent that has no policy => DENY
# ============================================================================

def test_unpermitted_action_research_deploy_denied(adapter):
    """research-01 | deployment.deploy | production-environment => DENY.

    Canonical unpermitted action: research-01 has no policy for deployment.deploy.
    This is the canonical attack scenario.
    """
    request = _make_request(
        source_agent=AgentId.RESEARCH_01,
        action=ActionName.DEPLOYMENT_DEPLOY,
        resource=ResourceName.PRODUCTION_ENVIRONMENT,
        capability=CapabilityName.RESEARCH_SEARCH,
    )
    result = adapter.evaluate(request)
    assert result == AuthorizationDecision.DENY


def test_unpermitted_action_coding_deploy_denied(adapter):
    """coding-01 | deployment.deploy | production-environment => DENY.

    Coding agent has no policy for deployment.deploy.
    """
    request = _make_request(
        source_agent=AgentId.CODING_01,
        action=ActionName.DEPLOYMENT_DEPLOY,
        resource=ResourceName.PRODUCTION_ENVIRONMENT,
        capability=CapabilityName.CODING_WRITE,
    )
    result = adapter.evaluate(request)
    assert result == AuthorizationDecision.DENY
