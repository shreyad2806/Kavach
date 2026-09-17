"""
Coding agent Cedar authorization tests.

Tests the Cedar policies governing coding-01 agent actions.
Coding-01 has permit policies for:
- coding.read on workspace
- coding.write on workspace
- coding.test on test-environment

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
# TEST 4 - Coding write allowed
# ============================================================================

def test_4_coding_write_allowed(adapter):
    """coding-01 | coding.write | workspace => ALLOW."""
    request = _make_request(
        source_agent=AgentId.CODING_01,
        action=ActionName.CODING_WRITE,
        resource=ResourceName.WORKSPACE,
        capability=CapabilityName.CODING_WRITE,
    )
    result = adapter.evaluate(request)
    assert result == AuthorizationDecision.ALLOW


# ============================================================================
# TEST 5 - Coding attempting production deployment => DENY
# ============================================================================

def test_5_coding_production_deploy_denied(adapter):
    """coding-01 | deployment.deploy | production-environment => DENY."""
    request = _make_request(
        source_agent=AgentId.CODING_01,
        action=ActionName.DEPLOYMENT_DEPLOY,
        resource=ResourceName.PRODUCTION_ENVIRONMENT,
        capability=CapabilityName.CODING_WRITE,
    )
    result = adapter.evaluate(request)
    assert result == AuthorizationDecision.DENY


# ============================================================================
# TEST - Coding action on wrong resource => DENY
# ============================================================================

def test_coding_write_wrong_resource_denied(adapter):
    """coding-01 | coding.write | production-environment => DENY.

    Coding action on the wrong resource must DENY.
    """
    request = _make_request(
        source_agent=AgentId.CODING_01,
        action=ActionName.CODING_WRITE,
        resource=ResourceName.PRODUCTION_ENVIRONMENT,
        capability=CapabilityName.CODING_WRITE,
    )
    result = adapter.evaluate(request)
    assert result == AuthorizationDecision.DENY


def test_coding_read_wrong_resource_denied(adapter):
    """coding-01 | coding.read | research-data => DENY.

    Coding action on the wrong resource must DENY.
    """
    request = _make_request(
        source_agent=AgentId.CODING_01,
        action=ActionName.CODING_READ,
        resource=ResourceName.RESEARCH_DATA,
        capability=CapabilityName.CODING_READ,
    )
    result = adapter.evaluate(request)
    assert result == AuthorizationDecision.DENY


def test_coding_test_wrong_resource_denied(adapter):
    """coding-01 | coding.test | workspace => DENY.

    Coding action on the wrong resource must DENY.
    """
    request = _make_request(
        source_agent=AgentId.CODING_01,
        action=ActionName.CODING_TEST,
        resource=ResourceName.WORKSPACE,
        capability=CapabilityName.CODING_TEST,
    )
    result = adapter.evaluate(request)
    assert result == AuthorizationDecision.DENY
