"""
Authorization pipeline tests — identity failures.

Tests that requests from unknown agents result in DENY with IDENTITY_FAILURE.
"""

from datetime import datetime, timezone

import pytest

from shield.authorization.pipeline import authorize
from shield.gateway.models import (
    ActionName,
    ActionRequest,
    AuthorizationDecision,
    AuthorizationResult,
    CapabilityName,
    CheckStatus,
    ReasonCode,
    ResourceName,
)
from shield.identity.models import AgentId, SecurityState
from shield.identity.service import IdentityService
from shield.provenance.models import Provenance


def _make_request(
    source_agent: AgentId,
    action: ActionName,
    resource: ResourceName,
    capability: CapabilityName,
) -> ActionRequest:
    """Helper to create a valid ActionRequest."""
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
# TEST 2 — Unknown agent => DENY with IDENTITY_FAILURE
# ============================================================================

def test_2_unknown_agent_deny():
    """
    Unknown agent (not in registry) => DENY with IDENTITY_FAILURE.
    The pipeline must short-circuit and not proceed to Cedar.
    """
    # Create a custom request with an agent that doesn't exist in the registry
    # We'll use a mock-like approach by creating a request and using a custom
    # identity service that returns None for the agent
    identity_service = IdentityService()

    # Create a request with a valid agent first, then modify the identity service
    # to not recognize it. Since we can't modify the enum, we'll test with a
    # valid agent that we remove from the registry.

    # Actually, we can't create an AgentId that's not in the enum.
    # Instead, we'll test by using a spy on the identity service.

    # For now, let's test the case where the identity service returns None
    # by using a custom implementation
    class MockIdentityService(IdentityService):
        def get_agent(self, agent_id):
            return None

    request = _make_request(
        source_agent=AgentId.RESEARCH_01,
        action=ActionName.RESEARCH_SEARCH,
        resource=ResourceName.RESEARCH_DATA,
        capability=CapabilityName.RESEARCH_SEARCH,
    )

    result = authorize(request, identity_service=MockIdentityService())

    assert result.decision == AuthorizationDecision.DENY
    assert ReasonCode.IDENTITY_FAILURE in result.reason_codes
    assert result.checks.identity == CheckStatus.FAIL
    assert result.agent_state == SecurityState.TERMINATED


# ============================================================================
# TEST — Identity failure short-circuits pipeline
# ============================================================================

def test_identity_failure_short_circuits():
    """
    Identity failure must short-circuit: capability, provenance, and Cedar
    must NOT be evaluated.
    """
    class MockCapabilityService:
        """Spy that records if has_capability was called."""
        def __init__(self):
            self.called = False

        def has_capability(self, agent_id, capability):
            self.called = True
            return True

    class MockIdentityService(IdentityService):
        def get_agent(self, agent_id):
            return None

    mock_capability = MockCapabilityService()

    request = _make_request(
        source_agent=AgentId.RESEARCH_01,
        action=ActionName.RESEARCH_SEARCH,
        resource=ResourceName.RESEARCH_DATA,
        capability=CapabilityName.RESEARCH_SEARCH,
    )

    result = authorize(
        request,
        identity_service=MockIdentityService(),
        capability_service=mock_capability,
    )

    assert result.decision == AuthorizationDecision.DENY
    assert ReasonCode.IDENTITY_FAILURE in result.reason_codes
    # Capability service should NOT have been called
    assert mock_capability.called is False
