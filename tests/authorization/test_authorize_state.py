"""
Authorization pipeline tests — agent state failures.

Tests that quarantined/terminated agents result in DENY.
"""

from datetime import datetime, timezone

import pytest

from shield.authorization.pipeline import authorize
from shield.gateway.models import (
    ActionName,
    ActionRequest,
    AuthorizationDecision,
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
# TEST 3 — Quarantined agent => DENY with AGENT_QUARANTINED
# ============================================================================

def test_3_quarantined_agent_deny():
    """
    Quarantined agent => DENY with AGENT_QUARANTINED.
    The pipeline must short-circuit and not proceed to Cedar.
    """
    identity_service = IdentityService()
    identity_service.set_state(AgentId.RESEARCH_01, SecurityState.QUARANTINED)

    request = _make_request(
        source_agent=AgentId.RESEARCH_01,
        action=ActionName.RESEARCH_SEARCH,
        resource=ResourceName.RESEARCH_DATA,
        capability=CapabilityName.RESEARCH_SEARCH,
    )

    result = authorize(request, identity_service=identity_service)

    assert result.decision == AuthorizationDecision.DENY
    assert ReasonCode.AGENT_QUARANTINED in result.reason_codes
    assert result.checks.identity == CheckStatus.PASS
    assert result.agent_state == SecurityState.QUARANTINED


# ============================================================================
# TEST — Terminated agent => DENY with IDENTITY_FAILURE
# ============================================================================

def test_terminated_agent_deny():
    """
    Terminated agent => DENY with IDENTITY_FAILURE.
    """
    identity_service = IdentityService()
    identity_service.set_state(AgentId.RESEARCH_01, SecurityState.TERMINATED)

    request = _make_request(
        source_agent=AgentId.RESEARCH_01,
        action=ActionName.RESEARCH_SEARCH,
        resource=ResourceName.RESEARCH_DATA,
        capability=CapabilityName.RESEARCH_SEARCH,
    )

    result = authorize(request, identity_service=identity_service)

    assert result.decision == AuthorizationDecision.DENY
    assert ReasonCode.IDENTITY_FAILURE in result.reason_codes
    assert result.checks.identity == CheckStatus.PASS
    assert result.agent_state == SecurityState.TERMINATED


# ============================================================================
# TEST — Quarantined agent short-circuits pipeline
# ============================================================================

def test_quarantined_agent_short_circuits():
    """
    Quarantined agent must short-circuit: capability, provenance, and Cedar
    must NOT be evaluated.
    """
    class MockCapabilityService:
        """Spy that records if has_capability was called."""
        def __init__(self):
            self.called = False

        def has_capability(self, agent_id, capability):
            self.called = True
            return True

    identity_service = IdentityService()
    identity_service.set_state(AgentId.RESEARCH_01, SecurityState.QUARANTINED)
    mock_capability = MockCapabilityService()

    request = _make_request(
        source_agent=AgentId.RESEARCH_01,
        action=ActionName.RESEARCH_SEARCH,
        resource=ResourceName.RESEARCH_DATA,
        capability=CapabilityName.RESEARCH_SEARCH,
    )

    result = authorize(
        request,
        identity_service=identity_service,
        capability_service=mock_capability,
    )

    assert result.decision == AuthorizationDecision.DENY
    assert ReasonCode.AGENT_QUARANTINED in result.reason_codes
    # Capability service should NOT have been called
    assert mock_capability.called is False
