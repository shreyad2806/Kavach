"""
Authorization pipeline tests — capability mismatches.

Tests that requests with incorrect capabilities result in DENY.
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
# TEST 4 — Capability mismatch => DENY with CAPABILITY_MISMATCH
# ============================================================================

def test_4_capability_mismatch_deny():
    """
    research-01 claims capability coding.write but only has research.search.
    The agent does NOT possess the claimed capability => DENY.
    """
    request = _make_request(
        source_agent=AgentId.RESEARCH_01,
        action=ActionName.DEPLOYMENT_DEPLOY,
        resource=ResourceName.PRODUCTION_ENVIRONMENT,
        capability=CapabilityName.CODING_WRITE,
    )

    result = authorize(request)

    assert result.decision == AuthorizationDecision.DENY
    assert ReasonCode.CAPABILITY_MISMATCH in result.reason_codes
    assert result.checks.identity == CheckStatus.PASS
    assert result.checks.capability == CheckStatus.FAIL


# ============================================================================
# TEST — Capability mismatch short-circuits pipeline
# ============================================================================

def test_capability_mismatch_short_circuits():
    """
    Capability mismatch must short-circuit: provenance and Cedar
    must NOT be evaluated.
    """
    class MockCedarAdapter:
        """Spy that records if evaluate was called."""
        def __init__(self):
            self.called = False

        def evaluate(self, request):
            from shield.gateway.models import AuthorizationDecision
            self.called = True
            return AuthorizationDecision.DENY

    mock_cedar = MockCedarAdapter()

    # research-01 claims coding.write but only has research.search
    request = _make_request(
        source_agent=AgentId.RESEARCH_01,
        action=ActionName.DEPLOYMENT_DEPLOY,
        resource=ResourceName.PRODUCTION_ENVIRONMENT,
        capability=CapabilityName.CODING_WRITE,
    )

    result = authorize(request, cedar_adapter=mock_cedar)

    assert result.decision == AuthorizationDecision.DENY
    assert ReasonCode.CAPABILITY_MISMATCH in result.reason_codes
    # Cedar should NOT have been called
    assert mock_cedar.called is False
