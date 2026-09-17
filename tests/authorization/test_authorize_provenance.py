"""
Authorization pipeline tests — provenance validation.

Tests that requests with invalid provenance result in DENY.
"""

from datetime import datetime, timezone

import pytest

from shield.authorization.pipeline import authorize
from shield.gateway.models import (
    ActionName,
    ActionRequest,
    AuthorizationDecision,
    CapabilityName,
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
    delegation_chain: list[AgentId] | None = None,
    claimed_authority: AgentId | None = None,
) -> ActionRequest:
    """Helper to create a valid ActionRequest with optional provenance overrides."""
    if delegation_chain is None:
        delegation_chain = [source_agent]
    if claimed_authority is None:
        claimed_authority = source_agent

    return ActionRequest(
        request_id=f"test-{source_agent.value}-{action.value}",
        timestamp=datetime.now(timezone.utc),
        source_agent=source_agent,
        target_agent=source_agent,
        task_id="task-test",
        action=action,
        resource=resource,
        claimed_authority=claimed_authority,
        capability=capability,
        provenance=Provenance(
            task_origin=delegation_chain[0],
            delegation_chain=delegation_chain,
        ),
    )


# ============================================================================
# TEST 5 — Invalid provenance => DENY with provenance reason code
# ============================================================================

def test_5_invalid_provenance_deny():
    """
    Invalid provenance (delegation loop) => DENY with PROVENANCE_ANOMALY.
    """
    request = _make_request(
        source_agent=AgentId.RESEARCH_01,
        action=ActionName.RESEARCH_SEARCH,
        resource=ResourceName.RESEARCH_DATA,
        capability=CapabilityName.RESEARCH_SEARCH,
        delegation_chain=[AgentId.ORCHESTRATOR_01, AgentId.RESEARCH_01, AgentId.ORCHESTRATOR_01],
    )

    result = authorize(request)

    assert result.decision == AuthorizationDecision.DENY
    assert ReasonCode.PROVENANCE_ANOMALY in result.reason_codes
    assert result.checks.identity is True
    assert result.checks.capability is True
    assert result.checks.provenance is False


# ============================================================================
# TEST — Provenance failure short-circuits pipeline
# ============================================================================

def test_provenance_failure_short_circuits():
    """
    Provenance failure must short-circuit: Cedar must NOT be evaluated.
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

    request = _make_request(
        source_agent=AgentId.RESEARCH_01,
        action=ActionName.RESEARCH_SEARCH,
        resource=ResourceName.RESEARCH_DATA,
        capability=CapabilityName.RESEARCH_SEARCH,
        delegation_chain=[AgentId.ORCHESTRATOR_01, AgentId.RESEARCH_01, AgentId.ORCHESTRATOR_01],
    )

    result = authorize(request, cedar_adapter=mock_cedar)

    assert result.decision == AuthorizationDecision.DENY
    assert ReasonCode.PROVENANCE_ANOMALY in result.reason_codes
    # Cedar should NOT have been called
    assert mock_cedar.called is False


# ============================================================================
# TEST — Authority mismatch => DENY with AUTHORITY_MISMATCH
# ============================================================================

def test_authority_mismatch_deny():
    """
    Authority mismatch (claimed authority not in delegation chain) => DENY.
    """
    request = _make_request(
        source_agent=AgentId.RESEARCH_01,
        action=ActionName.RESEARCH_SEARCH,
        resource=ResourceName.RESEARCH_DATA,
        capability=CapabilityName.RESEARCH_SEARCH,
        delegation_chain=[AgentId.RESEARCH_01],
        claimed_authority=AgentId.ORCHESTRATOR_01,
    )

    result = authorize(request)

    assert result.decision == AuthorizationDecision.DENY
    assert ReasonCode.AUTHORITY_MISMATCH in result.reason_codes
