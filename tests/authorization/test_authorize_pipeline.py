"""
Authorization pipeline tests — integration and edge cases.

Tests the complete pipeline behavior including the canonical attack scenario.
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
# TEST 10 — Research production deployment attack => DENY
# ============================================================================

def test_10_research_production_deployment_attack():
    """
    CRITICAL: The canonical attack scenario.
    research-01 | deployment.deploy | production-environment | capability research.search

    This request:
    - Has valid identity (research-01 is known)
    - Has valid provenance (self-originated)
    - Has capability research.search (which the agent possesses)
    - But attempts deployment.deploy (which Cedar denies)

    Expected: DENY (Cedar denial)
    """
    request = _make_request(
        source_agent=AgentId.RESEARCH_01,
        action=ActionName.DEPLOYMENT_DEPLOY,
        resource=ResourceName.PRODUCTION_ENVIRONMENT,
        capability=CapabilityName.RESEARCH_SEARCH,
    )

    result = authorize(request)

    # Must be DENY
    assert result.decision == AuthorizationDecision.DENY

    # Check traceability
    assert result.checks.identity is True
    assert result.checks.provenance is True
    assert result.checks.cedar is False

    # Reason code must include POLICY_DENIED
    assert ReasonCode.POLICY_DENIED in result.reason_codes


# ============================================================================
# TEST — Complete pipeline trace for valid request
# ============================================================================

def test_complete_pipeline_trace_valid():
    """
    Verify full pipeline trace for a valid request.
    All checks should pass.
    """
    request = _make_request(
        source_agent=AgentId.CODING_01,
        action=ActionName.CODING_WRITE,
        resource=ResourceName.WORKSPACE,
        capability=CapabilityName.CODING_WRITE,
    )

    result = authorize(request)

    assert result.decision == AuthorizationDecision.ALLOW
    assert result.checks.identity is True
    assert result.checks.capability is True
    assert result.checks.provenance is True
    assert result.checks.cedar is True
    assert result.checks.deterministic_rules is True
    assert result.reason_codes == []
    assert result.agent_state == SecurityState.ACTIVE


# ============================================================================
# TEST — Pipeline preserves request_id
# ============================================================================

def test_pipeline_preserves_request_id():
    """Verify that the pipeline preserves the original request_id."""
    request = _make_request(
        source_agent=AgentId.RESEARCH_01,
        action=ActionName.RESEARCH_SEARCH,
        resource=ResourceName.RESEARCH_DATA,
        capability=CapabilityName.RESEARCH_SEARCH,
    )

    result = authorize(request)

    assert result.request_id == request.request_id


# ============================================================================
# TEST — Multiple failures accumulate reason codes
# ============================================================================

def test_multiple_failures_accumulate():
    """
    When multiple checks fail, all applicable reason codes should be present.
    However, due to short-circuiting, only the first failure's reason code
    is recorded.
    """
    # This test verifies short-circuit behavior: identity failure prevents
    # capability/provenance/Cedar from being evaluated.
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

    # Only identity failure reason should be present (short-circuit)
    assert result.decision == AuthorizationDecision.DENY
    assert ReasonCode.IDENTITY_FAILURE in result.reason_codes
    # Other reasons should NOT be present due to short-circuit
    assert ReasonCode.CAPABILITY_MISMATCH not in result.reason_codes
    assert ReasonCode.PROVENANCE_ANOMALY not in result.reason_codes
    assert ReasonCode.POLICY_DENIED not in result.reason_codes
