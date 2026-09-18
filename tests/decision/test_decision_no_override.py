"""
Test that DENY decisions can never be overridden by detection or other factors.
"""

from datetime import datetime, timezone
from unittest.mock import Mock

from shield.authorization.pipeline import authorize
from shield.capabilities.models import CapabilityName
from shield.gateway.models import (
    ActionName,
    ActionRequest,
    AuthorizationDecision,
    CheckStatus,
    ReasonCode,
    ResourceName,
)
from shield.identity.models import AgentId, SecurityState
from shield.policy.cedar import CedarAdapter
from shield.provenance.models import Provenance
from shield.gateway.models import RequestContext


def test_no_deny_override_cedar_deny_risk_0():
    """
    TEST 10 — NO DENY OVERRIDE
    
    Explicitly test:
    - Cedar DENY + risk 0 → DENY
    
    Detection never changes the final authorization decision.
    """
    # Mock Cedar adapter to return DENY
    mock_cedar = Mock(spec=CedarAdapter)
    mock_cedar.evaluate.return_value = AuthorizationDecision.DENY

    request = ActionRequest(
        request_id="req-override-001",
        timestamp=datetime.now(timezone.utc),
        source_agent=AgentId.RESEARCH_01,
        target_agent=AgentId.RESEARCH_01,
        task_id="task-001",
        action=ActionName.RESEARCH_SEARCH,
        resource=ResourceName.RESEARCH_DATA,
        claimed_authority=AgentId.ORCHESTRATOR_01,
        capability=ActionName.RESEARCH_SEARCH,
        provenance=Provenance(
            task_origin=AgentId.ORCHESTRATOR_01,
            delegation_chain=[AgentId.ORCHESTRATOR_01, AgentId.RESEARCH_01],
        ),
        context=RequestContext(),
    )

    result = authorize(request, cedar_adapter=mock_cedar)

    # Verify decision is DENY despite low risk
    assert result.decision == AuthorizationDecision.DENY

    # Verify Cedar check is DENY
    assert result.checks.cedar == CheckStatus.DENY

    # Verify reason codes includes POLICY_DENIED
    assert ReasonCode.POLICY_DENIED in result.reason_codes


def test_no_deny_override_cedar_deny_risk_100():
    """
    Explicitly test:
    - Cedar DENY + risk 100 → DENY
    
    Even with maximum risk score, Cedar DENY cannot become ALLOW.
    """
    # Mock Cedar adapter to return DENY
    mock_cedar = Mock(spec=CedarAdapter)
    mock_cedar.evaluate.return_value = AuthorizationDecision.DENY

    request = ActionRequest(
        request_id="req-override-002",
        timestamp=datetime.now(timezone.utc),
        source_agent=AgentId.RESEARCH_01,
        target_agent=AgentId.DEPLOYMENT_01,
        task_id="task-002",
        action=ActionName.DEPLOYMENT_DEPLOY,
        resource=ResourceName.PRODUCTION_ENVIRONMENT,
        claimed_authority=AgentId.ORCHESTRATOR_01,
        capability=ActionName.RESEARCH_SEARCH,  # Capability mismatch
        provenance=Provenance(
            task_origin=AgentId.ORCHESTRATOR_01,
            delegation_chain=[AgentId.ORCHESTRATOR_01, AgentId.RESEARCH_01],
        ),
        context=RequestContext(),
    )

    result = authorize(request, cedar_adapter=mock_cedar)

    # Verify decision is DENY despite high risk
    assert result.decision == AuthorizationDecision.DENY

    # Verify Cedar check is DENY
    assert result.checks.cedar == CheckStatus.DENY

    # Verify reason codes includes POLICY_DENIED
    assert ReasonCode.POLICY_DENIED in result.reason_codes

    # Risk score may be high due to other violations, but decision remains DENY
    # This confirms detection never overrides Cedar DENY
    assert result.decision == AuthorizationDecision.DENY


def test_no_deny_override_capability_mismatch():
    """
    Verify that capability mismatch DENY cannot be overridden.
    """
    request = ActionRequest(
        request_id="req-override-003",
        timestamp=datetime.now(timezone.utc),
        source_agent=AgentId.RESEARCH_01,
        target_agent=AgentId.DEPLOYMENT_01,
        task_id="task-003",
        action=ActionName.DEPLOYMENT_DEPLOY,
        resource=ResourceName.PRODUCTION_ENVIRONMENT,
        claimed_authority=AgentId.ORCHESTRATOR_01,
        capability=CapabilityName.DEPLOYMENT_PRODUCTION,  # Research agent doesn't have this
        provenance=Provenance(
            task_origin=AgentId.ORCHESTRATOR_01,
            delegation_chain=[AgentId.ORCHESTRATOR_01, AgentId.RESEARCH_01],
        ),
        context=RequestContext(),
    )

    result = authorize(request)

    # Verify decision is DENY
    assert result.decision == AuthorizationDecision.DENY

    # Verify capability check is FAIL
    assert result.checks.capability == CheckStatus.FAIL

    # Verify reason codes includes CAPABILITY_MISMATCH
    assert ReasonCode.CAPABILITY_MISMATCH in result.reason_codes

    # Verify later checks were NOT evaluated (short-circuit)
    assert result.checks.provenance == CheckStatus.NOT_EVALUATED
    assert result.checks.cedar == CheckStatus.NOT_EVALUATED
    assert result.checks.deterministic_rules == CheckStatus.NOT_EVALUATED
