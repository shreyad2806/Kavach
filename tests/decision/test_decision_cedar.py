"""
Test Cedar DENY decision scenarios.
"""

from datetime import datetime, timezone
from unittest.mock import Mock

from shield.authorization.pipeline import authorize
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


def test_deny_cedar_policy_denied():
    """
    TEST 3 — CEDAR DENY
    
    Construct a request that:
    - passes identity
    - passes state
    - passes capability
    - passes provenance
    - reaches Cedar
    - is denied by Cedar
    
    Expected:
    - decision = DENY
    - cedar = DENY
    - No later detection result may turn this into ALLOW
    """
    # Mock Cedar adapter to return DENY
    mock_cedar = Mock(spec=CedarAdapter)
    mock_cedar.evaluate.return_value = AuthorizationDecision.DENY

    request = ActionRequest(
        request_id="req-cedar-deny-001",
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

    # Verify decision
    assert result.decision == AuthorizationDecision.DENY

    # Verify Cedar check is DENY
    assert result.checks.cedar == CheckStatus.DENY

    # Verify reason codes includes POLICY_DENIED
    assert ReasonCode.POLICY_DENIED in result.reason_codes

    # Verify earlier checks passed
    assert result.checks.identity == CheckStatus.PASS
    assert result.checks.agent_state == CheckStatus.PASS
    assert result.checks.capability == CheckStatus.PASS
    assert result.checks.provenance == CheckStatus.PASS

    # Verify deterministic rules was NOT evaluated (short-circuit)
    assert result.checks.deterministic_rules == CheckStatus.NOT_EVALUATED
