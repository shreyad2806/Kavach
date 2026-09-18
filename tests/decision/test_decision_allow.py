"""
Test ALLOW decision scenarios.
"""

from datetime import datetime, timezone

from shield.authorization.pipeline import authorize
from shield.gateway.models import (
    ActionName,
    ActionRequest,
    AuthorizationDecision,
    CheckStatus,
    ResourceName,
)
from shield.identity.models import AgentId, SecurityState
from shield.provenance.models import Provenance
from shield.gateway.models import RequestContext


def test_allow_valid_research_request():
    """
    TEST 1 — ALLOW
    
    Valid research request:
    - source_agent: research-01
    - action: research.search
    - resource: research-data
    - capability: research.search
    - valid provenance
    
    Expected:
    - decision = ALLOW
    - risk_score = 0
    - reason_codes contains no security violation
    - identity = PASS
    - agent_state = PASS
    - capability = PASS
    - provenance = PASS
    - cedar = ALLOW
    - deterministic_rules = PASS
    - agent_state = ACTIVE
    """
    request = ActionRequest(
        request_id="req-allow-001",
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

    result = authorize(request)

    # Verify decision
    assert result.decision == AuthorizationDecision.ALLOW

    # Verify risk score is 0 (no violations)
    assert result.risk_score == 0

    # Verify no security violation reason codes
    assert len(result.reason_codes) == 0

    # Verify all checks passed
    assert result.checks.identity == CheckStatus.PASS
    assert result.checks.agent_state == CheckStatus.PASS
    assert result.checks.capability == CheckStatus.PASS
    assert result.checks.provenance == CheckStatus.PASS
    assert result.checks.cedar == CheckStatus.ALLOW
    assert result.checks.deterministic_rules == CheckStatus.PASS

    # Verify agent state is ACTIVE
    assert result.agent_state == SecurityState.ACTIVE
