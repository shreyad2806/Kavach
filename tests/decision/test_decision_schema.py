"""
Test the Decision/AuthorizationResult schema structure.
"""

from datetime import datetime, timezone

from shield.authorization.pipeline import authorize
from shield.capabilities.service import CapabilityService
from shield.gateway.models import (
    ActionName,
    ActionRequest,
    AuthorizationChecks,
    AuthorizationDecision,
    AuthorizationResult,
    CheckStatus,
    ReasonCode,
    RequestContext,
    ResourceName,
)
from shield.identity.models import AgentId, SecurityState
from shield.identity.service import IdentityService
from shield.provenance.models import Provenance


def test_decision_schema_has_required_fields():
    """
    Verify the AuthorizationResult (Decision) schema contains all required top-level fields.
    """
    result = AuthorizationResult(
        request_id="req-001",
        decision=AuthorizationDecision.ALLOW,
        reason_codes=[],
        risk_score=0,
        checks=AuthorizationChecks(),
        agent_state=SecurityState.ACTIVE,
    )

    # Verify all required fields exist
    assert hasattr(result, "request_id")
    assert hasattr(result, "decision")
    assert hasattr(result, "risk_score")
    assert hasattr(result, "reason_codes")
    assert hasattr(result, "checks")
    assert hasattr(result, "agent_state")

    # Verify field values
    assert result.request_id == "req-001"
    assert result.decision == AuthorizationDecision.ALLOW
    assert result.risk_score == 0
    assert result.reason_codes == []
    assert result.agent_state == SecurityState.ACTIVE


def test_checks_schema_has_all_check_fields():
    """
    Verify AuthorizationChecks contains all required check fields.
    """
    checks = AuthorizationChecks()

    # Verify all check fields exist
    assert hasattr(checks, "identity")
    assert hasattr(checks, "agent_state")
    assert hasattr(checks, "capability")
    assert hasattr(checks, "provenance")
    assert hasattr(checks, "cedar")
    assert hasattr(checks, "deterministic_rules")

    # Verify default status is NOT_EVALUATED
    assert checks.identity == CheckStatus.NOT_EVALUATED
    assert checks.agent_state == CheckStatus.NOT_EVALUATED
    assert checks.capability == CheckStatus.NOT_EVALUATED
    assert checks.provenance == CheckStatus.NOT_EVALUATED
    assert checks.cedar == CheckStatus.NOT_EVALUATED
    assert checks.deterministic_rules == CheckStatus.NOT_EVALUATED


def test_check_status_enum_values():
    """
    Verify CheckStatus enum contains all required status values.
    """
    expected_statuses = {
        "PASS",
        "FAIL",
        "ALLOW",
        "DENY",
        "BLOCK",
        "NOT_EVALUATED",
    }
    actual_statuses = {status.value for status in CheckStatus}
    assert actual_statuses == expected_statuses


def test_decision_from_authorize_call():
    """
    Verify authorize() returns a valid AuthorizationResult with correct schema.
    """
    request = ActionRequest(
        request_id="req-002",
        timestamp=datetime.now(timezone.utc),
        source_agent=AgentId.RESEARCH_01,
        target_agent=AgentId.RESEARCH_01,
        task_id="task-002",
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

    # Verify result is AuthorizationResult
    assert isinstance(result, AuthorizationResult)

    # Verify schema fields
    assert isinstance(result.request_id, str)
    assert isinstance(result.decision, AuthorizationDecision)
    assert isinstance(result.risk_score, int) or result.risk_score is None
    assert isinstance(result.reason_codes, list)
    assert isinstance(result.checks, AuthorizationChecks)
    assert isinstance(result.agent_state, SecurityState)
