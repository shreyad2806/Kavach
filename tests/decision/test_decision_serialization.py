"""
Test Decision serialization scenarios.
"""

from datetime import datetime, timezone

from shield.authorization.pipeline import authorize
from shield.gateway.models import (
    ActionName,
    ActionRequest,
    AuthorizationChecks,
    AuthorizationDecision,
    AuthorizationResult,
    CheckStatus,
    ResourceName,
)
from shield.identity.models import AgentId, SecurityState
from shield.provenance.models import Provenance
from shield.gateway.models import RequestContext


def test_serialization_allow_result():
    """
    TEST 8 — SERIALIZATION
    
    Create a valid ALLOW Decision.
    Serialize it to JSON.
    Verify the output contains:
    - request_id
    - decision
    - risk_score
    - reason_codes
    - checks
    - agent_state
    
    Verify enums serialize to strings.
    Verify the result can be parsed back into the AuthorizationResult model.
    """
    request = ActionRequest(
        request_id="req-serial-001",
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

    # Serialize to dict
    result_dict = result.model_dump()

    # Verify required top-level fields exist
    assert "request_id" in result_dict
    assert "decision" in result_dict
    assert "risk_score" in result_dict
    assert "reason_codes" in result_dict
    assert "checks" in result_dict
    assert "agent_state" in result_dict

    # Verify enums serialize to strings
    assert isinstance(result_dict["decision"], str)
    assert result_dict["decision"] == "ALLOW"
    assert isinstance(result_dict["agent_state"], str)
    assert result_dict["agent_state"] == "ACTIVE"

    # Verify checks serialize with string statuses
    assert isinstance(result_dict["checks"]["identity"], str)
    assert result_dict["checks"]["identity"] == "PASS"
    assert isinstance(result_dict["checks"]["cedar"], str)
    assert result_dict["checks"]["cedar"] == "ALLOW"

    # Serialize to JSON
    result_json = result.model_dump_json()

    # Verify JSON is valid string
    assert isinstance(result_json, str)

    # Verify can be parsed back
    parsed_result = AuthorizationResult.model_validate_json(result_json)

    # Verify parsed result matches original
    assert parsed_result.request_id == result.request_id
    assert parsed_result.decision == result.decision
    assert parsed_result.risk_score == result.risk_score
    assert parsed_result.agent_state == result.agent_state


def test_serialization_deny_result():
    """
    Verify DENY results also serialize correctly with the same schema.
    """
    from shield.gateway.models import ReasonCode

    # Create a DENY result directly
    result = AuthorizationResult(
        request_id="req-serial-002",
        decision=AuthorizationDecision.DENY,
        reason_codes=[ReasonCode.CAPABILITY_MISMATCH],
        risk_score=30,
        checks=AuthorizationChecks(
            identity=CheckStatus.PASS,
            agent_state=CheckStatus.PASS,
            capability=CheckStatus.FAIL,
            provenance=CheckStatus.NOT_EVALUATED,
            cedar=CheckStatus.NOT_EVALUATED,
            deterministic_rules=CheckStatus.NOT_EVALUATED,
        ),
        agent_state=SecurityState.ACTIVE,
    )

    # Serialize to dict
    result_dict = result.model_dump()

    # Verify required fields exist
    assert "request_id" in result_dict
    assert "decision" in result_dict
    assert "risk_score" in result_dict
    assert "reason_codes" in result_dict
    assert "checks" in result_dict
    assert "agent_state" in result_dict

    # Verify decision is string
    assert result_dict["decision"] == "DENY"

    # Serialize to JSON and parse back
    result_json = result.model_dump_json()
    parsed_result = AuthorizationResult.model_validate_json(result_json)

    assert parsed_result.decision == AuthorizationDecision.DENY
    assert parsed_result.risk_score == 30
