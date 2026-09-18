from datetime import datetime, timezone
import pytest
from pydantic import ValidationError

from shield.capabilities.models import CapabilityName
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
from shield.provenance.models import Provenance


# ==============================================================================
# 1. CANONICAL MALICIOUS REQUEST AND AUTHORIZATION RESULT CONTRACT TEST
# ==============================================================================

def test_canonical_malicious_request_and_decision():
    """
    Validates the canonical Phase 3 attack scenario:
    - Source: research-01
    - Target: deployment-01
    - Capability possessed: research.search
    - Action requested: deployment.deploy
    - Resource targeted: production-environment
    - Claimed authority: orchestrator-01
    - Provenance: orchestrator-01 -> research-01

    Proves that:
    1. The ActionRequest contract accepts the suspicious request as valid input.
    2. The AuthorizationResult contract can cleanly represent the subsequent
       DENY decision with reason codes and advisory risk score.
    """
    request_data = {
        "request_id": "req-001",
        "timestamp": "2026-09-17T12:00:00Z",
        "source_agent": "research-01",
        "target_agent": "deployment-01",
        "task_id": "task-001",
        "parent_event_id": "evt-000",
        "action": "deployment.deploy",
        "resource": "production-environment",
        "claimed_authority": "orchestrator-01",
        "capability": "research.search",
        "provenance": {
            "task_origin": "orchestrator-01",
            "delegation_chain": [
                "orchestrator-01",
                "research-01",
            ],
        },
        "context": {},
    }

    # The request itself MUST validate successfully as input to Kavach
    action_request = ActionRequest.model_validate(request_data)
    assert action_request.request_id == "req-001"
    assert action_request.source_agent == AgentId.RESEARCH_01
    assert action_request.target_agent == AgentId.DEPLOYMENT_01
    assert action_request.capability == CapabilityName.RESEARCH_SEARCH
    assert action_request.action == ActionName.DEPLOYMENT_DEPLOY
    assert action_request.resource == ResourceName.PRODUCTION_ENVIRONMENT
    assert action_request.claimed_authority == AgentId.ORCHESTRATOR_01
    assert action_request.provenance.task_origin == AgentId.ORCHESTRATOR_01
    assert action_request.provenance.delegation_chain == [
        AgentId.ORCHESTRATOR_01,
        AgentId.RESEARCH_01,
    ]

    # The future security decision produced by Kavach authorization engine
    result_data = {
        "request_id": "req-001",
        "decision": "DENY",
        "reason_codes": [
            "CAPABILITY_MISMATCH",
            "AUTHORITY_MISMATCH",
        ],
        "risk_score": 94,
        "agent_state": "ACTIVE",
    }

    auth_result = AuthorizationResult.model_validate(result_data)
    assert auth_result.request_id == "req-001"
    assert auth_result.decision == AuthorizationDecision.DENY
    assert auth_result.reason_codes == [
        ReasonCode.CAPABILITY_MISMATCH,
        ReasonCode.AUTHORITY_MISMATCH,
    ]
    assert auth_result.risk_score == 94
    assert auth_result.agent_state == SecurityState.ACTIVE


# ==============================================================================
# 2. SECURITY INVARIANTS: CAPABILITY VS. REQUESTED ACTION SEPARATION
# ==============================================================================

def test_security_invariants_capability_action_separation():
    """
    Proves core security invariants:
    A. A research agent can possess: research.search
    B. The same request can ask for: deployment.deploy
    C. These are intentionally different fields.
    D. The ActionRequest model accepts this mismatch as INPUT (no premature rejection).
    E. AuthorizationResult can later represent: DENY + CAPABILITY_MISMATCH.
    """
    # Invariant A: research agent legitimate capability
    legitimate_cap = CapabilityName.RESEARCH_SEARCH
    assert legitimate_cap == "research.search"

    # Invariant B: requested action outside capability
    requested_act = ActionName.DEPLOYMENT_DEPLOY
    assert requested_act == "deployment.deploy"

    # Invariant C: different fields in model
    fields = ActionRequest.model_fields
    assert "capability" in fields
    assert "action" in fields
    assert fields["capability"].annotation == CapabilityName
    assert fields["action"].annotation == ActionName

    # Invariant D: ActionRequest accepts this mismatch as INPUT
    req = ActionRequest(
        request_id="req-mismatch-01",
        timestamp=datetime.now(timezone.utc),
        source_agent=AgentId.RESEARCH_01,
        target_agent=AgentId.DEPLOYMENT_01,
        task_id="task-mismatch-01",
        action=requested_act,
        resource=ResourceName.PRODUCTION_ENVIRONMENT,
        claimed_authority=AgentId.ORCHESTRATOR_01,
        capability=legitimate_cap,
        provenance=Provenance(
            task_origin=AgentId.ORCHESTRATOR_01,
            delegation_chain=[AgentId.ORCHESTRATOR_01, AgentId.RESEARCH_01],
        ),
        context=RequestContext(),
    )
    assert req.capability == CapabilityName.RESEARCH_SEARCH
    assert req.action == ActionName.DEPLOYMENT_DEPLOY

    # Invariant E: AuthorizationResult can represent DENY + CAPABILITY_MISMATCH
    res = AuthorizationResult(
        request_id="req-mismatch-01",
        decision=AuthorizationDecision.DENY,
        reason_codes=[ReasonCode.CAPABILITY_MISMATCH],
        risk_score=90,
        checks=AuthorizationChecks(
            identity=CheckStatus.PASS,
            agent_state=CheckStatus.PASS,
            capability=CheckStatus.FAIL,
            provenance=CheckStatus.PASS,
            cedar=CheckStatus.DENY,
            deterministic_rules=CheckStatus.BLOCK,
        ),
        agent_state=SecurityState.ACTIVE,
    )
    assert res.decision == AuthorizationDecision.DENY
    assert ReasonCode.CAPABILITY_MISMATCH in res.reason_codes


def test_action_request_does_not_contain_decision_or_calculation_fields():
    """
    ActionRequest is INPUT to Kavach, never an authorization result.
    It must not contain decision, authorization, or risk fields.
    """
    field_names = set(ActionRequest.model_fields.keys())
    forbidden_fields = {
        "decision",
        "is_authorized",
        "risk_calculation",
        "risk_score",
        "policy_result",
        "quarantine_decision",
        "llm_output",
    }
    present_forbidden = forbidden_fields.intersection(field_names)
    assert not present_forbidden, f"ActionRequest contains forbidden output fields: {present_forbidden}"


# ==============================================================================
# 3. VALIDATION TESTS: ACTION REQUEST
# ==============================================================================

@pytest.fixture
def base_valid_action_request_kwargs():
    return {
        "request_id": "req-valid-100",
        "timestamp": datetime.now(timezone.utc),
        "source_agent": AgentId.RESEARCH_01,
        "target_agent": AgentId.DEPLOYMENT_01,
        "task_id": "task-valid-100",
        "parent_event_id": "evt-root-001",
        "action": ActionName.RESEARCH_SEARCH,
        "resource": ResourceName.RESEARCH_DATA,
        "claimed_authority": AgentId.ORCHESTRATOR_01,
        "capability": CapabilityName.RESEARCH_SEARCH,
        "provenance": Provenance(
            task_origin=AgentId.ORCHESTRATOR_01,
            delegation_chain=[AgentId.ORCHESTRATOR_01, AgentId.RESEARCH_01],
        ),
        "context": RequestContext(),
    }


def test_action_request_complete_valid(base_valid_action_request_kwargs):
    req = ActionRequest(**base_valid_action_request_kwargs)
    assert req.request_id == "req-valid-100"
    assert req.source_agent == AgentId.RESEARCH_01
    assert req.target_agent == AgentId.DEPLOYMENT_01
    assert req.action == ActionName.RESEARCH_SEARCH
    assert req.resource == ResourceName.RESEARCH_DATA
    assert req.claimed_authority == AgentId.ORCHESTRATOR_01
    assert req.capability == CapabilityName.RESEARCH_SEARCH


def test_action_request_missing_request_id_fails(base_valid_action_request_kwargs):
    kwargs = base_valid_action_request_kwargs.copy()
    del kwargs["request_id"]
    with pytest.raises(ValidationError):
        ActionRequest(**kwargs)


def test_action_request_empty_request_id_fails(base_valid_action_request_kwargs):
    kwargs = base_valid_action_request_kwargs.copy()
    kwargs["request_id"] = ""
    with pytest.raises(ValidationError):
        ActionRequest(**kwargs)


def test_action_request_invalid_source_agent_fails(base_valid_action_request_kwargs):
    kwargs = base_valid_action_request_kwargs.copy()
    kwargs["source_agent"] = "untrusted-agent"
    with pytest.raises(ValidationError):
        ActionRequest(**kwargs)


def test_action_request_invalid_target_agent_fails(base_valid_action_request_kwargs):
    kwargs = base_valid_action_request_kwargs.copy()
    kwargs["target_agent"] = "external-api"
    with pytest.raises(ValidationError):
        ActionRequest(**kwargs)


def test_action_request_invalid_action_fails(base_valid_action_request_kwargs):
    kwargs = base_valid_action_request_kwargs.copy()
    kwargs["action"] = "deployment.destroy"
    with pytest.raises(ValidationError):
        ActionRequest(**kwargs)


def test_action_request_invalid_resource_fails(base_valid_action_request_kwargs):
    kwargs = base_valid_action_request_kwargs.copy()
    kwargs["resource"] = "s3-bucket-confidential"
    with pytest.raises(ValidationError):
        ActionRequest(**kwargs)


def test_action_request_invalid_capability_fails(base_valid_action_request_kwargs):
    kwargs = base_valid_action_request_kwargs.copy()
    # 'deployment.deploy' is an action name, not a capability name
    kwargs["capability"] = "deployment.deploy"
    with pytest.raises(ValidationError):
        ActionRequest(**kwargs)


def test_action_request_invalid_claimed_authority_fails(base_valid_action_request_kwargs):
    kwargs = base_valid_action_request_kwargs.copy()
    kwargs["claimed_authority"] = "system-administrator"
    with pytest.raises(ValidationError):
        ActionRequest(**kwargs)


def test_action_request_empty_provenance_chain_fails():
    with pytest.raises(ValidationError):
        Provenance(
            task_origin=AgentId.ORCHESTRATOR_01,
            delegation_chain=[],
        )


def test_action_request_provenance_origin_mismatch_fails():
    with pytest.raises(ValidationError):
        Provenance(
            task_origin=AgentId.ORCHESTRATOR_01,
            delegation_chain=[AgentId.RESEARCH_01],
        )


# ==============================================================================
# 4. VALIDATION TESTS: AUTHORIZATION RESULT
# ==============================================================================

def test_authorization_result_complete_valid():
    res = AuthorizationResult(
        request_id="req-200",
        decision=AuthorizationDecision.ALLOW,
        reason_codes=[],
        risk_score=10,
        checks=AuthorizationChecks(
            identity=CheckStatus.PASS,
            agent_state=CheckStatus.PASS,
            capability=CheckStatus.PASS,
            provenance=CheckStatus.PASS,
            cedar=CheckStatus.ALLOW,
            deterministic_rules=CheckStatus.PASS,
        ),
        agent_state=SecurityState.ACTIVE,
    )
    assert res.decision == AuthorizationDecision.ALLOW
    assert res.risk_score == 10
    assert res.agent_state == SecurityState.ACTIVE


def test_authorization_result_multiple_reason_codes():
    res = AuthorizationResult(
        request_id="req-201",
        decision=AuthorizationDecision.DENY,
        reason_codes=[
            ReasonCode.CAPABILITY_MISMATCH,
            ReasonCode.AUTHORITY_MISMATCH,
            ReasonCode.POLICY_DENIED,
        ],
        risk_score=95,
        agent_state=SecurityState.ACTIVE,
    )
    assert len(res.reason_codes) == 3
    assert res.reason_codes[0] == ReasonCode.CAPABILITY_MISMATCH
    assert res.reason_codes[1] == ReasonCode.AUTHORITY_MISMATCH
    assert res.reason_codes[2] == ReasonCode.POLICY_DENIED


def test_authorization_result_risk_score_boundaries():
    # Boundary 0 is valid
    res_zero = AuthorizationResult(
        request_id="req-risk-0",
        decision=AuthorizationDecision.ALLOW,
        risk_score=0,
        agent_state=SecurityState.ACTIVE,
    )
    assert res_zero.risk_score == 0

    # Boundary 100 is valid
    res_hundred = AuthorizationResult(
        request_id="req-risk-100",
        decision=AuthorizationDecision.DENY,
        risk_score=100,
        agent_state=SecurityState.ACTIVE,
    )
    assert res_hundred.risk_score == 100

    # Negative risk score fails
    with pytest.raises(ValidationError):
        AuthorizationResult(
            request_id="req-risk-neg",
            decision=AuthorizationDecision.ALLOW,
            risk_score=-1,
            agent_state=SecurityState.ACTIVE,
        )

    # Risk score > 100 fails
    with pytest.raises(ValidationError):
        AuthorizationResult(
            request_id="req-risk-excess",
            decision=AuthorizationDecision.DENY,
            risk_score=101,
            agent_state=SecurityState.ACTIVE,
        )


def test_authorization_result_invalid_decision_fails():
    with pytest.raises(ValidationError):
        AuthorizationResult(
            request_id="req-301",
            decision="PERMIT_WITH_CONDITIONS",  # type: ignore[arg-type]
            agent_state=SecurityState.ACTIVE,
        )


def test_authorization_result_invalid_reason_code_fails():
    with pytest.raises(ValidationError):
        AuthorizationResult(
            request_id="req-302",
            decision=AuthorizationDecision.DENY,
            reason_codes=["UNREGISTERED_REASON_CODE"],  # type: ignore[list-item]
            agent_state=SecurityState.ACTIVE,
        )


def test_authorization_result_invalid_agent_state_fails():
    with pytest.raises(ValidationError):
        AuthorizationResult(
            request_id="req-303",
            decision=AuthorizationDecision.DENY,
            agent_state="COMPROMISED",  # type: ignore[arg-type]
        )


def test_authorization_result_missing_request_id_fails():
    with pytest.raises(ValidationError):
        AuthorizationResult(
            decision=AuthorizationDecision.ALLOW,  # type: ignore[call-arg]
            agent_state=SecurityState.ACTIVE,
        )


# ==============================================================================
# 5. SERIALIZATION AND ROUNDTRIP EQUIVALENCE TESTS
# ==============================================================================

def test_action_request_serialization_roundtrip(base_valid_action_request_kwargs):
    original = ActionRequest(**base_valid_action_request_kwargs)

    # 1. model_dump -> model_validate
    dumped_dict = original.model_dump()
    assert isinstance(dumped_dict, dict)
    reconstructed_from_dict = ActionRequest.model_validate(dumped_dict)
    assert reconstructed_from_dict == original

    # 2. model_dump_json -> model_validate_json
    dumped_json = original.model_dump_json()
    assert isinstance(dumped_json, str)
    reconstructed_from_json = ActionRequest.model_validate_json(dumped_json)
    assert reconstructed_from_json == original


def test_authorization_result_serialization_roundtrip():
    original = AuthorizationResult(
        request_id="req-roundtrip-res",
        decision=AuthorizationDecision.DENY,
        reason_codes=[
            ReasonCode.CAPABILITY_MISMATCH,
            ReasonCode.AUTHORITY_MISMATCH,
        ],
        risk_score=94,
        checks=AuthorizationChecks(
            identity=CheckStatus.PASS,
            agent_state=CheckStatus.PASS,
            capability=CheckStatus.FAIL,
            provenance=CheckStatus.PASS,
            cedar=CheckStatus.DENY,
            deterministic_rules=CheckStatus.BLOCK,
        ),
        agent_state=SecurityState.ACTIVE,
    )

    # 1. model_dump -> model_validate
    dumped_dict = original.model_dump()
    assert isinstance(dumped_dict, dict)
    reconstructed_from_dict = AuthorizationResult.model_validate(dumped_dict)
    assert reconstructed_from_dict == original

    # 2. model_dump_json -> model_validate_json
    dumped_json = original.model_dump_json()
    assert isinstance(dumped_json, str)
    reconstructed_from_json = AuthorizationResult.model_validate_json(dumped_json)
    assert reconstructed_from_json == original
