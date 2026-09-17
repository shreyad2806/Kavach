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
    ReasonCode,
    RequestContext,
    ResourceName,
)
from shield.identity.models import AgentId, SecurityState
from shield.provenance.models import Provenance


def test_resource_name_vocabulary():
    expected_resources = {
        "research-data",
        "workspace",
        "test-environment",
        "staging-environment",
        "production-environment",
    }
    actual_resources = {r.value for r in ResourceName}
    assert actual_resources == expected_resources


def test_action_name_vocabulary():
    expected_actions = {
        "research.search",
        "research.read",
        "coding.read",
        "coding.write",
        "coding.test",
        "deployment.preview",
        "deployment.deploy",
        "verification.test",
        "orchestrator.delegate",
        "orchestrator.coordinate",
    }
    actual_actions = {a.value for a in ActionName}
    assert actual_actions == expected_actions


def test_action_and_capability_separation():
    # 'deployment.deploy' is an action, NOT a capability
    assert "deployment.deploy" in {a.value for a in ActionName}
    assert "deployment.deploy" not in {c.value for c in CapabilityName}

    # 'deployment.production' is a capability, NOT an action
    assert "deployment.production" in {c.value for c in CapabilityName}
    assert "deployment.production" not in {a.value for a in ActionName}


def test_request_context_clean_and_forbids_core_entities():
    # Valid minimal context
    ctx = RequestContext()
    assert ctx.environment_tags == {}

    ctx_with_tags = RequestContext(environment_tags={"stage": "prod", "region": "us-east-1"})
    assert ctx_with_tags.environment_tags["region"] == "us-east-1"

    # Context must NOT contain core request entities
    forbidden_keys = ["capability", "action", "resource", "source_agent", "target_agent"]
    for key in forbidden_keys:
        with pytest.raises(ValidationError):
            RequestContext(**{key: "injected_value"})


def test_action_request_canonical_attack_example_valid():
    raw_payload = {
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
            "delegation_chain": ["orchestrator-01", "research-01"],
        },
        "context": {},
    }

    req = ActionRequest.model_validate(raw_payload)
    assert req.request_id == "req-001"
    assert req.source_agent == AgentId.RESEARCH_01
    assert req.target_agent == AgentId.DEPLOYMENT_01
    assert req.action == ActionName.DEPLOYMENT_DEPLOY
    assert req.resource == ResourceName.PRODUCTION_ENVIRONMENT
    assert req.claimed_authority == AgentId.ORCHESTRATOR_01
    assert req.capability == CapabilityName.RESEARCH_SEARCH
    assert req.provenance.task_origin == AgentId.ORCHESTRATOR_01
    assert len(req.provenance.delegation_chain) == 2


def test_action_request_does_not_have_decision_fields():
    # Model fields must not contain decision or authorization logic
    field_names = set(ActionRequest.model_fields.keys())
    assert "is_authorized" not in field_names
    assert "decision" not in field_names
    assert "risk_score" not in field_names


def test_action_request_validation_failures():
    valid_kwargs = {
        "request_id": "req-001",
        "timestamp": datetime.now(timezone.utc),
        "source_agent": AgentId.RESEARCH_01,
        "target_agent": AgentId.DEPLOYMENT_01,
        "task_id": "task-001",
        "action": ActionName.RESEARCH_SEARCH,
        "resource": ResourceName.RESEARCH_DATA,
        "claimed_authority": AgentId.ORCHESTRATOR_01,
        "capability": CapabilityName.RESEARCH_SEARCH,
        "provenance": Provenance(
            task_origin=AgentId.ORCHESTRATOR_01,
            delegation_chain=[AgentId.ORCHESTRATOR_01],
        ),
    }

    # Empty request_id fails
    with pytest.raises(ValidationError):
        ActionRequest(**{**valid_kwargs, "request_id": ""})

    # Empty task_id fails
    with pytest.raises(ValidationError):
        ActionRequest(**{**valid_kwargs, "task_id": ""})

    # Invalid source_agent fails
    with pytest.raises(ValidationError):
        ActionRequest(**{**valid_kwargs, "source_agent": "rogue-agent"})  # type: ignore[arg-type]

    # Forbids extra fields
    with pytest.raises(ValidationError):
        ActionRequest(**{**valid_kwargs, "is_authorized": True})


def test_authorization_decision_enum():
    assert {d.value for d in AuthorizationDecision} == {"ALLOW", "DENY"}


def test_reason_codes_vocabulary():
    expected = {
        "IDENTITY_FAILURE",
        "CAPABILITY_MISMATCH",
        "AUTHORITY_MISMATCH",
        "PROVENANCE_ANOMALY",
        "POLICY_DENIED",
        "AGENT_QUARANTINED",
        "PRIVILEGE_ESCALATION",
        "SUSPICIOUS_BEHAVIOR",
    }
    assert {r.value for r in ReasonCode} == expected


def test_authorization_checks_model():
    # Uncalculated default is None
    checks = AuthorizationChecks()
    assert checks.identity is None
    assert checks.capability is None
    assert checks.provenance is None
    assert checks.cedar is None
    assert checks.deterministic_rules is None

    # Calculated checks
    checks_populated = AuthorizationChecks(
        identity=True,
        capability=False,
        provenance=True,
        cedar=False,
        deterministic_rules=False,
    )
    assert checks_populated.capability is False


def test_authorization_result_creation_and_serialization():
    result = AuthorizationResult(
        request_id="req-001",
        decision=AuthorizationDecision.DENY,
        reason_codes=[ReasonCode.CAPABILITY_MISMATCH],
        risk_score=85,
        checks=AuthorizationChecks(
            identity=True,
            capability=False,
            provenance=True,
            cedar=False,
            deterministic_rules=False,
        ),
        agent_state=SecurityState.ACTIVE,
    )
    assert result.decision == "DENY"
    assert result.reason_codes == ["CAPABILITY_MISMATCH"]
    assert result.risk_score == 85

    dumped = result.model_dump()
    assert dumped["decision"] == "DENY"
    assert dumped["risk_score"] == 85

    # Roundtrip from JSON
    json_str = result.model_dump_json()
    reloaded = AuthorizationResult.model_validate_json(json_str)
    assert reloaded.decision == AuthorizationDecision.DENY
    assert reloaded.risk_score == 85


def test_authorization_result_risk_score_validation():
    base_kwargs = {
        "request_id": "req-001",
        "decision": AuthorizationDecision.ALLOW,
        "agent_state": SecurityState.ACTIVE,
    }

    # Valid boundaries
    assert AuthorizationResult(**{**base_kwargs, "risk_score": 0}).risk_score == 0
    assert AuthorizationResult(**{**base_kwargs, "risk_score": 100}).risk_score == 100
    assert AuthorizationResult(**{**base_kwargs, "risk_score": None}).risk_score is None

    # Invalid boundaries
    with pytest.raises(ValidationError):
        AuthorizationResult(**{**base_kwargs, "risk_score": -1})

    with pytest.raises(ValidationError):
        AuthorizationResult(**{**base_kwargs, "risk_score": 101})
