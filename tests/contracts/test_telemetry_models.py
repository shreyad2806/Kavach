from datetime import datetime, timezone
import pytest
from pydantic import ValidationError

from shield.gateway.models import ActionName, AuthorizationDecision, ReasonCode, ResourceName
from shield.identity.models import AgentId
from shield.telemetry.events import EventType, SecurityEvent


def test_event_type_vocabulary():
    expected = {
        "AUTHORIZATION_REQUEST",
        "AUTHORIZATION_DECISION",
        "SECURITY_VIOLATION",
        "QUARANTINE",
    }
    assert {e.value for e in EventType} == expected


def test_security_event_creation_valid():
    now = datetime.now(timezone.utc)
    event = SecurityEvent(
        event_id="evt-100",
        timestamp=now,
        event_type=EventType.SECURITY_VIOLATION,
        source_agent=AgentId.RESEARCH_01,
        target_agent=AgentId.DEPLOYMENT_01,
        request_id="req-001",
        task_id="task-001",
        action=ActionName.DEPLOYMENT_DEPLOY,
        resource=ResourceName.PRODUCTION_ENVIRONMENT,
        policy_decision=AuthorizationDecision.DENY,
        reason_codes=[ReasonCode.CAPABILITY_MISMATCH],
        risk_score=90,
    )
    assert event.event_id == "evt-100"
    assert event.event_type == EventType.SECURITY_VIOLATION
    assert event.policy_decision == AuthorizationDecision.DENY
    assert event.reason_codes == [ReasonCode.CAPABILITY_MISMATCH]
    assert event.risk_score == 90


def test_security_event_serialization_roundtrip():
    raw_payload = {
        "event_id": "evt-200",
        "timestamp": "2026-09-17T12:00:00Z",
        "event_type": "QUARANTINE",
        "source_agent": "coding-01",
        "target_agent": "deployment-01",
        "request_id": "req-002",
        "task_id": "task-002",
        "action": "coding.write",
        "resource": "workspace",
        "policy_decision": "DENY",
        "reason_codes": ["AGENT_QUARANTINED"],
        "risk_score": 95,
    }

    model = SecurityEvent.model_validate(raw_payload)
    assert model.event_id == "evt-200"
    assert model.event_type == EventType.QUARANTINE
    assert model.source_agent == AgentId.CODING_01
    assert model.policy_decision == AuthorizationDecision.DENY

    dumped = model.model_dump(mode="json")
    assert dumped["event_id"] == "evt-200"
    assert dumped["event_type"] == "QUARANTINE"
    assert dumped["reason_codes"] == ["AGENT_QUARANTINED"]

    json_str = model.model_dump_json()
    reloaded = SecurityEvent.model_validate_json(json_str)
    assert reloaded.event_id == model.event_id
    assert reloaded.event_type == model.event_type


def test_security_event_validation_failures():
    base_kwargs = {
        "event_id": "evt-001",
        "timestamp": datetime.now(timezone.utc),
        "event_type": EventType.AUTHORIZATION_DECISION,
        "source_agent": AgentId.RESEARCH_01,
        "target_agent": AgentId.DEPLOYMENT_01,
        "request_id": "req-001",
        "task_id": "task-001",
        "action": ActionName.RESEARCH_SEARCH,
        "resource": ResourceName.RESEARCH_DATA,
        "policy_decision": AuthorizationDecision.ALLOW,
    }

    # Empty event_id fails
    with pytest.raises(ValidationError):
        SecurityEvent(**{**base_kwargs, "event_id": ""})

    # Empty request_id fails
    with pytest.raises(ValidationError):
        SecurityEvent(**{**base_kwargs, "request_id": ""})

    # Invalid risk score fails
    with pytest.raises(ValidationError):
        SecurityEvent(**{**base_kwargs, "risk_score": 150})

    with pytest.raises(ValidationError):
        SecurityEvent(**{**base_kwargs, "risk_score": -10})

    # Invalid event_type fails
    with pytest.raises(ValidationError):
        SecurityEvent(**{**base_kwargs, "event_type": "UNKNOWN_EVENT"})  # type: ignore[arg-type]

    # Forbids extra fields
    with pytest.raises(ValidationError):
        SecurityEvent(**{**base_kwargs, "unexpected_field": "val"})
