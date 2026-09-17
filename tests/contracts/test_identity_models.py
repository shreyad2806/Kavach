import pytest
from pydantic import ValidationError

from shield.identity.models import AgentId, AgentIdentity, AgentRole, SecurityState


def test_agent_id_enum_values():
    expected_ids = {
        "orchestrator-01",
        "research-01",
        "coding-01",
        "deployment-01",
        "verification-01",
    }
    actual_ids = {agent.value for agent in AgentId}
    assert actual_ids == expected_ids


def test_agent_role_enum_values():
    expected_roles = {
        "orchestrator",
        "research",
        "coding",
        "deployment",
        "verification",
    }
    actual_roles = {role.value for role in AgentRole}
    assert actual_roles == expected_roles


def test_security_state_enum_values():
    expected_states = {"ACTIVE", "SUSPICIOUS", "QUARANTINED", "TERMINATED"}
    actual_states = {state.value for state in SecurityState}
    assert actual_states == expected_states


def test_agent_identity_creation_valid():
    identity = AgentIdentity(
        agent_id=AgentId.RESEARCH_01,
        role=AgentRole.RESEARCH,
        state=SecurityState.ACTIVE,
    )
    assert identity.agent_id == "research-01"
    assert identity.role == "research"
    assert identity.state == "ACTIVE"


def test_agent_identity_default_state():
    identity = AgentIdentity(
        agent_id=AgentId.DEPLOYMENT_01,
        role=AgentRole.DEPLOYMENT,
    )
    assert identity.state == SecurityState.ACTIVE


def test_agent_identity_serialization_roundtrip():
    raw_json = '{"agent_id": "coding-01", "role": "coding", "state": "QUARANTINED"}'
    model = AgentIdentity.model_validate_json(raw_json)
    assert model.agent_id == AgentId.CODING_01
    assert model.role == AgentRole.CODING
    assert model.state == SecurityState.QUARANTINED

    dumped = model.model_dump()
    assert dumped == {
        "agent_id": "coding-01",
        "role": "coding",
        "state": "QUARANTINED",
    }


def test_agent_identity_invalid_id_fails():
    with pytest.raises(ValidationError):
        AgentIdentity(
            agent_id="unknown-agent",  # type: ignore[arg-type]
            role=AgentRole.RESEARCH,
        )


def test_agent_identity_invalid_role_fails():
    with pytest.raises(ValidationError):
        AgentIdentity(
            agent_id=AgentId.RESEARCH_01,
            role="unauthorized_role",  # type: ignore[arg-type]
        )


def test_agent_identity_invalid_state_fails():
    with pytest.raises(ValidationError):
        AgentIdentity(
            agent_id=AgentId.RESEARCH_01,
            role=AgentRole.RESEARCH,
            state="BANNED",  # type: ignore[arg-type]
        )


def test_agent_identity_forbids_extra_fields():
    with pytest.raises(ValidationError):
        AgentIdentity(
            agent_id=AgentId.RESEARCH_01,
            role=AgentRole.RESEARCH,
            capabilities=["research.search"],  # type: ignore[call-arg]
        )
