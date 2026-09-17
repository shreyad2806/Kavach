import pytest
from pydantic import ValidationError

from shield.identity.models import AgentId
from shield.provenance.models import Provenance


def test_provenance_single_hop_valid():
    prov = Provenance(
        task_origin=AgentId.ORCHESTRATOR_01,
        delegation_chain=[AgentId.ORCHESTRATOR_01],
    )
    assert prov.task_origin == AgentId.ORCHESTRATOR_01
    assert prov.delegation_chain == [AgentId.ORCHESTRATOR_01]


def test_provenance_multi_hop_valid():
    prov = Provenance(
        task_origin=AgentId.ORCHESTRATOR_01,
        delegation_chain=[AgentId.ORCHESTRATOR_01, AgentId.RESEARCH_01],
    )
    assert prov.task_origin == AgentId.ORCHESTRATOR_01
    assert len(prov.delegation_chain) == 2
    assert prov.delegation_chain[1] == AgentId.RESEARCH_01


def test_provenance_serialization_roundtrip():
    raw_dict = {
        "task_origin": "orchestrator-01",
        "delegation_chain": ["orchestrator-01", "research-01"],
    }
    model = Provenance.model_validate(raw_dict)
    assert model.task_origin == AgentId.ORCHESTRATOR_01
    assert model.delegation_chain == [AgentId.ORCHESTRATOR_01, AgentId.RESEARCH_01]

    dumped = model.model_dump()
    assert dumped == raw_dict


def test_provenance_empty_delegation_chain_fails():
    with pytest.raises(ValidationError):
        Provenance(
            task_origin=AgentId.ORCHESTRATOR_01,
            delegation_chain=[],
        )


def test_provenance_origin_mismatch_with_chain_fails():
    # Chain starts with research-01, but task_origin claims orchestrator-01
    with pytest.raises(ValidationError):
        Provenance(
            task_origin=AgentId.ORCHESTRATOR_01,
            delegation_chain=[AgentId.RESEARCH_01],
        )


def test_provenance_invalid_agent_in_chain_fails():
    with pytest.raises(ValidationError):
        Provenance(
            task_origin=AgentId.ORCHESTRATOR_01,
            delegation_chain=[AgentId.ORCHESTRATOR_01, "unknown-agent"],  # type: ignore[list-item]
        )


def test_provenance_forbids_extra_fields():
    with pytest.raises(ValidationError):
        Provenance(
            task_origin=AgentId.ORCHESTRATOR_01,
            delegation_chain=[AgentId.ORCHESTRATOR_01],
            is_valid=True,  # type: ignore[call-arg]
        )
