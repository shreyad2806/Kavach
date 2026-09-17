import pytest
from pydantic import ValidationError

from kavach.capabilities.models import Capability, CapabilityName


def test_capability_name_vocabulary():
    expected_capabilities = {
        "research.search",
        "research.read",
        "coding.read",
        "coding.write",
        "coding.test",
        "deployment.preview",
        "deployment.production",
        "verification.test",
        "orchestrator.delegate",
        "orchestrator.coordinate",
    }
    actual_capabilities = {c.value for c in CapabilityName}
    assert actual_capabilities == expected_capabilities


def test_capability_creation_valid():
    cap = Capability(
        name=CapabilityName.RESEARCH_SEARCH,
        description="Allows querying research datasets and search tools.",
    )
    assert cap.name == "research.search"
    assert cap.description == "Allows querying research datasets and search tools."


def test_capability_serialization_roundtrip():
    raw_json = '{"name": "deployment.production", "description": "Production release deployment."}'
    model = Capability.model_validate_json(raw_json)
    assert model.name == CapabilityName.DEPLOYMENT_PRODUCTION

    dumped = model.model_dump()
    assert dumped == {
        "name": "deployment.production",
        "description": "Production release deployment.",
    }


def test_capability_disallows_arbitrary_string():
    with pytest.raises(ValidationError):
        Capability(
            name="arbitrary.capability",  # type: ignore[arg-type]
            description="Arbitrary action",
        )


def test_capability_does_not_contain_action_names():
    # 'deployment.deploy' is an action, NOT a capability
    with pytest.raises(ValidationError):
        Capability(
            name="deployment.deploy",  # type: ignore[arg-type]
            description="Deploy to environment",
        )


def test_capability_empty_description_fails():
    with pytest.raises(ValidationError):
        Capability(
            name=CapabilityName.CODING_READ,
            description="",
        )


def test_capability_forbids_extra_fields():
    with pytest.raises(ValidationError):
        Capability(
            name=CapabilityName.CODING_READ,
            description="Read code",
            target_resource="workspace",  # type: ignore[call-arg]
        )
