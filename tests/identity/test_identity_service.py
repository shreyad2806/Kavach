import pytest

from shield.identity.models import AgentId, AgentIdentity, AgentRole, SecurityState
from shield.identity.service import IdentityService


@pytest.fixture
def service():
    """Provides a fresh IdentityService instance for each test."""
    return IdentityService()


# ==============================================================================
# TEST 1 — KNOWN AGENT
# ==============================================================================

def test_1_known_agent(service):
    """
    Validates that querying a recognized agent returns an AgentIdentity
    with correct identifier, role, and active status.
    """
    agent = service.get_agent("research-01")
    assert agent is not None
    assert isinstance(agent, AgentIdentity)
    assert agent.agent_id == AgentId.RESEARCH_01
    assert agent.agent_id == "research-01"
    assert agent.role == AgentRole.RESEARCH
    assert agent.role == "research"
    assert agent.state == SecurityState.ACTIVE
    assert agent.state == "ACTIVE"


# ==============================================================================
# TEST 2 — UNKNOWN AGENT
# ==============================================================================

def test_2_unknown_agent(service):
    """
    Validates that querying an unprompted/unknown agent identity yields None.
    The service must never dynamically or silently create an identity.
    """
    agent = service.get_agent("unknown-agent")
    assert agent is None

    # Verify no new agent was created in the registry
    all_agents = service.list_agents()
    assert len(all_agents) == 5
    assert not any(a.agent_id == "unknown-agent" for a in all_agents)


# ==============================================================================
# TEST 3 — QUARANTINED AGENT
# ==============================================================================

def test_3_quarantined_agent(service):
    """
    Validates that transitioning an agent to QUARANTINED preserves its validity
    as a recognized identity while recording its isolation state.
    Identity lookup succeeds; downstream authorization will interpret QUARANTINED as ACTION=DENY.
    """
    # Start: research-01 is ACTIVE
    initial_agent = service.get_agent("research-01")
    assert initial_agent is not None
    assert initial_agent.state == SecurityState.ACTIVE

    # Update: transition to QUARANTINED
    service.set_state("research-01", SecurityState.QUARANTINED)

    # Identity lookup succeeds (identity valid, state quarantined)
    quarantined_agent = service.get_agent("research-01")
    assert quarantined_agent is not None
    assert quarantined_agent.agent_id == AgentId.RESEARCH_01
    assert quarantined_agent.state == SecurityState.QUARANTINED

    # Security implication: recognized identity whose actions must later be denied
    # Note: IdentityService does not evaluate authorization; this assertion confirms the state contract
    assert quarantined_agent.state != SecurityState.ACTIVE


# ==============================================================================
# TEST 4 — EVERY CANONICAL AGENT EXISTS
# ==============================================================================

def test_4_every_canonical_agent_exists(service):
    """
    Verifies that exactly the five canonical agents exist in the registry:
    orchestrator-01, research-01, coding-01, deployment-01, verification-01.
    """
    canonical_ids = [
        "orchestrator-01",
        "research-01",
        "coding-01",
        "deployment-01",
        "verification-01",
    ]

    for agent_id in canonical_ids:
        agent = service.get_agent(agent_id)
        assert agent is not None, f"Canonical agent '{agent_id}' missing from registry."
        assert agent.agent_id.value == agent_id

    # Ensure exactly 5 agents exist (no duplicates, no unexpected additions)
    assert len(service.list_agents()) == 5


# ==============================================================================
# TEST 5 — CORRECT ROLE MAPPING
# ==============================================================================

def test_5_correct_role_mapping(service):
    """
    Verifies the static role mappings for each canonical agent:
    - orchestrator-01 -> orchestrator
    - research-01     -> research
    - coding-01       -> coding
    - deployment-01   -> deployment
    - verification-01 -> verification
    """
    expected_mappings = {
        "orchestrator-01": AgentRole.ORCHESTRATOR,
        "research-01": AgentRole.RESEARCH,
        "coding-01": AgentRole.CODING,
        "deployment-01": AgentRole.DEPLOYMENT,
        "verification-01": AgentRole.VERIFICATION,
    }

    for agent_id, expected_role in expected_mappings.items():
        agent = service.get_agent(agent_id)
        assert agent is not None
        assert agent.role == expected_role


# ==============================================================================
# TEST 6 — INVALID STATE UPDATE
# ==============================================================================

def test_6_invalid_state_update(service):
    """
    Verifies that attempting to set an agent to an invalid or unknown state
    raises an error (ValueError) and does not corrupt the agent's current state.
    """
    with pytest.raises(ValueError, match="Invalid security state"):
        service.set_state("research-01", "BANNED_STATE")

    with pytest.raises(ValueError, match="Invalid security state"):
        service.set_state("research-01", "HACKED")

    # Verify research-01 is still in its original state
    agent = service.get_agent("research-01")
    assert agent is not None
    assert agent.state == SecurityState.ACTIVE


# ==============================================================================
# TEST 7 — INVALID AGENT STATE UPDATE
# ==============================================================================

def test_7_invalid_agent_state_update(service):
    """
    Verifies that attempting to set state for an unknown agent fails safely (KeyError).
    The unknown agent must NOT be inserted into the registry.
    """
    with pytest.raises(KeyError, match="not found in identity registry"):
        service.set_state("unknown-agent", SecurityState.QUARANTINED)

    # Ensure unknown agent was not added
    assert service.get_agent("unknown-agent") is None
    assert len(service.list_agents()) == 5


# ==============================================================================
# TEST 8 — STATE ISOLATION
# ==============================================================================

def test_8_state_isolation(service):
    """
    Verifies that changing the security state of one agent (e.g. research-01)
    does not affect any other agent in the registry.
    """
    service.set_state("research-01", SecurityState.QUARANTINED)

    # research-01 is QUARANTINED
    research_agent = service.get_agent("research-01")
    assert research_agent.state == SecurityState.QUARANTINED

    # The other 4 agents remain strictly ACTIVE
    other_agents = [
        "orchestrator-01",
        "coding-01",
        "deployment-01",
        "verification-01",
    ]
    for agent_id in other_agents:
        agent = service.get_agent(agent_id)
        assert agent is not None
        assert agent.state == SecurityState.ACTIVE, (
            f"Agent '{agent_id}' state was modified unexpectedly to {agent.state}"
        )


def test_registry_reset(service):
    """
    Verifies that calling reset() restores the canonical state across all agents.
    """
    service.set_state("research-01", SecurityState.QUARANTINED)
    service.set_state("coding-01", SecurityState.SUSPICIOUS)

    service.reset()

    for agent in service.list_agents():
        assert agent.state == SecurityState.ACTIVE
