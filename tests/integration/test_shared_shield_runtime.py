"""Phase 21B: real P1 tools share Shield runtime security state."""

import pytest

from agents.coding.agent import CodingAgent
from agents.deployment.agent import DeploymentAgent
from agents.orchestrator.agent import OrchestratorAgent
from agents.research.agent import ResearchAgent
from agents.verification.agent import VerificationAgent
from sandbox.runtime.kavach_guard import KavachDeniedError, KavachGuard
from sandbox.runtime.message_bus import MessageBus
from shield.capabilities.models import CapabilityName
from shield.enforcement.quarantine import QuarantineService
from shield.gateway.models import ActionName, AuthorizationDecision, ResourceName
from shield.identity.models import AgentId, SecurityState
from shield.runtime.services import get_shield_runtime, reset_shield_runtime


@pytest.fixture
def p1_runtime():
    """Give each test a fresh process-wide runtime and restore it afterward."""
    runtime = reset_shield_runtime()
    try:
        yield runtime
    finally:
        reset_shield_runtime()


def test_quarantine_persists_across_real_p1_tool_calls(p1_runtime):
    """A real research agent sees its Shield quarantine on separate tools."""
    bus = MessageBus()
    orchestrator = OrchestratorAgent(bus)
    research = ResearchAgent(bus)
    deployment = DeploymentAgent(bus)
    coding = CodingAgent(bus)
    verification = VerificationAgent(bus)
    quarantine = QuarantineService()

    # Every component resolves the one current P1 Shield runtime.
    assert QuarantineService()._identity is p1_runtime.identity_service
    assert get_shield_runtime() is p1_runtime

    orchestrator.delegate("research", {"task": "shared runtime research"})
    assert research.search("shared runtime")["query"] == "shared runtime"
    quarantine.quarantine(AgentId.RESEARCH_01)
    assert p1_runtime.identity_service.get_agent(AgentId.RESEARCH_01).state == SecurityState.QUARANTINED

    with pytest.raises(KavachDeniedError) as search_denial:
        research.search("must be denied")
    assert search_denial.value.result.decision == AuthorizationDecision.DENY
    assert [code.value for code in search_denial.value.result.reason_codes] == ["AGENT_QUARANTINED"]

    with pytest.raises(KavachDeniedError) as read_denial:
        research.tools.read_document("test.txt")
    assert [code.value for code in read_denial.value.result.reason_codes] == ["AGENT_QUARANTINED"]

    # A direct protected deployment attempt from research uses the same state.
    decision = KavachGuard().authorize(
        "research",
        ActionName.DEPLOYMENT_DEPLOY,
        ResourceName.PRODUCTION_ENVIRONMENT,
        CapabilityName.RESEARCH_SEARCH,
    )
    assert decision.decision == AuthorizationDecision.DENY
    assert [code.value for code in decision.reason_codes] == ["AGENT_QUARANTINED"]

    # Quarantining research does not affect other real P1 agents.
    assert deployment.simulate_deployment("staging")["status"] == "SUCCESS"
    assert coding.run_tests()["status"] == "PASSED"
    assert verification.run_tests()["status"] == "PASSED"

    quarantine.release(AgentId.RESEARCH_01)
    assert research.search("restored")["query"] == "restored"


def test_default_guards_resolve_the_authoritative_runtime_after_reset():
    """Module-level real-tool guards do not retain an obsolete state container."""
    first = reset_shield_runtime()
    bus = MessageBus()
    research = ResearchAgent(bus)

    assert research.search("first runtime")["query"] == "first runtime"

    second = reset_shield_runtime()
    assert second is get_shield_runtime()
    assert second is not first
    QuarantineService().quarantine(AgentId.RESEARCH_01)

    with pytest.raises(KavachDeniedError) as denial:
        research.search("second runtime quarantine")
    assert [code.value for code in denial.value.result.reason_codes] == ["AGENT_QUARANTINED"]

    QuarantineService().release(AgentId.RESEARCH_01)
    reset_shield_runtime()
