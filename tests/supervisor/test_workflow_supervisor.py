"""Phase 21C: WorkflowSupervisor — lifecycle, security preservation, ShieldRuntime reuse.

Covers:
- A/B: create/start lifecycle (CREATED -> RUNNING -> COMPLETED)
- C:   unique workflow IDs and independent lifecycle state
- D/E: cooperative stop (before and during execution)
- F:   failure handling (error retained, FAILED, no silent swallow)
- G:   Kavach DENY preserved (never reported as success)
- H:   workflow_id correlation across supervisor events
- I:   independent lifecycle state across workflows
- J:   supervisor maintains NO second agent security state
- K:   Phase 21B shared quarantine invariant through the actual P1 tools
"""

import pytest

from agents.coding.agent import CodingAgent
from agents.deployment.agent import DeploymentAgent
from agents.research.agent import ResearchAgent
from agents.supervisor import (
    WorkflowNotFoundError,
    WorkflowStatus,
    WorkflowSupervisor,
)
from agents.verification.agent import VerificationAgent
from sandbox.runtime.message_bus import MessageBus
from sandbox.runtime.kavach_guard import KavachDeniedError
from shield.enforcement.quarantine import QuarantineService
from shield.gateway.models import AuthorizationDecision
from shield.identity.models import AgentId, SecurityState
from shield.runtime.services import get_shield_runtime, reset_shield_runtime


@pytest.fixture
def p1_runtime():
    """Fresh process-wide Shield runtime per test (same pattern as Phase 21B)."""
    runtime = reset_shield_runtime()
    try:
        yield runtime
    finally:
        reset_shield_runtime()


# ============================================================================
# A. create workflow
# ============================================================================

def test_create_workflow_starts_in_created_state(p1_runtime):
    supervisor = WorkflowSupervisor()
    workflow_id = supervisor.create_workflow("Research Fibonacci")

    workflow = supervisor.get_workflow(workflow_id)
    assert workflow.status == WorkflowStatus.CREATED
    assert workflow.task == "Research Fibonacci"
    assert workflow.workflow_id.startswith("wf-")
    assert workflow.started_at is None
    assert workflow.completed_at is None
    assert workflow.result is None
    assert workflow.error is None


def test_create_workflow_rejects_empty_task(p1_runtime):
    supervisor = WorkflowSupervisor()
    with pytest.raises(ValueError):
        supervisor.create_workflow("   ")


# ============================================================================
# B. start workflow -> COMPLETED (real P1 agents, real KavachGuard)
# ============================================================================

def test_start_workflow_runs_to_completion(p1_runtime):
    supervisor = WorkflowSupervisor()
    workflow_id = supervisor.create_workflow("Research a simple Fibonacci algorithm.")

    workflow = supervisor.start_workflow(workflow_id)

    assert workflow.status == WorkflowStatus.COMPLETED
    assert workflow.started_at is not None
    assert workflow.completed_at is not None
    assert workflow.error is None

    # Canonical phases executed in order through the real P1 path.
    phase_agents = [phase.agent for phase in workflow.phases]
    assert phase_agents == [
        "orchestrator",
        "research",
        "orchestrator",
        "coding",
        "verification",
        "orchestrator",
        "deployment",
    ]
    assert all(
        phase.status == WorkflowStatus.COMPLETED for phase in workflow.phases
    )

    # Result snapshot collected from real agent operations.
    assert workflow.result is not None
    assert workflow.result["coding"]["status"] == "PASSED"
    assert workflow.result["verification"]["status"] == "PASSED"
    assert workflow.result["deployment"]["status"] == "SUCCESS"
    assert workflow.result["messages_received"] >= 3

    # All agents remain ACTIVE — supervisor created no security side effects.
    for agent_id in (
        AgentId.ORCHESTRATOR_01,
        AgentId.RESEARCH_01,
        AgentId.CODING_01,
        AgentId.DEPLOYMENT_01,
        AgentId.VERIFICATION_01,
    ):
        assert (
            p1_runtime.identity_service.get_agent(agent_id).state
            == SecurityState.ACTIVE
        )


def test_start_workflow_twice_is_rejected(p1_runtime):
    supervisor = WorkflowSupervisor()
    workflow_id = supervisor.create_workflow("task")
    supervisor.start_workflow(workflow_id)

    with pytest.raises(RuntimeError, match="cannot start"):
        supervisor.start_workflow(workflow_id)


# ============================================================================
# C. unique workflow IDs / I. independent lifecycle state
# ============================================================================

def test_workflow_ids_are_unique(p1_runtime):
    supervisor = WorkflowSupervisor()
    ids = {supervisor.create_workflow(f"task-{i}") for i in range(10)}
    assert len(ids) == 10


def test_workflows_have_independent_lifecycle_state(p1_runtime):
    supervisor = WorkflowSupervisor()
    first_id = supervisor.create_workflow("first")
    second_id = supervisor.create_workflow("second")

    supervisor.start_workflow(first_id)

    first = supervisor.get_workflow(first_id)
    second = supervisor.get_workflow(second_id)
    assert first.status == WorkflowStatus.COMPLETED
    assert second.status == WorkflowStatus.CREATED
    assert first.events is not second.events
    assert second.events[0].event_type.value == "WORKFLOW_CREATED"


def test_unknown_workflow_id_raises(p1_runtime):
    supervisor = WorkflowSupervisor()
    with pytest.raises(WorkflowNotFoundError):
        supervisor.get_workflow("wf-does-not-exist")
    with pytest.raises(WorkflowNotFoundError):
        supervisor.start_workflow("wf-does-not-exist")
    with pytest.raises(WorkflowNotFoundError):
        supervisor.stop_workflow("wf-does-not-exist")
    with pytest.raises(WorkflowNotFoundError):
        supervisor.get_workflow_events("wf-does-not-exist")


# ============================================================================
# D. stop before execution
# ============================================================================

def test_stop_before_execution_marks_workflow_stopped(p1_runtime):
    supervisor = WorkflowSupervisor()
    workflow_id = supervisor.create_workflow("never runs")

    stopped = supervisor.stop_workflow(workflow_id)
    assert stopped.status == WorkflowStatus.STOPPED

    with pytest.raises(RuntimeError, match="cannot start"):
        supervisor.start_workflow(workflow_id)


# ============================================================================
# E. cooperative stop during execution
# ============================================================================

def test_cooperative_stop_during_execution(p1_runtime, monkeypatch):
    supervisor = WorkflowSupervisor()
    workflow_id = supervisor.create_workflow("stop me mid-flight")

    real_research_agent = ResearchAgent

    class StoppingResearchAgent(real_research_agent):
        """Requests a cooperative stop from inside the research phase."""

        def __init__(self, bus):
            super().__init__(bus)

        def search(self, query):
            supervisor.stop_workflow(workflow_id)
            return super().search(query)

    monkeypatch.setattr(
        "agents.supervisor.service.ResearchAgent", StoppingResearchAgent
    )

    workflow = supervisor.start_workflow(workflow_id)

    assert workflow.status == WorkflowStatus.STOPPED
    # Stop was requested while RUNNING, then honored at the next phase gate.
    event_types = [event.event_type.value for event in workflow.events]
    assert "WORKFLOW_STOP_REQUESTED" in event_types
    assert event_types[-1] == "WORKFLOW_STOPPED"
    # Later phases never started.
    phase_agents = [phase.agent for phase in workflow.phases]
    assert "coding" not in phase_agents
    assert "deployment" not in phase_agents
    assert "verification" not in phase_agents
    assert workflow.current_agent is None


# ============================================================================
# F. workflow failure
# ============================================================================

def test_workflow_failure_is_retained_not_swallowed(p1_runtime, monkeypatch):
    supervisor = WorkflowSupervisor()
    workflow_id = supervisor.create_workflow("doomed workflow")

    class ExplodingResearchAgent:
        """Stands in for ResearchAgent and fails mid-workflow."""

        def __init__(self, bus):
            self.bus = bus

        def search(self, query):
            raise RuntimeError("boom: research subsystem crashed")

        def write_research(self, filename, content):  # pragma: no cover
            return "unused"

        def send_result(self, receiver, content):  # pragma: no cover
            return None

    monkeypatch.setattr(
        "agents.supervisor.service.ResearchAgent", ExplodingResearchAgent
    )

    workflow = supervisor.start_workflow(workflow_id)

    assert workflow.status == WorkflowStatus.FAILED
    assert workflow.error is not None
    assert "boom: research subsystem crashed" in workflow.error
    assert workflow.completed_at is not None
    # The failing phase is retained as incomplete.
    research_phase = [p for p in workflow.phases if p.agent == "research"][-1]
    assert research_phase.status == WorkflowStatus.RUNNING
    assert "boom" in (workflow.summary()["error"] or "")


# ============================================================================
# G. Kavach protected DENY preserved by the supervisor
# ============================================================================

def test_kavach_deny_fails_workflow_and_is_never_reported_as_success(
    p1_runtime,
):
    supervisor = WorkflowSupervisor()
    workflow_id = supervisor.create_workflow("attack workflow")

    # Quarantine research-01 through the REAL Shield enforcement service.
    QuarantineService().quarantine(AgentId.RESEARCH_01)

    workflow = supervisor.start_workflow(workflow_id)

    # The workflow reached the research phase and was DENIED by Kavach.
    assert workflow.status == WorkflowStatus.FAILED
    assert workflow.error is not None
    assert "KavachDeniedError" in workflow.error
    assert "AGENT_QUARANTINED" in workflow.error

    # The denial is exposed verbatim — never converted into success.
    assert workflow.result is not None
    assert workflow.result["kavach_denied"] is True
    assert workflow.result["decision"] == AuthorizationDecision.DENY.value
    assert workflow.result["reason_codes"] == ["AGENT_QUARANTINED"]
    assert workflow.result["request_id"]

    # And the workflow result snapshot never claims the protected action ran.
    assert "coding" not in (workflow.result or {})
    event_types = [event.event_type.value for event in workflow.events]
    assert "WORKFLOW_FAILED" in event_types


# ============================================================================
# H. workflow_id correlation in supervisor events
# ============================================================================

def test_supervisor_events_correlate_by_workflow_id(p1_runtime):
    supervisor = WorkflowSupervisor()
    workflow_id = supervisor.create_workflow("correlated workflow")
    supervisor.start_workflow(workflow_id)

    events = supervisor.get_workflow_events(workflow_id)
    assert events, "supervisor must record lifecycle events"
    assert all(event.workflow_id == workflow_id for event in events)
    assert len({event.event_id for event in events}) == len(events)
    assert events[0].event_type.value == "WORKFLOW_CREATED"
    assert events[1].event_type.value == "WORKFLOW_STARTED"
    assert events[-1].event_type.value == "WORKFLOW_COMPLETED"
    # Phase lifecycle is visible per agent for GET /workflows/:id/events.
    phase_started = [e for e in events if e.event_type.value == "PHASE_STARTED"]
    assert {e.agent for e in phase_started} == {
        "orchestrator", "research", "coding", "verification", "deployment",
    }


# ============================================================================
# J. supervisor keeps NO second agent security state
# ============================================================================

def test_supervisor_does_not_duplicate_shield_security_state(p1_runtime):
    supervisor = WorkflowSupervisor()
    supervisor.create_workflow("state check")
    supervisor.start_workflow(supervisor.get_workflow_events.__self__ and
                              supervisor._workflows and
                              next(iter(supervisor._workflows)))

    # No shadow identity/quarantine/security services on the supervisor.
    for attr in (
        "identity_service",
        "capability_service",
        "cedar_adapter",
        "incident_service",
        "quarantine_service",
        "agents",
        "identities",
    ):
        assert not hasattr(supervisor, attr)

    # The ONE runtime is the shared ShieldRuntime; quarantine state created
    # outside the supervisor is exactly what P1 tools observe.
    runtime = get_shield_runtime()
    assert QuarantineService()._identity is runtime.identity_service
    assert runtime.identity_service.get_agent(AgentId.RESEARCH_01).state == (
        SecurityState.ACTIVE
    )


# ============================================================================
# K. Phase 21B shared quarantine invariant through the supervisor + real tools
# ============================================================================

def test_quarantine_propagates_into_supervised_p1_workflow(p1_runtime):
    """The critical Phase 21B invariant, exercised through the supervisor.

    1. research-01 ACTIVE
    2. supervised workflow with legitimate research ops -> COMPLETED (ALLOW)
    3. real QuarantineService quarantines research-01
    4. second supervised workflow performs real ResearchTools operations
    5. Kavach DENIES with exactly AGENT_QUARANTINED
    6. deployment/coding/verification agents remain functional
    7. release research-01
    8. legitimate research operation works again
    """
    supervisor = WorkflowSupervisor()
    bus = MessageBus()
    research = ResearchAgent(bus)
    deployment = DeploymentAgent(bus)
    coding = CodingAgent(bus)
    verification = VerificationAgent(bus)
    quarantine = QuarantineService()

    # 1. ACTIVE
    assert (
        p1_runtime.identity_service.get_agent(AgentId.RESEARCH_01).state
        == SecurityState.ACTIVE
    )

    # 2. Legitimate supervised workflow -> COMPLETED.
    first_id = supervisor.create_workflow("legitimate research run")
    assert supervisor.start_workflow(first_id).status == WorkflowStatus.COMPLETED

    # 3. Real quarantine via shared ShieldRuntime.
    quarantine.quarantine(AgentId.RESEARCH_01)
    assert (
        p1_runtime.identity_service.get_agent(AgentId.RESEARCH_01).state
        == SecurityState.QUARANTINED
    )

    # 4/5. Supervised workflow hits real ResearchTools -> DENIED.
    second_id = supervisor.create_workflow("post-quarantine attempt")
    denied_workflow = supervisor.start_workflow(second_id)
    assert denied_workflow.status == WorkflowStatus.FAILED
    assert denied_workflow.result["kavach_denied"] is True
    assert denied_workflow.result["reason_codes"] == ["AGENT_QUARANTINED"]

    # Tool-level: exactly AGENT_QUARANTINED, nothing else.
    with pytest.raises(KavachDeniedError) as denial:
        research.search("must be denied")
    assert denial.value.result.decision == AuthorizationDecision.DENY
    assert [rc.value for rc in denial.value.result.reason_codes] == [
        "AGENT_QUARANTINED"
    ]

    # 6. Quarantine is agent-specific: other real agents keep working.
    assert deployment.simulate_deployment("staging")["status"] == "SUCCESS"
    assert coding.run_tests()["status"] == "PASSED"
    assert verification.run_tests()["status"] == "PASSED"

    # 7. Release through the same Shield enforcement service.
    quarantine.release(AgentId.RESEARCH_01)
    assert (
        p1_runtime.identity_service.get_agent(AgentId.RESEARCH_01).state
        == SecurityState.ACTIVE
    )

    # 8. Legitimate research works again — via tools AND supervisor.
    assert research.search("restored")["query"] == "restored"
    third_id = supervisor.create_workflow("post-release research run")
    assert supervisor.start_workflow(third_id).status == WorkflowStatus.COMPLETED
