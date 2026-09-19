"""Task routing: the submitted task decides which real agents and protected
tools execute.

The activity stream is a record of what actually ran, so it cannot be one
generic sequence for every task.  These tests prove three genuinely different
paths, all of which still execute through the real P1 boundary:

    AgentTools -> KavachGuard -> get_shield_runtime() -> authorize()

No events are synthesised anywhere: every event asserted here was emitted by a
real authorization decision, and none of them is fabricated by the supervisor.
"""

import pytest

from agents.supervisor import WorkflowStatus, WorkflowSupervisor
from agents.supervisor.service import (
    TaskKind,
    classify_task,
    research_source_document,
    research_topic,
)
from shield.identity.models import SecurityState
from shield.runtime.services import reset_shield_runtime
from shield.telemetry.session import clear_events, list_events

ARITHMETIC_TASK = "Calculate 12 * 7 + 5 and verify the result."
RESEARCH_TASK = "Research the Fibonacci sequence and summarize it."
DEPLOYMENT_TASK = "Prepare a frontend deployment preview."

ARITHMETIC_PATH = [
    ("orchestrator-01", "orchestrator.delegate", "workspace"),
    ("coding-01", "coding.read", "workspace"),
    ("coding-01", "coding.write", "workspace"),
    ("coding-01", "coding.test", "test-environment"),
    ("verification-01", "verification.test", "test-environment"),
    ("deployment-01", "deployment.preview", "staging-environment"),
]

RESEARCH_PATH = [
    ("orchestrator-01", "orchestrator.delegate", "workspace"),
    ("research-01", "research.search", "research-data"),
    ("research-01", "research.read", "research-data"),
]

DEPLOYMENT_PATH = [
    ("orchestrator-01", "orchestrator.delegate", "workspace"),
    ("coding-01", "coding.read", "workspace"),
    ("verification-01", "verification.test", "test-environment"),
    ("deployment-01", "deployment.preview", "staging-environment"),
]


@pytest.fixture
def p1_runtime():
    """Fresh process-wide Shield runtime + clean session telemetry per test."""
    runtime = reset_shield_runtime()
    clear_events()
    try:
        yield runtime
    finally:
        reset_shield_runtime()
        clear_events()


def run(task: str):
    """Execute a task through the real supervisor and return (workflow, events)."""
    supervisor = WorkflowSupervisor()
    workflow_id = supervisor.create_workflow(task)
    workflow = supervisor.start_workflow(workflow_id)
    events = list_events(workflow_id=workflow_id)
    # Oldest first, which is execution order.
    return workflow, list(reversed(events))


def path_of(events):
    return [(e["source_agent"], e["action"], e["resource"]) for e in events]


# ============================================================================
# Classification
# ============================================================================

@pytest.mark.parametrize(
    "task,expected",
    [
        (ARITHMETIC_TASK, TaskKind.CODING),
        ("compute fibonacci", TaskKind.CODING),
        ("implement the parser", TaskKind.CODING),
        ("baseline", TaskKind.CODING),
        (RESEARCH_TASK, TaskKind.RESEARCH),
        ("summarize the incident report", TaskKind.RESEARCH),
        ("investigate the timeout", TaskKind.RESEARCH),
        (DEPLOYMENT_TASK, TaskKind.DEPLOYMENT),
        ("deploy to staging", TaskKind.DEPLOYMENT),
        ("release the service", TaskKind.DEPLOYMENT),
    ],
)
def test_classify_task(task, expected):
    assert classify_task(task) is expected


def test_research_topic_and_document_are_task_derived():
    assert research_topic(RESEARCH_TASK) == "fibonacci sequence"
    assert research_source_document(RESEARCH_TASK) == "fibonacci.txt"
    # Deterministic: the same task always resolves to the same source.
    assert research_source_document(RESEARCH_TASK) == research_source_document(RESEARCH_TASK)


# ============================================================================
# A. Coding / arithmetic path
# ============================================================================

def test_coding_task_runs_the_coding_path(p1_runtime):
    workflow, events = run(ARITHMETIC_TASK)

    assert workflow.status == WorkflowStatus.COMPLETED
    assert workflow.error is None
    assert workflow.result["task_kind"] == "coding"
    assert workflow.result["value"] == 89
    assert path_of(events) == ARITHMETIC_PATH

    # Research must NOT be invoked for a coding task.
    assert not any(e["source_agent"] == "research-01" for e in events)
    # Every decision is a real ALLOW for this workflow.
    assert all(e["policy_decision"] == "ALLOW" for e in events)
    assert all(e["workflow_id"] == workflow.workflow_id for e in events)


# ============================================================================
# B. Research path
# ============================================================================

def test_research_task_runs_the_research_path(p1_runtime):
    workflow, events = run(RESEARCH_TASK)

    assert workflow.status == WorkflowStatus.COMPLETED
    assert workflow.error is None
    assert workflow.result["task_kind"] == "research"
    assert path_of(events) == RESEARCH_PATH
    assert workflow.result["source_document"] == "fibonacci.txt"

    # A research task must not produce coding/deployment work.
    actions = {e["action"] for e in events}
    assert "coding.write" not in actions
    assert "coding.test" not in actions
    assert "deployment.preview" not in actions

    # Only research.search / research.read capabilities are exercised, and the
    # research agent is read-only (no research.write anywhere).
    caps = {e["capability"] for e in events}
    assert caps == {"orchestrator.delegate", "research.search", "research.read"}


def test_research_task_reads_a_real_document_when_present(p1_runtime):
    """The read is a real authorization; the document is whatever exists."""
    workflow, events = run(RESEARCH_TASK)
    read_event = next(e for e in events if e["action"] == "research.read")
    assert read_event["resource"] == "research-data"
    assert workflow.result["document_status"] in {"FOUND", "NOT_FOUND"}


def test_research_task_with_unknown_subject_still_completes(p1_runtime):
    """A missing source document must not fail the workflow or invent content."""
    workflow, events = run("Research the migration strategy for quark engines and summarize it")
    assert workflow.status == WorkflowStatus.COMPLETED
    assert workflow.result["task_kind"] == "research"
    assert workflow.result["document_status"] == "NOT_FOUND"
    assert path_of(events) == RESEARCH_PATH


# ============================================================================
# C. Deployment path
# ============================================================================

def test_deployment_task_runs_the_deployment_path(p1_runtime):
    workflow, events = run(DEPLOYMENT_TASK)

    assert workflow.status == WorkflowStatus.COMPLETED
    assert workflow.error is None
    assert workflow.result["task_kind"] == "deployment"
    assert path_of(events) == DEPLOYMENT_PATH

    # The protected deployment action is a staging preview, and nothing more.
    preview = next(e for e in events if e["action"] == "deployment.preview")
    assert preview["resource"] == "staging-environment"
    assert preview["capability"] == "deployment.preview"

    actions = {e["action"] for e in events}
    assert "coding.write" not in actions
    assert "coding.test" not in actions
    assert "research.search" not in actions


def test_deployment_request_for_production_still_only_previews_staging(p1_runtime):
    """A production-worded task must not turn the staging preview into a deploy."""
    workflow, events = run("Deploy the frontend to production")

    assert workflow.status == WorkflowStatus.COMPLETED
    assert workflow.result["task_kind"] == "deployment"
    assert workflow.result["requested_target"] == "production"
    assert workflow.result["deployed_target"] == "staging"
    # Every deployment action stays a staging preview.
    for event in events:
        if event["action"].startswith("deployment."):
            assert event["action"] == "deployment.preview"
            assert event["resource"] == "staging-environment"


# ============================================================================
# D. Cross-cutting: paths differ, security is untouched
# ============================================================================

def test_the_three_paths_produce_different_activity(p1_runtime):
    _, coding_events = run(ARITHMETIC_TASK)
    _, research_events = run(RESEARCH_TASK)
    _, deployment_events = run(DEPLOYMENT_TASK)

    coding_set = {e["action"] for e in coding_events}
    research_set = {e["action"] for e in research_events}
    deployment_set = {e["action"] for e in deployment_events}

    assert len(coding_events) != len(research_events)
    assert coding_set != research_set
    assert research_set != deployment_set
    assert deployment_set != coding_set


def test_normal_tasks_quarantine_nobody(p1_runtime):
    """A legitimate task must never leave an agent quarantined."""
    for task in (ARITHMETIC_TASK, RESEARCH_TASK, DEPLOYMENT_TASK):
        workflow, events = run(task)
        assert workflow.status == WorkflowStatus.COMPLETED
        assert not any(e["policy_decision"] == "DENY" for e in events)
        runtime = p1_runtime
        assert all(
            agent.state is SecurityState.ACTIVE
            for agent in runtime.identity_service.list_agents()
        )
        assert runtime.identity_service.list_agents()
