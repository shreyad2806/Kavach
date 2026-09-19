"""P1 Workflow Supervisor — programmatic lifecycle for the multi-agent workflow.

The supervisor owns WORKFLOW LIFECYCLE only:

    create_workflow(task)            -> workflow_id
    start_workflow(workflow_id)      -> Workflow (runs synchronously)
    stop_workflow(workflow_id)       -> cooperative stop
    get_workflow(workflow_id)        -> Workflow
    get_workflow_events(workflow_id) -> supervisor lifecycle events

Security is NOT implemented here.  Every protected side effect performed
during execution goes through the real P1 path:

    Agent method -> AgentTools -> KavachGuard -> ShieldRuntime -> authorize()

The supervisor reuses the shared ShieldRuntime (Phase 21B) via the real
agents, tools, and QuarantineService.  It never instantiates its own
IdentityService or duplicates Shield state.

Kavach security DENYs are preserved: a denied protected action raises
KavachDeniedError inside the workflow body, which marks the workflow
FAILED and records the denial -- the unauthorized action is NEVER
reported as successful and is NEVER executed.
"""

import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Callable

from agents.common.messages import AgentMessage
from agents.coding.agent import CodingAgent
from agents.deployment.agent import DeploymentAgent
from agents.orchestrator.agent import OrchestratorAgent
from agents.research.agent import ResearchAgent
from agents.verification.agent import VerificationAgent
from agents.supervisor.models import (
    PhaseRun,
    Workflow,
    WorkflowEvent,
    WorkflowEventType,
    WorkflowStatus,
)
from sandbox.runtime.message_bus import MessageBus
from sandbox.runtime.kavach_guard import KavachDeniedError

logger = logging.getLogger(__name__)


class WorkflowNotFoundError(KeyError):
    """Raised when a workflow_id is unknown to the supervisor."""


class WorkflowSupervisor:
    """Registry and lifecycle driver for supervised P1 workflows.

    Process-local and in-memory by design (no database persistence yet).
    The workflow_id is the correlation identifier for all supervisor
    lifecycle events.
    """

    def __init__(self) -> None:
        self._workflows: dict[str, Workflow] = {}
        # Cooperative stop: check-workflow callbacks consulted before each
        # phase starts.  Fresh per workflow so state never leaks between runs.
        self._stop_checks: dict[str, Callable[[], bool]] = {}

    # ------------------------------------------------------------------
    # Programmatic API
    # ------------------------------------------------------------------

    def create_workflow(self, task: str) -> str:
        """Create a workflow in CREATED state and return its unique id."""
        if not isinstance(task, str) or not task.strip():
            raise ValueError("task must be a non-empty string")

        workflow_id = f"wf-{uuid.uuid4().hex[:12]}"
        workflow = Workflow(workflow_id=workflow_id, task=task)
        self._workflows[workflow_id] = workflow
        self._stop_checks[workflow_id] = self._make_stop_check(workflow_id)

        self._record_event(
            workflow, WorkflowEventType.WORKFLOW_CREATED, detail={"task": task}
        )
        return workflow_id

    def start_workflow(self, workflow_id: str) -> Workflow:
        """Validate and synchronously execute the workflow.

        CREATED -> RUNNING -> (COMPLETED | FAILED | STOPPED).
        """
        workflow = self._get_or_raise(workflow_id)
        if workflow.status != WorkflowStatus.CREATED:
            raise RuntimeError(
                f"Workflow {workflow_id} cannot start from status "
                f"{workflow.status.value} (expected CREATED)"
            )

        workflow.status = WorkflowStatus.RUNNING
        workflow.started_at = datetime.now(timezone.utc)
        self._record_event(workflow, WorkflowEventType.WORKFLOW_STARTED)

        try:
            self._execute(workflow)
        except _WorkflowStopped:
            workflow.status = WorkflowStatus.STOPPED
            workflow.completed_at = datetime.now(timezone.utc)
            self._record_event(workflow, WorkflowEventType.WORKFLOW_STOPPED)
        except KavachDeniedError as exc:
            # Kavach DENY is preserved verbatim: the unauthorized action was
            # NOT executed.  The workflow fails with the security denial.
            workflow.status = WorkflowStatus.FAILED
            workflow.error = self._describe_denial(exc)
            workflow.result = self._denial_result(exc)
            workflow.completed_at = datetime.now(timezone.utc)
            self._record_event(
                workflow,
                WorkflowEventType.WORKFLOW_FAILED,
                detail={
                    "error": workflow.error,
                    "kavach_denied": True,
                    "reason_codes": [
                        rc.value for rc in (exc.result.reason_codes if exc.result else [])
                    ],
                },
            )
        except Exception as exc:  # noqa: BLE001 - supervisor must retain any failure
            workflow.status = WorkflowStatus.FAILED
            workflow.error = f"{type(exc).__name__}: {exc}"
            workflow.completed_at = datetime.now(timezone.utc)
            self._record_event(
                workflow,
                WorkflowEventType.WORKFLOW_FAILED,
                detail={"error": workflow.error},
            )

        if workflow.status == WorkflowStatus.RUNNING:
            workflow.status = WorkflowStatus.COMPLETED
            workflow.completed_at = datetime.now(timezone.utc)
            self._record_event(workflow, WorkflowEventType.WORKFLOW_COMPLETED)

        return workflow

    def stop_workflow(self, workflow_id: str) -> Workflow:
        """Cooperatively stop a workflow.

        RUNNING -> STOPPING (new phases will not start; the in-flight
        operation finishes), then the executor transitions to STOPPED.
        CREATED workflows transition directly to STOPPED.  This never
        touches agent security state -- Shield owns that.
        """
        workflow = self._get_or_raise(workflow_id)
        if workflow.status == WorkflowStatus.CREATED:
            workflow.status = WorkflowStatus.STOPPED
            workflow.completed_at = datetime.now(timezone.utc)
            self._record_event(workflow, WorkflowEventType.WORKFLOW_STOPPED)
        elif workflow.status == WorkflowStatus.RUNNING:
            workflow.status = WorkflowStatus.STOPPING
            self._record_event(workflow, WorkflowEventType.WORKFLOW_STOP_REQUESTED)
        return workflow

    def get_workflow(self, workflow_id: str) -> Workflow:
        """Return the workflow object for an id."""
        return self._get_or_raise(workflow_id)

    def get_workflow_events(self, workflow_id: str) -> list[WorkflowEvent]:
        """Return supervisor lifecycle events correlated by workflow_id."""
        return list(self._get_or_raise(workflow_id).events)

    # ------------------------------------------------------------------
    # Canonical workflow body (single authoritative execution path)
    # ------------------------------------------------------------------

    def _execute(self, workflow: Workflow) -> dict[str, Any]:
        """Execute the canonical 12-step P1 workflow.

        This is the ONE authoritative workflow execution path (moved from
        scripts/run_workflow.py).  Agents, MessageBus, AgentTools and the
        KavachGuard enforcement boundary are the real P1 components; the
        supervisor adds only phase lifecycle tracking and cooperative stop.
        """
        bus = MessageBus()
        workflow.result = {}

        orchestrator = OrchestratorAgent(bus)
        research = ResearchAgent(bus)
        coding = CodingAgent(bus)
        deployment = DeploymentAgent(bus)
        verification = VerificationAgent(bus)

        # -- Phase: orchestrator -> research -------------------------------
        self._phase(workflow, "orchestrator", self._stop_check_for(workflow.workflow_id))
        orchestrator.delegate(
            "research", {"task": f"Research: {workflow.task}"}
        )
        self._phase_done(workflow, "orchestrator")

        self._phase(workflow, "research", self._stop_check_for(workflow.workflow_id))
        research.search(workflow.task)
        research.write_research(
            "fibonacci.txt", f"Research on '{workflow.task}' completed."
        )
        research.send_result(
            "orchestrator",
            {"status": "RESEARCH_COMPLETE", "topic": workflow.task},
        )
        self._phase_done(workflow, "research")

        # -- Phase: orchestrator -> coding ---------------------------------
        self._phase(workflow, "orchestrator", self._stop_check_for(workflow.workflow_id))
        orchestrator.delegate("coding", {"task": f"Implement: {workflow.task}"})
        self._phase_done(workflow, "orchestrator")

        self._phase(workflow, "coding", self._stop_check_for(workflow.workflow_id))
        coding.write_file(
            "fibonacci.py",
            "def fibonacci(n):\n"
            "    if n <= 1:\n"
            "        return n\n"
            "    return fibonacci(n - 1) + fibonacci(n - 2)\n",
        )
        coding_result = coding.run_tests()
        self._phase_done(workflow, "coding")
        workflow.result["coding"] = coding_result

        coding.send_result(
            "verification",
            {"status": "CODE_READY", "file": "fibonacci.py"},
        )

        # -- Phase: verification -------------------------------------------
        self._phase(workflow, "verification", self._stop_check_for(workflow.workflow_id))
        verification_result = verification.run_tests()
        self._phase_done(workflow, "verification")
        workflow.result["verification"] = verification_result

        verification.send_result(
            "orchestrator",
            {
                "status": "VERIFIED",
                "tests_passed": verification_result.get("tests_passed", 0),
            },
        )

        # -- Phase: orchestrator -> deployment ------------------------------
        self._phase(workflow, "orchestrator", self._stop_check_for(workflow.workflow_id))
        orchestrator.delegate(
            "deployment", {"task": f"Simulate deployment: {workflow.task}"}
        )
        self._phase_done(workflow, "orchestrator")

        self._phase(workflow, "deployment", self._stop_check_for(workflow.workflow_id))
        deployment_result = deployment.simulate_deployment("staging")
        self._phase_done(workflow, "deployment")
        workflow.result["deployment"] = deployment_result

        deployment.send_result(
            "orchestrator",
            {
                "status": "DEPLOYMENT_COMPLETE",
                "target": "staging",
                "simulated": True,
            },
        )

        # Final result snapshot for consumers (JSON-friendly).
        workflow.result["messages_received"] = len(orchestrator.get_results())
        return workflow.result

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _phase(
        self,
        workflow: Workflow,
        agent: str,
        stop_check: Callable[[], bool] | None = None,
    ) -> PhaseRun:
        """Begin a phase; raise _WorkflowStopped if a stop was requested."""
        if stop_check is not None and stop_check():
            logger.info("Workflow %s stopping before phase %s", workflow.workflow_id, agent)
            raise _WorkflowStopped()
        workflow.current_agent = agent
        phase = PhaseRun(agent=agent)
        workflow.phases.append(phase)
        self._record_event(workflow, WorkflowEventType.PHASE_STARTED, agent=agent)
        return phase

    def _phase_done(self, workflow: Workflow, agent: str) -> None:
        phase = workflow.phases[-1] if workflow.phases else None
        if phase is not None and phase.agent == agent and phase.completed_at is None:
            phase.status = WorkflowStatus.COMPLETED
            phase.completed_at = datetime.now(timezone.utc)
        self._record_event(workflow, WorkflowEventType.PHASE_COMPLETED, agent=agent)
        workflow.current_agent = None

    def _make_stop_check(self, workflow_id: str) -> Callable[[], bool]:
        def check() -> bool:
            workflow = self._workflows.get(workflow_id)
            return bool(workflow and workflow.status == WorkflowStatus.STOPPING)

        return check

    def _stop_check_for(self, workflow_id: str) -> Callable[[], bool]:
        check = self._stop_checks.get(workflow_id)
        if check is None:
            check = self._make_stop_check(workflow_id)
        return check

    def _get_or_raise(self, workflow_id: str) -> Workflow:
        workflow = self._workflows.get(workflow_id)
        if workflow is None:
            raise WorkflowNotFoundError(workflow_id)
        return workflow

    def _record_event(
        self,
        workflow: Workflow,
        event_type: WorkflowEventType,
        agent: str | None = None,
        detail: dict[str, Any] | None = None,
    ) -> WorkflowEvent:
        event = WorkflowEvent(
            event_id=f"wev-{uuid.uuid4().hex[:12]}",
            workflow_id=workflow.workflow_id,
            event_type=event_type,
            timestamp=datetime.now(timezone.utc),
            agent=agent,
            detail=detail or {},
        )
        workflow.events.append(event)
        return event

    @staticmethod
    def _describe_denial(exc: KavachDeniedError) -> str:
        reason_codes = []
        if exc.result is not None:
            reason_codes = [rc.value for rc in exc.result.reason_codes]
        return f"KavachDeniedError: {exc.reason} reasons={reason_codes}"

    @staticmethod
    def _denial_result(exc: KavachDeniedError) -> dict[str, Any] | None:
        if exc.result is None:
            return None
        result = exc.result
        return {
            "kavach_denied": True,
            "request_id": getattr(result, "request_id", None),
            "decision": result.decision.value,
            "reason_codes": [rc.value for rc in result.reason_codes],
            "risk_score": result.risk_score,
        }


class _WorkflowStopped(Exception):
    """Internal control-flow signal: a cooperative stop was requested."""


__all__ = [
    "WorkflowNotFoundError",
    "WorkflowSupervisor",
]
