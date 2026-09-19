"""
WorkflowSupervisor — manages P1 workflow lifecycle and event tracking.

Wraps the existing P1 agent workflow with:
  - Lifecycle states: CREATED → RUNNING → COMPLETED | FAILED | STOPPED
  - Per-workflow event log
  - Uses the shared ShieldRuntime (wired via configure_all_guards at startup)

The supervisor is synchronous. start() blocks until the workflow completes.
"""

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from agents.coding.agent import CodingAgent
from agents.deployment.agent import DeploymentAgent
from agents.orchestrator.agent import OrchestratorAgent
from agents.research.agent import ResearchAgent
from agents.verification.agent import VerificationAgent
from sandbox.runtime.message_bus import MessageBus
from shield.runtime.services import ShieldRuntime, get_runtime


class WorkflowStatus(str, Enum):
    CREATED = "CREATED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    STOPPED = "STOPPED"


@dataclass
class WorkflowEvent:
    event_id: str
    workflow_id: str
    timestamp: str
    step: str
    status: str
    detail: str = ""


@dataclass
class WorkflowSnapshot:
    workflow_id: str
    task: str
    status: WorkflowStatus
    created_at: str
    started_at: str | None
    completed_at: str | None
    error: str | None
    steps_completed: list[str]
    events: list[WorkflowEvent]


class WorkflowSupervisor:
    """
    Manages a single P1 workflow execution with lifecycle and event tracking.

    Module-level KavachGuard instances in agent tools must already be wired
    to the shared ShieldRuntime via configure_all_guards() before start() is
    called. This is done once at application startup in shield/api/app.py.
    """

    def __init__(self, workflow_id: str, task: str, runtime: ShieldRuntime) -> None:
        self.workflow_id = workflow_id
        self.task = task
        self._runtime = runtime
        self.status = WorkflowStatus.CREATED
        self.created_at = datetime.now(timezone.utc).isoformat()
        self.started_at: str | None = None
        self.completed_at: str | None = None
        self.error: str | None = None
        self.steps_completed: list[str] = []
        self._events: list[WorkflowEvent] = []
        self._stopped = False

    @classmethod
    def create(cls, task: str, runtime: ShieldRuntime | None = None) -> "WorkflowSupervisor":
        """Factory — create a new workflow in CREATED state."""
        wf_id = f"wf-{uuid.uuid4().hex[:12]}"
        rt = runtime or get_runtime()
        return cls(workflow_id=wf_id, task=task, runtime=rt)

    def _emit(self, step: str, status: str, detail: str = "") -> None:
        self._events.append(WorkflowEvent(
            event_id=f"evt-{uuid.uuid4().hex[:8]}",
            workflow_id=self.workflow_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            step=step,
            status=status,
            detail=detail,
        ))

    def start(self) -> "WorkflowSupervisor":
        """
        Execute the P1 workflow synchronously.
        Transitions: CREATED → RUNNING → COMPLETED | FAILED
        """
        if self.status != WorkflowStatus.CREATED:
            raise ValueError(f"Cannot start workflow in state {self.status.value}")

        self.status = WorkflowStatus.RUNNING
        self.started_at = datetime.now(timezone.utc).isoformat()
        self._emit("workflow", "STARTED", f"task={self.task!r}")

        try:
            self._run()
            if not self._stopped:
                self.status = WorkflowStatus.COMPLETED
                self.completed_at = datetime.now(timezone.utc).isoformat()
                self._emit("workflow", "COMPLETED")
        except Exception as exc:
            self.status = WorkflowStatus.FAILED
            self.completed_at = datetime.now(timezone.utc).isoformat()
            self.error = str(exc)
            self._emit("workflow", "FAILED", detail=str(exc))

        return self

    def stop(self) -> "WorkflowSupervisor":
        """
        Request a stop. CREATED → STOPPED immediately.
        RUNNING → sets flag; transitions to STOPPED at next step boundary.
        """
        if self.status in (WorkflowStatus.COMPLETED, WorkflowStatus.FAILED, WorkflowStatus.STOPPED):
            return self
        self._stopped = True
        if self.status == WorkflowStatus.CREATED:
            self.status = WorkflowStatus.STOPPED
            self.completed_at = datetime.now(timezone.utc).isoformat()
            self._emit("workflow", "STOPPED", "stopped before start")
        return self

    def snapshot(self) -> WorkflowSnapshot:
        return WorkflowSnapshot(
            workflow_id=self.workflow_id,
            task=self.task,
            status=self.status,
            created_at=self.created_at,
            started_at=self.started_at,
            completed_at=self.completed_at,
            error=self.error,
            steps_completed=list(self.steps_completed),
            events=list(self._events),
        )

    def get_events(self) -> list[WorkflowEvent]:
        return list(self._events)

    # ------------------------------------------------------------------
    # Internal workflow execution — uses normal agent constructors.
    # Module-level guards are already wired to shared runtime.
    # ------------------------------------------------------------------

    def _run(self) -> None:
        bus = MessageBus()
        orchestrator = OrchestratorAgent(bus)
        research = ResearchAgent(bus)
        coding = CodingAgent(bus)
        deployment = DeploymentAgent(bus)
        verification = VerificationAgent(bus)

        # Step 1: Orchestrator → Research
        if self._stopped:
            return
        self._emit("orchestrator.delegate", "RUNNING", "delegating to research")
        orchestrator.delegate("research", {"task": self.task})
        self.steps_completed.append("orchestrator.delegate.research")
        self._emit("orchestrator.delegate", "COMPLETED")

        # Step 2: Research
        if self._stopped:
            return
        self._emit("research.search", "RUNNING")
        result = research.search(self.task)
        self.steps_completed.append("research.search")
        self._emit("research.search", "COMPLETED", str(result))

        if self._stopped:
            return
        self._emit("research.write", "RUNNING")
        research.write_research("output.txt", f"Research for: {self.task}")
        self.steps_completed.append("research.write")
        self._emit("research.write", "COMPLETED")

        research.send_result("orchestrator", {"status": "RESEARCH_COMPLETE", "task": self.task})

        # Step 3: Orchestrator → Coding
        if self._stopped:
            return
        self._emit("orchestrator.delegate", "RUNNING", "delegating to coding")
        orchestrator.delegate("coding", {"task": f"Implement: {self.task}"})
        self.steps_completed.append("orchestrator.delegate.coding")
        self._emit("orchestrator.delegate", "COMPLETED")

        if self._stopped:
            return
        self._emit("coding.write", "RUNNING")
        coding.write_file("output.py", f"# Implementation for: {self.task}\n")
        self.steps_completed.append("coding.write")
        self._emit("coding.write", "COMPLETED")

        if self._stopped:
            return
        self._emit("coding.test", "RUNNING")
        test_result = coding.run_tests()
        self.steps_completed.append("coding.test")
        self._emit("coding.test", "COMPLETED", str(test_result))

        coding.send_result("verification", {"status": "CODE_READY"})

        # Step 4: Verification
        if self._stopped:
            return
        self._emit("verification.test", "RUNNING")
        v_result = verification.run_tests()
        self.steps_completed.append("verification.test")
        self._emit("verification.test", "COMPLETED", str(v_result))

        verification.send_result("orchestrator", {"status": "VERIFIED"})

        # Step 5: Deployment
        if self._stopped:
            return
        self._emit("orchestrator.delegate", "RUNNING", "delegating to deployment")
        orchestrator.delegate("deployment", {"task": "Deploy to staging"})
        self.steps_completed.append("orchestrator.delegate.deployment")
        self._emit("orchestrator.delegate", "COMPLETED")

        if self._stopped:
            return
        self._emit("deployment.simulate", "RUNNING")
        d_result = deployment.simulate_deployment("staging")
        self.steps_completed.append("deployment.simulate")
        self._emit("deployment.simulate", "COMPLETED", str(d_result))

        deployment.send_result("orchestrator", {"status": "DEPLOYMENT_COMPLETE"})
