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

import ast
import operator
import re
import threading
import uuid
from datetime import datetime, timezone
from enum import Enum
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
from shield.telemetry.context import (
    reset_current_workflow_id,
    set_current_workflow_id,
)
from kavach_logger import get_logger

logger = get_logger("kavach.agents.supervisor")


# ============================================================================
# Task analysis — read the arithmetic expression out of the task description.
#
# Evaluation is restricted to + - * / % ** over numeric literals via an AST
# allowlist.  No names, calls, attributes or subscripts are reachable, so a
# hostile task string cannot execute anything.
# ============================================================================

_BIN_OPS: dict[type, Callable[[Any, Any], Any]] = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.Mod: operator.mod,
    ast.Pow: operator.pow,
}

_UNARY_OPS: dict[type, Callable[[Any], Any]] = {
    ast.UAdd: operator.pos,
    ast.USub: operator.neg,
}

_ARITHMETIC_RE = re.compile(r"-?\d[\d\s]*(?:\s*[+\-*/%]\s*-?\d[\d\s]*)+")


def _evaluate_arithmetic_node(node: ast.AST) -> Any:
    """Evaluate an arithmetic-only AST node. Anything else is rejected."""
    if isinstance(node, ast.Expression):
        return _evaluate_arithmetic_node(node.body)
    if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
        return node.value
    if isinstance(node, ast.BinOp) and type(node.op) in _BIN_OPS:
        return _BIN_OPS[type(node.op)](
            _evaluate_arithmetic_node(node.left),
            _evaluate_arithmetic_node(node.right),
        )
    if isinstance(node, ast.UnaryOp) and type(node.op) in _UNARY_OPS:
        return _UNARY_OPS[type(node.op)](_evaluate_arithmetic_node(node.operand))
    raise ValueError(f"Unsupported arithmetic node: {type(node).__name__}")


def analyse_task(task: str) -> tuple[str | None, int | float | None]:
    """
    Extract the first evaluable arithmetic expression from a task description.

    Returns ``(expression, value)`` or ``(None, None)`` when the task is not
    arithmetic.  This is task interpretation, not security logic.
    """
    for match in _ARITHMETIC_RE.finditer(task):
        expression = match.group(0).strip()
        try:
            value = _evaluate_arithmetic_node(ast.parse(expression, mode="eval"))
        except (ValueError, SyntaxError, ZeroDivisionError, TypeError, OverflowError):
            continue
        if isinstance(value, float) and value.is_integer():
            value = int(value)
        return expression, value
    return None, None


class TaskKind(str, Enum):
    """Which real agent path a task requires.

    This is TASK INTERPRETATION, not security: it decides which real agents and
    protected tools run, and nothing else.  Every operation the chosen path
    performs still has to pass KavachGuard -> authorize().
    """

    CODING = "coding"
    RESEARCH = "research"
    DEPLOYMENT = "deployment"


# Keyword sets used only to pick the agent path.  Deliberately narrow: an
# unrecognised task is treated as a coding task (the general-purpose path).
_DEPLOYMENT_KEYWORDS = (
    "deploy",
    "deployment",
    "release",
    "rollout",
    "roll out",
    "ship",
    "staging",
    "production",
    "preview",
    "infrastructure",
)

_RESEARCH_KEYWORDS = (
    "research",
    "investigate",
    "summarize",
    "summarise",
    "summary",
    "explore",
    "study",
    "survey",
    "analysis",
    "analyse",
    "analyze",
    "gather information",
    "look up",
    "learn about",
    "tell me about",
    "what is",
    "what are",
    "find out",
    "trends",
    "market",
    "information on",
    "details about",
)

_TOPIC_STOPWORDS = frozenset(
    {
        "a",
        "about",
        "an",
        "and",
        "are",
        "details",
        "find",
        "for",
        "in",
        "information",
        "into",
        "is",
        "it",
        "me",
        "of",
        "on",
        "out",
        "please",
        "summarise",
        "summarize",
        "summary",
        "tell",
        "the",
        "this",
        "to",
        "what",
        "with",
    }
    | set(_RESEARCH_KEYWORDS)
    | set(_DEPLOYMENT_KEYWORDS)
)


def classify_task(task: str) -> TaskKind:
    """Route a task to the agent path its wording calls for.

    Deployment intent wins over research intent when both appear ("research how
    to deploy" is still a deployment job); anything unrecognised is a coding
    task.  Purely deterministic string matching.
    """
    text = task.lower()
    deploy_hits = sum(1 for keyword in _DEPLOYMENT_KEYWORDS if keyword in text)
    research_hits = sum(1 for keyword in _RESEARCH_KEYWORDS if keyword in text)
    if deploy_hits and deploy_hits >= research_hits:
        return TaskKind.DEPLOYMENT
    if research_hits:
        return TaskKind.RESEARCH
    return TaskKind.CODING


def research_topic(task: str) -> str:
    """The subject the research agent is asked about."""
    words = [
        word
        for word in re.sub(r"[^\w\s]", " ", task.lower()).split()
        if word not in _TOPIC_STOPWORDS and not word.isdigit()
    ]
    return " ".join(words[:3]) or "the requested topic"


def research_source_document(task: str) -> str:
    """The workspace document the research agent reads as its source.

    Derived from the topic word, so the same task always resolves to the same
    document.  Reading it is a real ``research.read`` authorization; if the
    document is not present the agent reports NOT_FOUND rather than inventing
    content.
    """
    topic = research_topic(task)
    stem = topic.split()[0] if topic.split() else "notes"
    return f"{stem}.txt"


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
        # Background worker threads for asynchronous execution (HTTP control plane).
        self._threads: dict[str, threading.Thread] = {}

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
        logger.info("workflow created", extra={"workflow_id": workflow_id, "task": task})
        return workflow_id

    def start_workflow(self, workflow_id: str) -> Workflow:
        """Validate and synchronously execute the workflow.

        CREATED -> RUNNING -> (COMPLETED | FAILED | STOPPED).
        """
        workflow = self._begin(workflow_id)
        return self._settle(workflow)

    def start_workflow_async(self, workflow_id: str) -> Workflow:
        """Begin execution on a background thread and return IMMEDIATELY.

        CREATED -> RUNNING is performed synchronously so the caller observes a
        truthful RUNNING state; the phases then execute on a worker thread while
        the caller polls ``get_workflow``.  Security is unchanged: the worker
        runs exactly the same ``_execute`` body through the same real agents and
        the same KavachGuard boundary.
        """
        workflow = self._begin(workflow_id)
        thread = threading.Thread(
            target=self._settle,
            args=(workflow,),
            name=f"kavach-workflow-{workflow_id}",
            daemon=True,
        )
        self._threads[workflow_id] = thread
        thread.start()
        return workflow

    def wait_for_completion(self, workflow_id: str, timeout: float = 60.0) -> Workflow:
        """Block until an asynchronously started workflow settles (test helper)."""
        thread = self._threads.get(workflow_id)
        if thread is not None:
            thread.join(timeout)
        return self._get_or_raise(workflow_id)

    def _begin(self, workflow_id: str) -> Workflow:
        """Validate CREATED and move the workflow to RUNNING."""
        workflow = self._get_or_raise(workflow_id)
        if workflow.status != WorkflowStatus.CREATED:
            raise RuntimeError(
                f"Workflow {workflow_id} cannot start from status "
                f"{workflow.status.value} (expected CREATED)"
            )

        workflow.status = WorkflowStatus.RUNNING
        workflow.started_at = datetime.now(timezone.utc)
        self._record_event(workflow, WorkflowEventType.WORKFLOW_STARTED)
        logger.info("workflow started", extra={"workflow_id": workflow_id, "task": workflow.task})
        return workflow

    def _settle(self, workflow: Workflow) -> Workflow:
        """Execute the workflow body and settle on a terminal status."""
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
            logger.warning(
                "workflow blocked by Kavach",
                extra={
                    "workflow_id": workflow.workflow_id,
                    "reason": workflow.error,
                    "kavach_denied": True,
                },
            )
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
            logger.error(
                "workflow failed",
                extra={"workflow_id": workflow.workflow_id, "error": workflow.error},
                exc_info=True,
            )
            self._record_event(
                workflow,
                WorkflowEventType.WORKFLOW_FAILED,
                detail={"error": workflow.error},
            )

        if workflow.status == WorkflowStatus.RUNNING:
            workflow.status = WorkflowStatus.COMPLETED
            workflow.completed_at = datetime.now(timezone.utc)
            self._record_event(workflow, WorkflowEventType.WORKFLOW_COMPLETED)
            logger.info(
                "workflow completed",
                extra={"workflow_id": workflow.workflow_id, "task": workflow.task},
            )

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

    def list_workflows(self) -> list[Workflow]:
        """Return all known workflows (read-only projection for dashboards)."""
        return list(self._workflows.values())

    def reset(self) -> None:
        """
        Forget every workflow. Used ONLY to start a fresh demo session.

        This clears workflow lifecycle state and nothing else: agent identity
        and security state remain owned by Shield and are untouched here.
        """
        self._workflows.clear()
        self._stop_checks.clear()
        self._threads.clear()

    def get_workflow_events(self, workflow_id: str) -> list[WorkflowEvent]:
        """Return supervisor lifecycle events correlated by workflow_id."""
        return list(self._get_or_raise(workflow_id).events)

    # ------------------------------------------------------------------
    # Canonical workflow body (single authoritative execution path)
    # ------------------------------------------------------------------

    def _execute(self, workflow: Workflow) -> dict[str, Any]:
        """Execute the canonical P1 workflow.

        This is the ONE authoritative workflow execution path.  Agents,
        MessageBus, AgentTools and the KavachGuard enforcement boundary are the
        real P1 components; the supervisor adds only phase lifecycle tracking
        and cooperative stop.

        The canonical workflow is deliberately arithmetic and deliberately does
        NOT involve the research agent.  The research agent exists to be probed
        by the security demo (capability escalation, quarantine), not to sit in
        the happy path.

        The workflow_id is bound to the telemetry context for the duration of
        the run so every AUTHORIZATION_DECISION event emitted by KavachGuard
        carries the same correlation id.  This is telemetry correlation only —
        the pipeline never reads it.
        """
        workflow.result = {}
        token = set_current_workflow_id(workflow.workflow_id)
        try:
            return self._run_phases(workflow)
        finally:
            reset_current_workflow_id(token)

    def _run_phases(self, workflow: Workflow) -> dict[str, Any]:
        """Route the task to the agents and protected tools it actually needs.

        Different task classes must produce different real work — the activity
        stream is a record of what actually ran, so it cannot be the same
        sequence for every task.
        """
        kind = classify_task(workflow.task)
        workflow.result["task_kind"] = kind.value
        logger.info(
            "workflow task classified",
            extra={"workflow_id": workflow.workflow_id, "task_kind": kind.value},
        )
        if kind is TaskKind.RESEARCH:
            return self._run_research(workflow)
        if kind is TaskKind.DEPLOYMENT:
            return self._run_deployment(workflow)
        return self._run_coding(workflow)

    def _run_coding(self, workflow: Workflow) -> dict[str, Any]:
        """Coding/arithmetic path: orchestrator -> coding -> verification -> deployment.

        Does NOT involve the research agent.
        """
        bus = MessageBus()
        stop_check = self._stop_check_for(workflow.workflow_id)

        orchestrator = OrchestratorAgent(bus)
        coding = CodingAgent(bus)
        verification = VerificationAgent(bus)
        deployment = DeploymentAgent(bus)

        expression, value = analyse_task(workflow.task)

        # -- Phase: orchestrator delegates the coding work ------------------
        self._phase(workflow, "orchestrator", stop_check)
        orchestrator.delegate(
            "coding",
            {
                "task": workflow.task,
                "expression": expression,
            },
        )
        self._phase_done(workflow, "orchestrator")

        # -- Phase: coding reads, writes and tests the solution -------------
        self._phase(workflow, "coding", stop_check)
        # 1. coding.read — inspect the current artifact (empty if not written yet)
        previous_artifact = coding.read_file("calc.py")
        # 2. coding.write — write the solution
        source = self._calc_source(expression, value)
        coding.write_file("calc.py", source)
        # 3. coding.test
        coding_result = coding.run_tests()
        self._phase_done(workflow, "coding")

        workflow.result["artifact"] = "calc.py"
        workflow.result["previous_artifact_bytes"] = len(previous_artifact)
        workflow.result["artifact_bytes"] = len(source)
        workflow.result["expression"] = expression
        workflow.result["value"] = value
        workflow.result["coding"] = coding_result

        coding.send_result(
            "verification",
            {"status": "CODE_READY", "file": "calc.py", "value": value},
        )

        # -- Phase: verification -------------------------------------------
        self._phase(workflow, "verification", stop_check)
        verification_result = verification.run_tests()
        self._phase_done(workflow, "verification")
        workflow.result["verification"] = verification_result

        verification.send_result(
            "orchestrator",
            {
                "status": "VERIFIED",
                "tests_passed": verification_result.get("tests_passed", 0),
                "value": value,
            },
        )

        # -- Phase: deployment preview against staging ----------------------
        self._phase(workflow, "deployment", stop_check)
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

    @staticmethod
    def _calc_source(expression: str | None, value: int | float | None) -> str:
        """Render the artifact the coding agent writes for this task."""
        if expression is None:
            return (
                '\"\"\"Solution artifact produced by the coding agent.\"\"\"\n'
                "\n"
                "RESULT = None\n"
            )
        return (
            '\"\"\"Arithmetic solution produced by the coding agent.\"\"\"\n'
            "\n"
            f'EXPRESSION = "{expression}"\n'
            f"RESULT = {value}\n"
        )

    def _run_research(self, workflow: Workflow) -> dict[str, Any]:
        """Research path: orchestrator -> research (search + read).

        The research agent is read-only by design, so this path performs no
        coding, no testing and no deployment: only the operations the task
        actually needs.
        """
        bus = MessageBus()
        stop_check = self._stop_check_for(workflow.workflow_id)

        orchestrator = OrchestratorAgent(bus)
        research = ResearchAgent(bus)

        topic = research_topic(workflow.task)
        document = research_source_document(workflow.task)

        # -- Phase: orchestrator delegates the research question ------------
        self._phase(workflow, "orchestrator", stop_check)
        orchestrator.delegate(
            "research",
            {
                "task": workflow.task,
                "topic": topic,
                "source_document": document,
            },
        )
        self._phase_done(workflow, "orchestrator")

        # -- Phase: research searches and reads its source ------------------
        self._phase(workflow, "research", stop_check)
        # 1. research.search — find material on the topic
        search_result = research.search(topic)
        # 2. research.read — read the source document for the topic
        document_result = research.read_document(document)
        self._phase_done(workflow, "research")

        workflow.result.update(
            {
                "topic": topic,
                "source_document": document,
                "document_status": document_result.get("status"),
                "results_found": len(search_result.get("results", []))
                if isinstance(search_result, dict)
                else 0,
                "summary": (
                    f"Researched '{topic}' ({document_result.get('status', 'UNKNOWN')} "
                    f"source: {document})"
                ),
            }
        )

        research.send_result(
            "orchestrator",
            {
                "status": "RESEARCH_READY",
                "topic": topic,
                "document": document,
                "document_status": document_result.get("status"),
            },
        )

        workflow.result["messages_received"] = len(orchestrator.get_results())
        return workflow.result

    def _run_deployment(self, workflow: Workflow) -> dict[str, Any]:
        """Deployment path: orchestrator -> coding (inspect) -> verification -> deployment.

        The only protected deployment action available to the deployment agent is
        a staging PREVIEW (deployment.preview against staging-environment).  The
        workflow never attempts a production deployment; a production request is
        only ever expressed as intent when the task asks for it.
        """
        bus = MessageBus()
        stop_check = self._stop_check_for(workflow.workflow_id)

        orchestrator = OrchestratorAgent(bus)
        coding = CodingAgent(bus)
        verification = VerificationAgent(bus)
        deployment = DeploymentAgent(bus)

        # Intent only — the authorized action below is always a staging preview.
        requested_target = (
            "production" if "production" in workflow.task.lower() else "staging"
        )

        # -- Phase: orchestrator delegates the deployment preparation -------
        self._phase(workflow, "orchestrator", stop_check)
        orchestrator.delegate(
            "deployment",
            {
                "task": workflow.task,
                "requested_target": requested_target,
            },
        )
        self._phase_done(workflow, "orchestrator")

        # -- Phase: coding inspects the artifact that would be deployed -----
        self._phase(workflow, "coding", stop_check)
        # 1. coding.read — inspect the current artifact (empty if absent)
        artifact = coding.read_file("app.py")
        self._phase_done(workflow, "coding")

        workflow.result["inspected_artifact"] = "app.py"
        workflow.result["inspected_bytes"] = len(artifact)

        # -- Phase: verification gate before any deployment -----------------
        self._phase(workflow, "verification", stop_check)
        verification_result = verification.run_tests()
        self._phase_done(workflow, "verification")
        workflow.result["verification"] = verification_result

        # verification -> orchestrator is an allowed MessageBus route, and the
        # orchestrator is the delegation origin for this workflow.
        verification.send_result(
            "orchestrator",
            {
                "status": "VERIFIED",
                "tests_passed": verification_result.get("tests_passed", 0),
            },
        )

        # -- Phase: deployment preview against staging ----------------------
        self._phase(workflow, "deployment", stop_check)
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

        workflow.result.update(
            {
                "requested_target": requested_target,
                "deployed_target": "staging",
                "summary": (
                    f"Staging deployment preview ready for '{requested_target}' "
                    f"(authorized as a staging preview)."
                ),
            }
        )
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
            logger.info("workflow stopping before phase", extra={"workflow_id": workflow.workflow_id, "agent": agent})
            raise _WorkflowStopped()
        workflow.current_agent = agent
        phase = PhaseRun(agent=agent)
        workflow.phases.append(phase)
        logger.info("phase started", extra={"workflow_id": workflow.workflow_id, "agent": agent})
        self._record_event(workflow, WorkflowEventType.PHASE_STARTED, agent=agent)
        return phase

    def _phase_done(self, workflow: Workflow, agent: str) -> None:
        phase = workflow.phases[-1] if workflow.phases else None
        if phase is not None and phase.agent == agent and phase.completed_at is None:
            phase.status = WorkflowStatus.COMPLETED
            phase.completed_at = datetime.now(timezone.utc)
        logger.info("phase completed", extra={"workflow_id": workflow.workflow_id, "agent": agent})
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
    "TaskKind",
    "WorkflowNotFoundError",
    "WorkflowSupervisor",
    "classify_task",
    "research_source_document",
    "research_topic",
]
