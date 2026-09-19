"""Workflow control plane + demo session control.

Thin HTTP wrapper over the EXISTING ``WorkflowSupervisor`` — no mock workflows.
``POST /workflows/{id}/start`` executes the real canonical P1 workflow, so every
protected side effect flows through the real path:

    AgentTools -> KavachGuard -> get_shield_runtime() -> authorize()

A Kavach DENY (e.g. a quarantined agent) surfaces as a FAILED workflow carrying
``result.kavach_denied`` and the real ``reason_codes`` — the unauthorized action
is never executed and never reported as success.

Endpoints are synchronous ``def`` so FastAPI runs them in a worker threadpool and
the blocking workflow execution never stalls the event loop.
"""

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from agents.supervisor import WorkflowNotFoundError
from api.deps import get_supervisor
from api.middleware.auth import require_api_key
from sandbox.runtime.kavach_guard import (
    KavachDeniedError,
    KavachGuard,
    KavachGuardError,
)
from shield.capabilities.models import CapabilityName
from shield.gateway.models import (
    ActionName,
    AuthorizationResult,
    ResourceName,
)
from shield.identity.models import AgentId, SecurityState
from shield.runtime.services import get_runtime
from shield.telemetry.session import clear_events, list_events

router = APIRouter(dependencies=[Depends(require_api_key)])


class WorkflowCreateRequest(BaseModel):
    task: str


def _event_to_dict(event) -> dict:
    return {
        "event_id": event.event_id,
        "workflow_id": event.workflow_id,
        "event_type": event.event_type.value,
        "timestamp": event.timestamp.isoformat(),
        "agent": event.agent,
        "detail": event.detail,
    }


def _session_event(request_id: str) -> dict | None:
    """The already-emitted authorization event for a request, if any."""
    for event in list_events(limit=500):
        if event.get("request_id") == request_id:
            return event
    return None


def _attempt_view(result: AuthorizationResult, executed: bool) -> dict:
    """Project a real AuthorizationResult. Nothing here is synthesised."""
    return {
        "request_id": result.request_id,
        "decision": result.decision.value,
        "reason_codes": [code.value for code in result.reason_codes],
        "risk_score": result.risk_score,
        "agent_state": result.agent_state.value,
        "checks": dict(result.checks.model_dump(mode="json")),
        "executed": executed,
        "event": _session_event(result.request_id),
    }


def _agent_states() -> list[dict]:
    return [
        {"agent_id": agent.agent_id.value, "state": agent.state.value}
        for agent in get_runtime().identity_service.list_agents()
    ]


def _workflow_snapshot(workflow) -> dict:
    """Single source of truth for the live dashboard.

    Contains everything the UI needs for one poll: lifecycle status, the
    authorization events produced by THIS workflow (never historical audit
    entries, never another workflow's decisions), the current agent states and
    the workflow result/error.  All of it is a projection of real backend state.
    """
    snapshot = dict(workflow.summary())
    snapshot["events"] = list_events(limit=500, workflow_id=workflow.workflow_id)
    snapshot["agents"] = _agent_states()
    return snapshot


# ============================================================================
# Demo session control — declared before the parameterised workflow routes
# ============================================================================

@router.post("/demo/reset")
def reset_demo_session() -> dict:
    """Start a clean demo session.

    Releases every agent, forgets the current session's authorization events,
    clears in-memory incidents and workflow lifecycle state, and leaves the
    permanent audit log untouched.

    This is a presentation control, not a security control: it can only ever
    move agents back to ACTIVE through the same enforcement service the
    operator UI uses, and it cannot create, permit, or replay anything.
    """
    runtime = get_runtime()

    for agent in runtime.identity_service.list_agents():
        runtime.identity_service.set_state(agent.agent_id, SecurityState.ACTIVE)

    runtime.incident_service.clear()
    clear_events()
    get_supervisor().reset()

    return {
        "status": "reset",
        "agents": _agent_states(),
        "workflows": 0,
        "incidents": 0,
        "events": 0,
    }


@router.post("/simulation/attack")
def simulate_attack() -> dict:
    """Run the compromised-research-agent attack against the REAL enforcement path.

    Steps, all real:

      1. research-01 requests a production deployment while presenting its own
         (research) capability — an unauthorized capability escalation.
         Evaluated by KavachGuard -> authorize(), the same boundary every
         protected P1 tool call passes through.
      2. The security layer quarantines research-01 via the existing
         QuarantineService.
      3. One more genuine protected research operation is attempted through the
         real ResearchTools object; quarantine must deny it before execution.

    No risk score, reason code, or decision is invented here.
    """
    runtime = get_runtime()
    guard = KavachGuard()

    # -- 1. Unauthorized capability escalation -------------------------------
    try:
        attack_result = guard.authorize(
            p1_source_agent="research",
            action=ActionName.DEPLOYMENT_DEPLOY,
            resource=ResourceName.PRODUCTION_ENVIRONMENT,
            capability=CapabilityName.RESEARCH_SEARCH,
            target_agent="deployment",
        )
    except KavachGuardError as exc:
        # Fail closed: the boundary itself is unavailable, so nothing ran.
        raise HTTPException(
            status_code=503,
            detail=f"Kavach enforcement boundary unavailable: {exc}",
        )

    # -- 2. Enforcement: quarantine the compromised agent --------------------
    try:
        runtime.quarantine_service.quarantine(AgentId.RESEARCH_01)
    except KeyError:
        raise HTTPException(status_code=404, detail="Agent 'research-01' not found")

    # -- 3. Post-quarantine proof: a real protected operation is denied -----
    post_quarantine = _post_quarantine_probe()

    return {
        "attack": _attempt_view(attack_result, executed=False),
        "quarantine": {
            "agent_id": AgentId.RESEARCH_01.value,
            "state": SecurityState.QUARANTINED.value,
        },
        "post_quarantine": post_quarantine,
        "agents": _agent_states(),
    }


def _post_quarantine_probe() -> dict:
    """Attempt one genuine protected research operation after quarantine."""
    from agents.research.tools import _guard as research_guard
    from agents.research.tools import ResearchTools
    from sandbox.runtime.message_bus import MessageBus

    tools = ResearchTools(MessageBus())
    executed = False
    try:
        tools.web_search("post-quarantine probe")
        executed = True
    except KavachDeniedError:
        executed = False
    except KavachGuardError as exc:
        raise HTTPException(
            status_code=503,
            detail=f"Kavach enforcement boundary unavailable: {exc}",
        )

    calls = research_guard.authorization_calls
    if not calls:
        raise HTTPException(
            status_code=500,
            detail="Post-quarantine probe produced no authorization decision",
        )
    return _attempt_view(calls[-1], executed=executed)


# ============================================================================
# Workflow lifecycle
# ============================================================================

@router.post("", status_code=201)
def create_workflow(body: WorkflowCreateRequest) -> dict:
    try:
        workflow_id = get_supervisor().create_workflow(body.task)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {"workflow_id": workflow_id, "status": "CREATED"}


@router.get("/{workflow_id}")
def get_workflow(workflow_id: str) -> dict:
    try:
        return _workflow_snapshot(get_supervisor().get_workflow(workflow_id))
    except WorkflowNotFoundError:
        raise HTTPException(status_code=404, detail=f"Workflow '{workflow_id}' not found")


@router.post("/{workflow_id}/start")
def start_workflow(workflow_id: str) -> dict:
    """Begin the workflow and return IMMEDIATELY with status RUNNING.

    The phases execute on a background worker thread; the caller polls
    ``GET /workflows/{id}`` for live progress.  Nothing about enforcement
    changes — the worker runs the same agents through the same KavachGuard.
    """
    supervisor = get_supervisor()
    try:
        workflow = supervisor.start_workflow_async(workflow_id)
    except WorkflowNotFoundError:
        raise HTTPException(status_code=404, detail=f"Workflow '{workflow_id}' not found")
    except RuntimeError as exc:
        # Cannot start from a non-CREATED status.
        raise HTTPException(status_code=409, detail=str(exc))
    return _workflow_snapshot(workflow)


@router.post("/{workflow_id}/stop")
def stop_workflow(workflow_id: str) -> dict:
    try:
        return _workflow_snapshot(get_supervisor().stop_workflow(workflow_id))
    except WorkflowNotFoundError:
        raise HTTPException(status_code=404, detail=f"Workflow '{workflow_id}' not found")


@router.get("/{workflow_id}/events")
def get_workflow_events(workflow_id: str) -> list[dict]:
    try:
        events = get_supervisor().get_workflow_events(workflow_id)
    except WorkflowNotFoundError:
        raise HTTPException(status_code=404, detail=f"Workflow '{workflow_id}' not found")
    return [_event_to_dict(event) for event in events]
