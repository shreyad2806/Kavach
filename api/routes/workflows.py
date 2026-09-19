"""Workflow control-plane routes.

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

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from agents.supervisor import WorkflowNotFoundError
from api.deps import get_supervisor

router = APIRouter()


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
        return get_supervisor().get_workflow(workflow_id).summary()
    except WorkflowNotFoundError:
        raise HTTPException(status_code=404, detail=f"Workflow '{workflow_id}' not found")


@router.post("/{workflow_id}/start")
def start_workflow(workflow_id: str) -> dict:
    supervisor = get_supervisor()
    try:
        return supervisor.start_workflow(workflow_id).summary()
    except WorkflowNotFoundError:
        raise HTTPException(status_code=404, detail=f"Workflow '{workflow_id}' not found")
    except RuntimeError as exc:
        # Cannot start from a non-CREATED status.
        raise HTTPException(status_code=409, detail=str(exc))


@router.post("/{workflow_id}/stop")
def stop_workflow(workflow_id: str) -> dict:
    try:
        return get_supervisor().stop_workflow(workflow_id).summary()
    except WorkflowNotFoundError:
        raise HTTPException(status_code=404, detail=f"Workflow '{workflow_id}' not found")


@router.get("/{workflow_id}/events")
def get_workflow_events(workflow_id: str) -> list[dict]:
    try:
        events = get_supervisor().get_workflow_events(workflow_id)
    except WorkflowNotFoundError:
        raise HTTPException(status_code=404, detail=f"Workflow '{workflow_id}' not found")
    return [_event_to_dict(event) for event in events]
