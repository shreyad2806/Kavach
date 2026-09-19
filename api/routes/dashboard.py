"""Dashboard — a read-only projection of authoritative state.

Every number here is derived from a real owner:

  agents    → ShieldRuntime.identity_service
  workflows → WorkflowSupervisor
  incidents → ShieldRuntime.incident_service
  events    → the current session's authorization events

No metric is incremented, estimated, or back-filled from the audit log.
"""

from fastapi import APIRouter, Depends

from api.deps import get_supervisor
from api.middleware.auth import require_api_key
from shield.runtime.services import get_runtime
from shield.telemetry.session import counts as session_counts

router = APIRouter(dependencies=[Depends(require_api_key)])


@router.get("/")
async def dashboard():
    runtime = get_runtime()

    agents = runtime.identity_service.list_agents()
    agents_by_state: dict[str, int] = {}
    for agent in agents:
        agents_by_state[agent.state.value] = agents_by_state.get(agent.state.value, 0) + 1

    workflows = get_supervisor().list_workflows()
    workflows_by_status: dict[str, int] = {}
    for workflow in workflows:
        workflows_by_status[workflow.status.value] = (
            workflows_by_status.get(workflow.status.value, 0) + 1
        )

    incidents = runtime.incident_service.list_all()
    incidents_by_status: dict[str, int] = {}
    for incident in incidents:
        incidents_by_status[incident.status.value] = (
            incidents_by_status.get(incident.status.value, 0) + 1
        )

    events = session_counts()

    return {
        "agents": {
            "total": len(agents),
            "active": agents_by_state.get("ACTIVE", 0),
            "quarantined": agents_by_state.get("QUARANTINED", 0),
            "by_state": agents_by_state,
        },
        "workflows": {
            "total": len(workflows),
            "created": workflows_by_status.get("CREATED", 0),
            "running": workflows_by_status.get("RUNNING", 0),
            "completed": workflows_by_status.get("COMPLETED", 0),
            "failed": workflows_by_status.get("FAILED", 0),
            "stopped": workflows_by_status.get("STOPPED", 0),
            "by_status": workflows_by_status,
        },
        "incidents": {
            "total": len(incidents),
            "open": incidents_by_status.get("OPEN", 0),
            "by_status": incidents_by_status,
        },
        "events": {
            "total": events["total"],
            "allow": events["ALLOW"],
            "deny": events["DENY"],
        },
    }
