"""Read-only dashboard projection.

Every number here is derived from real backend state — nothing is invented:
  * agents     -> shared runtime IdentityService (the five Shield identities)
  * workflows  -> the process-wide WorkflowSupervisor registry
  * incidents  -> shared runtime IncidentService
  * events     -> the Shield authorization audit sink (ALLOW/DENY counts)

No security metrics are fabricated; if a source has no data the count is 0.
"""

from fastapi import APIRouter

from agents.supervisor.models import WorkflowStatus
from api.deps import get_identity_service, get_incident_service, get_supervisor
from api.routes.events import _read_authorization_events
from shield.identity.models import SecurityState

router = APIRouter()


@router.get("")
async def dashboard() -> dict:
    identities = get_identity_service().list_agents()
    agent_counts = {state.value: 0 for state in SecurityState}
    for identity in identities:
        agent_counts[identity.state.value] += 1

    workflow_counts = {status.value: 0 for status in WorkflowStatus}
    for workflow in get_supervisor().list_workflows():
        workflow_counts[workflow.status.value] += 1

    incidents = get_incident_service().list_all()
    open_incidents = sum(1 for incident in incidents if incident.status.value == "OPEN")

    events = _read_authorization_events()
    allow_count = sum(1 for event in events if event.get("policy_decision") == "ALLOW")
    deny_count = sum(1 for event in events if event.get("policy_decision") == "DENY")

    return {
        "agents": {
            "total": len(identities),
            "active": agent_counts[SecurityState.ACTIVE.value],
            "quarantined": agent_counts[SecurityState.QUARANTINED.value],
            "suspicious": agent_counts[SecurityState.SUSPICIOUS.value],
            "terminated": agent_counts[SecurityState.TERMINATED.value],
        },
        "workflows": {
            "total": sum(workflow_counts.values()),
            "created": workflow_counts[WorkflowStatus.CREATED.value],
            "running": workflow_counts[WorkflowStatus.RUNNING.value]
            + workflow_counts[WorkflowStatus.STOPPING.value],
            "completed": workflow_counts[WorkflowStatus.COMPLETED.value],
            "failed": workflow_counts[WorkflowStatus.FAILED.value],
            "stopped": workflow_counts[WorkflowStatus.STOPPED.value],
        },
        "incidents": {
            "total": len(incidents),
            "open": open_incidents,
        },
        "events": {
            "total": len(events),
            "allow": allow_count,
            "deny": deny_count,
        },
    }
