from fastapi import APIRouter, Depends, HTTPException

from api.middleware.auth import require_api_key
from shield.incidents.models import IncidentStatus
from shield.runtime.services import get_runtime

router = APIRouter(dependencies=[Depends(require_api_key)])


def _fmt(i):
    return {
        "incident_id": i.incident_id,
        "timestamp": i.timestamp.isoformat(),
        "agent_id": i.agent_id.value,
        "severity": i.severity.value,
        "status": i.status.value,
        "reason_codes": [r.value for r in i.reason_codes],
        "request_ids": i.request_ids,
        "description": i.description,
    }


@router.get("/")
async def list_incidents():
    return [_fmt(i) for i in get_runtime().incident_service.list_all()]


@router.get("/{incident_id}")
async def get_incident(incident_id: str):
    incident = get_runtime().incident_service.get(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found")
    return _fmt(incident)


@router.patch("/{incident_id}/resolve")
async def resolve_incident(incident_id: str):
    try:
        get_runtime().incident_service.update_status(incident_id, IncidentStatus.RESOLVED)
    except KeyError:
        raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found")
    return {"incident_id": incident_id, "status": IncidentStatus.RESOLVED.value}
