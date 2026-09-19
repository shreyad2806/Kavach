"""Incident routes.

Projects the existing ``IncidentService`` (from the shared runtime) over HTTP.
Incidents are created by the Kavach pipeline when a decision's risk_score
crosses the threshold; this layer only reads them.  No database is added —
incidents remain process-local at this stage, which is acceptable.

Frontend contract (CriticalIncidentPanel.jsx, IncidentHistoryModal.jsx):
    incident_id, agent_id, severity, status, reason_codes, description, timestamp
"""

from fastapi import APIRouter, HTTPException

from api.deps import get_incident_service

router = APIRouter()


def _serialize(incident) -> dict:
    return {
        "incident_id": incident.incident_id,
        "timestamp": incident.timestamp.isoformat(),
        "agent_id": incident.agent_id.value,
        "severity": incident.severity.value,
        "status": incident.status.value,
        "reason_codes": [code.value for code in incident.reason_codes],
        "request_ids": list(incident.request_ids),
        "description": incident.description,
    }


@router.get("")
async def list_incidents() -> list[dict]:
    return [_serialize(incident) for incident in get_incident_service().list_all()]


@router.get("/{incident_id}")
async def get_incident(incident_id: str) -> dict:
    incident = get_incident_service().get(incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found")
    return _serialize(incident)
