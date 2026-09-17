"""
Incident Service — creates and manages security incidents.
"""

import uuid
from datetime import datetime, timezone

from shield.gateway.models import AuthorizationResult, ReasonCode
from shield.identity.models import AgentId
from shield.incidents.models import Incident, IncidentSeverity, IncidentStatus

_SEVERITY_MAP: dict[int, IncidentSeverity] = {
    0: IncidentSeverity.LOW,
    25: IncidentSeverity.MEDIUM,
    50: IncidentSeverity.HIGH,
    75: IncidentSeverity.CRITICAL,
}


def _risk_to_severity(risk_score: int | None) -> IncidentSeverity:
    score = risk_score or 0
    if score >= 75:
        return IncidentSeverity.CRITICAL
    if score >= 50:
        return IncidentSeverity.HIGH
    if score >= 25:
        return IncidentSeverity.MEDIUM
    return IncidentSeverity.LOW


class IncidentService:
    def __init__(self) -> None:
        self._incidents: dict[str, Incident] = {}

    def create(self, agent_id: AgentId, result: AuthorizationResult) -> Incident:
        incident = Incident(
            incident_id=f"inc-{uuid.uuid4().hex[:8]}",
            timestamp=datetime.now(timezone.utc),
            agent_id=agent_id,
            severity=_risk_to_severity(result.risk_score),
            reason_codes=list(result.reason_codes),
            request_ids=[result.request_id],
        )
        self._incidents[incident.incident_id] = incident
        return incident

    def get(self, incident_id: str) -> Incident | None:
        return self._incidents.get(incident_id)

    def list_all(self) -> list[Incident]:
        return list(self._incidents.values())

    def update_status(self, incident_id: str, status: IncidentStatus) -> None:
        if incident_id not in self._incidents:
            raise KeyError(f"Incident '{incident_id}' not found.")
        self._incidents[incident_id].status = status
