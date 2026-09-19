"""
Incident Service — creates and manages security incidents.

Incident creation is triggered when the FINAL authorization decision has:
    risk_score >= INCIDENT_THRESHOLD

Incident creation is a consequence of the decision, not an authorization mechanism.
It must NEVER change ALLOW -> DENY or DENY -> ALLOW.
"""

import logging
import uuid
from datetime import datetime, timezone

from shield.gateway.models import AuthorizationResult, ReasonCode
from shield.identity.models import AgentId
from shield.incidents.models import Incident, IncidentSeverity, IncidentStatus

logger = logging.getLogger(__name__)

# Phase 16 configurable threshold
INCIDENT_THRESHOLD: int = 80


def _risk_to_severity(risk_score: int | None) -> IncidentSeverity:
    """
    Deterministically map risk score to incident severity.
    For Phase 16: risk >= INCIDENT_THRESHOLD -> HIGH
    """
    score = risk_score or 0
    if score >= INCIDENT_THRESHOLD:
        return IncidentSeverity.HIGH
    if score >= 50:
        return IncidentSeverity.MEDIUM
    if score >= 25:
        return IncidentSeverity.LOW
    return IncidentSeverity.LOW


class IncidentService:
    """
    Creates and manages security incidents.
    Incident creation is fail-safe: failures MUST NOT alter authorization decisions.
    """

    def __init__(self, threshold: int = INCIDENT_THRESHOLD) -> None:
        self._incidents: dict[str, Incident] = {}
        self._threshold = threshold

    @property
    def threshold(self) -> int:
        """Return the current incident threshold."""
        return self._threshold

    def should_create_incident(self, result: AuthorizationResult) -> bool:
        """
        Determine whether an incident should be created based on the risk score.

        Returns True if risk_score >= threshold, False otherwise.
        This does NOT modify the authorization result.
        """
        if result.risk_score is None:
            return False
        return result.risk_score >= self._threshold

    def create(self, agent_id: AgentId, result: AuthorizationResult) -> Incident:
        """
        Create an incident from the FINAL authorization decision.

        Parameters:
            agent_id: Source agent from the request/decision.
            result: Final AuthorizationResult from the pipeline.

        Returns:
            Incident with status OPEN and severity derived from risk score.
        """
        incident = Incident(
            incident_id=f"inc-{uuid.uuid4().hex[:8]}",
            timestamp=datetime.now(timezone.utc),
            agent_id=agent_id,
            severity=_risk_to_severity(result.risk_score),
            status=IncidentStatus.OPEN,
            reason_codes=list(result.reason_codes),
            request_ids=[result.request_id],
        )
        self._incidents[incident.incident_id] = incident
        logger.info(
            "Incident %s created for agent %s (risk=%d, severity=%s)",
            incident.incident_id,
            agent_id.value,
            result.risk_score or 0,
            incident.severity.value,
        )
        return incident

    def clear(self) -> None:
        """
        Drop all incidents. Used ONLY to start a fresh demo session.

        This does not weaken detection: a new incident is created whenever a
        later decision again crosses the threshold. Incidents are held in
        memory, to be replaced by durable storage in a later phase.
        """
        self._incidents.clear()

    def get(self, incident_id: str) -> Incident | None:
        """Retrieve an incident by ID."""
        return self._incidents.get(incident_id)

    def list_all(self) -> list[Incident]:
        """Return all incidents."""
        return list(self._incidents.values())

    def update_status(self, incident_id: str, status: IncidentStatus) -> None:
        """Update the status of an existing incident."""
        if incident_id not in self._incidents:
            raise KeyError(f"Incident '{incident_id}' not found.")
        self._incidents[incident_id].status = status
