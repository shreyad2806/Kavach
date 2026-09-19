"""
DynamoDB-backed IncidentService.

Falls back to in-memory if SHIELD_INCIDENTS_TABLE is not set.
"""

import os
from datetime import datetime, timezone

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from shield.gateway.models import AuthorizationResult, ReasonCode
from shield.identity.models import AgentId
from shield.incidents.models import Incident, IncidentSeverity, IncidentStatus
from shield.incidents.service import INCIDENT_THRESHOLD, IncidentService


def _table():
    name = os.environ.get("SHIELD_INCIDENTS_TABLE")
    if not name:
        return None
    return boto3.resource("dynamodb").Table(name)


class DynamoIncidentService(IncidentService):
    """IncidentService backed by DynamoDB."""

    def __init__(self, threshold: int = INCIDENT_THRESHOLD) -> None:
        super().__init__(threshold)
        self._ddb_table = _table()

    def create(self, agent_id: AgentId, result: AuthorizationResult) -> Incident:
        incident = super().create(agent_id, result)  # writes to in-memory
        if not self._ddb_table:
            return incident
        try:
            self._ddb_table.put_item(Item={
                "incident_id": incident.incident_id,
                "timestamp": incident.timestamp.isoformat(),
                "agent_id": incident.agent_id.value,
                "severity": incident.severity.value,
                "status": incident.status.value,
                "reason_codes": [r.value for r in incident.reason_codes],
                "request_ids": incident.request_ids,
                "description": incident.description,
            })
        except (BotoCoreError, ClientError):
            pass
        return incident

    def get(self, incident_id: str) -> Incident | None:
        if not self._ddb_table:
            return super().get(incident_id)
        # Check in-memory first (fast path)
        cached = super().get(incident_id)
        if cached:
            return cached
        try:
            resp = self._ddb_table.get_item(Key={"incident_id": incident_id})
            item = resp.get("Item")
            if not item:
                return None
            return self._from_item(item)
        except (BotoCoreError, ClientError):
            return None

    def list_all(self) -> list[Incident]:
        if not self._ddb_table:
            return super().list_all()
        try:
            resp = self._ddb_table.scan()
            return [self._from_item(item) for item in resp.get("Items", [])]
        except (BotoCoreError, ClientError):
            return super().list_all()

    def update_status(self, incident_id: str, status: IncidentStatus) -> None:
        super().update_status(incident_id, status)
        if not self._ddb_table:
            return
        try:
            self._ddb_table.update_item(
                Key={"incident_id": incident_id},
                UpdateExpression="SET #s = :s",
                ExpressionAttributeNames={"#s": "status"},
                ExpressionAttributeValues={":s": status.value},
            )
        except (BotoCoreError, ClientError):
            pass

    @staticmethod
    def _from_item(item: dict) -> Incident:
        return Incident(
            incident_id=item["incident_id"],
            timestamp=datetime.fromisoformat(item["timestamp"]),
            agent_id=AgentId(item["agent_id"]),
            severity=IncidentSeverity(item["severity"]),
            status=IncidentStatus(item["status"]),
            reason_codes=[ReasonCode(r) for r in item.get("reason_codes", [])],
            request_ids=item.get("request_ids", []),
            description=item.get("description", ""),
        )
