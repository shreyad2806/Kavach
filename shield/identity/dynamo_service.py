"""
DynamoDB-backed IdentityService.

Falls back to the in-memory IdentityService if SHIELD_AGENTS_TABLE is not set
or DynamoDB is unreachable, so local dev and tests work without AWS.
"""

import os
from copy import deepcopy

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from shield.identity.models import AgentId, AgentIdentity, AgentRole, SecurityState
from shield.identity.service import CANONICAL_AGENTS, IdentityService


def _table():
    name = os.environ.get("SHIELD_AGENTS_TABLE")
    if not name:
        return None
    return boto3.resource("dynamodb").Table(name)


class DynamoIdentityService(IdentityService):
    """
    IdentityService backed by DynamoDB for persistent agent state.
    Bootstraps the table with canonical agents on first use.
    """

    def __init__(self) -> None:
        super().__init__()  # populates in-memory registry
        self._table = _table()
        if self._table:
            self._bootstrap()

    def _bootstrap(self) -> None:
        """Write canonical agents to DynamoDB if they don't exist yet."""
        for agent_id, spec in CANONICAL_AGENTS.items():
            try:
                self._table.put_item(
                    Item={
                        "agent_id": agent_id.value,
                        "role": spec["role"].value,
                        "state": spec["status"].value,
                    },
                    ConditionExpression="attribute_not_exists(agent_id)",
                )
            except ClientError as e:
                if e.response["Error"]["Code"] != "ConditionalCheckFailedException":
                    raise

    def get_agent(self, agent_id: AgentId | str) -> AgentIdentity | None:
        if not self._table:
            return super().get_agent(agent_id)
        resolved = self._resolve_agent_id(agent_id)
        if resolved is None:
            return None
        try:
            resp = self._table.get_item(Key={"agent_id": resolved.value})
            item = resp.get("Item")
            if not item:
                return None
            return AgentIdentity(
                agent_id=AgentId(item["agent_id"]),
                role=AgentRole(item["role"]),
                state=SecurityState(item["state"]),
            )
        except (BotoCoreError, ClientError):
            return super().get_agent(agent_id)

    def set_state(self, agent_id: AgentId | str, state: SecurityState | str) -> None:
        super().set_state(agent_id, state)  # validates and updates in-memory
        if not self._table:
            return
        resolved_id = self._resolve_agent_id(agent_id)
        resolved_state = self._resolve_security_state(state)
        try:
            self._table.update_item(
                Key={"agent_id": resolved_id.value},
                UpdateExpression="SET #s = :s",
                ExpressionAttributeNames={"#s": "state"},
                ExpressionAttributeValues={":s": resolved_state.value},
            )
        except (BotoCoreError, ClientError):
            pass  # in-memory already updated; DynamoDB failure is non-fatal

    def list_agents(self) -> list[AgentIdentity]:
        if not self._table:
            return super().list_agents()
        try:
            resp = self._table.scan()
            return [
                AgentIdentity(
                    agent_id=AgentId(item["agent_id"]),
                    role=AgentRole(item["role"]),
                    state=SecurityState(item["state"]),
                )
                for item in resp.get("Items", [])
            ]
        except (BotoCoreError, ClientError):
            return super().list_agents()
