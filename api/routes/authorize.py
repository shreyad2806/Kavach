"""Authorization gateway — ``POST /authorize``.

Evaluates a single ActionRequest against the shared ShieldRuntime so that an
HTTP caller (the Node BFF, an external orchestrator) sees exactly the same
identity, capability, provenance, Cedar and detection state the real P1 agents
are enforced against.

This route adds no authorization logic of its own: it builds the existing
ActionRequest contract and hands it to the existing pipeline.
"""

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from api.middleware.auth import require_api_key
from shield.capabilities.models import CapabilityName
from shield.gateway.models import (
    ActionName,
    ActionRequest,
    AuthorizationResult,
    ResourceName,
)
from shield.identity.models import AgentId
from shield.provenance.models import Provenance
from shield.runtime.services import get_runtime

router = APIRouter(dependencies=[Depends(require_api_key)])


class AuthorizeRequest(BaseModel):
    source_agent: str
    target_agent: str
    task_id: str
    action: str
    resource: str
    claimed_authority: str
    capability: str
    provenance: dict[str, list[str] | str]

    def to_action_request(self) -> ActionRequest:
        provenance_data = self.provenance
        return ActionRequest(
            request_id=f"http-{uuid.uuid4().hex[:12]}",
            timestamp=datetime.now(timezone.utc),
            source_agent=AgentId(self.source_agent),
            target_agent=AgentId(self.target_agent),
            task_id=self.task_id,
            action=ActionName(self.action),
            resource=ResourceName(self.resource),
            claimed_authority=AgentId(self.claimed_authority),
            capability=CapabilityName(self.capability),
            provenance=Provenance(
                task_origin=AgentId(provenance_data["task_origin"]),
                delegation_chain=[
                    AgentId(agent) for agent in provenance_data["delegation_chain"]
                ],
            ),
        )


@router.post("", response_model=AuthorizationResult)
async def authorize_request(body: AuthorizeRequest) -> AuthorizationResult:
    try:
        request = body.to_action_request()
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    try:
        return get_runtime().authorize(request)
    except Exception as exc:  # noqa: BLE001 - surfaced as a controlled 500
        raise HTTPException(status_code=500, detail=f"Internal error: {exc}")
