"""Agent control-plane routes.

Exposes the five real Shield identities and quarantine/restore controls.
All state comes from the shared runtime's IdentityService — the same registry
the real P1 KavachGuard consults — so an isolate call here is immediately
enforced against protected P1 operations.

Frontend contract (frontend/src/api.js + FleetList/AgentControlCard):
    [{ "agent_id", "role", "state", "risk_score" }]

``risk_score`` is intentionally null: Shield does not maintain an authoritative
per-agent risk score (risk is computed per authorization decision, not per
agent).  The frontend already treats it as optional (``!= null`` checks), so we
return null rather than fabricate a value.
"""

from fastapi import APIRouter, HTTPException

from api.deps import get_identity_service, get_quarantine_service
from shield.identity.models import AgentId

router = APIRouter()


def _serialize(identity) -> dict:
    return {
        "agent_id": identity.agent_id.value,
        "role": identity.role.value,
        "state": identity.state.value,
        # No authoritative per-agent risk score exists in Shield; the frontend
        # treats this as optional/nullable. Never fabricate one.
        "risk_score": None,
    }


def _resolve_agent_id(agent_id: str) -> AgentId:
    try:
        return AgentId(agent_id)
    except ValueError:
        raise HTTPException(status_code=404, detail=f"Agent '{agent_id}' not found")


@router.get("")
async def list_agents() -> list[dict]:
    identities = get_identity_service().list_agents()
    return [_serialize(identity) for identity in identities]


@router.get("/{agent_id}")
async def get_agent(agent_id: str) -> dict:
    identity = get_identity_service().get_agent(_resolve_agent_id(agent_id))
    if identity is None:
        raise HTTPException(status_code=404, detail=f"Agent '{agent_id}' not found")
    return _serialize(identity)


@router.post("/{agent_id}/isolate")
async def isolate_agent(agent_id: str) -> dict:
    resolved = _resolve_agent_id(agent_id)
    try:
        get_quarantine_service().quarantine(resolved)
    except KeyError:
        raise HTTPException(status_code=404, detail=f"Agent '{agent_id}' not found")
    identity = get_identity_service().get_agent(resolved)
    return _serialize(identity)


@router.post("/{agent_id}/restore")
async def restore_agent(agent_id: str) -> dict:
    resolved = _resolve_agent_id(agent_id)
    try:
        get_quarantine_service().release(resolved)
    except KeyError:
        raise HTTPException(status_code=404, detail=f"Agent '{agent_id}' not found")
    identity = get_identity_service().get_agent(resolved)
    return _serialize(identity)
