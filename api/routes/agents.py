from fastapi import APIRouter, Depends, HTTPException

from api.middleware.auth import require_api_key
from shield.identity.models import SecurityState
from shield.runtime.services import get_runtime

router = APIRouter(dependencies=[Depends(require_api_key)])


@router.get("/")
async def list_agents():
    agents = get_runtime().identity_service.list_agents()
    return [
        {"agent_id": a.agent_id.value, "role": a.role.value, "state": a.state.value}
        for a in agents
    ]


@router.get("/{agent_id}")
async def get_agent(agent_id: str):
    agent = get_runtime().identity_service.get_agent(agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail=f"Agent '{agent_id}' not found")
    return {"agent_id": agent.agent_id.value, "role": agent.role.value, "state": agent.state.value}


@router.post("/{agent_id}/isolate")
async def isolate_agent(agent_id: str):
    try:
        get_runtime().quarantine_service.quarantine(agent_id)
    except KeyError:
        raise HTTPException(status_code=404, detail=f"Agent '{agent_id}' not found")
    return {"agent_id": agent_id, "state": SecurityState.QUARANTINED.value}


@router.post("/{agent_id}/restore")
async def restore_agent(agent_id: str):
    try:
        get_runtime().quarantine_service.release(agent_id)
    except KeyError:
        raise HTTPException(status_code=404, detail=f"Agent '{agent_id}' not found")
    return {"agent_id": agent_id, "state": SecurityState.ACTIVE.value}
