import json

from fastapi import APIRouter, Depends

from api.middleware.auth import require_api_key
from shield.runtime.services import get_runtime
from shield.telemetry.events import get_audit_log_path

router = APIRouter(dependencies=[Depends(require_api_key)])


@router.get("/")
async def dashboard():
    rt = get_runtime()
    agents = rt.identity_service.list_agents()
    agent_states: dict[str, int] = {}
    for a in agents:
        agent_states[a.state.value] = agent_states.get(a.state.value, 0) + 1

    incidents = rt.incident_service.list_all()
    open_count = sum(1 for i in incidents if i.status.value == "OPEN")

    recent_events = []
    path = get_audit_log_path()
    if path.exists():
        lines = path.read_text(encoding="utf-8").splitlines()
        for line in reversed(lines):
            line = line.strip()
            if not line:
                continue
            try:
                recent_events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
            if len(recent_events) >= 20:
                break

    deny_count  = sum(1 for e in recent_events if e.get("policy_decision") == "DENY")
    allow_count = sum(1 for e in recent_events if e.get("policy_decision") == "ALLOW")

    return {
        "agents":        {"total": len(agents), "by_state": agent_states},
        "incidents":     {"total": len(incidents), "open": open_count},
        "recent_events": {"total": len(recent_events), "deny": deny_count, "allow": allow_count},
    }
