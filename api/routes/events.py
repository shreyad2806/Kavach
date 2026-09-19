import json

from fastapi import APIRouter, Depends, Query

from api.middleware.auth import require_api_key
from shield.telemetry.events import get_audit_log_path

router = APIRouter(dependencies=[Depends(require_api_key)])


@router.get("/")
async def list_events(limit: int = Query(default=100, le=500)):
    path = get_audit_log_path()
    if not path.exists():
        return []
    lines = path.read_text(encoding="utf-8").splitlines()
    events = []
    for line in reversed(lines):
        line = line.strip()
        if not line:
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            continue
        if len(events) >= limit:
            break
    return events
