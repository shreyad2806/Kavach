"""Authorization event stream.

Returns the CURRENT session's authorization events — the decisions produced by
KavachGuard / authorize() since this process started (or since the demo session
was reset).

The append-only JSONL audit file remains the permanent record; this endpoint is
the live projection the dashboard consumes, so a fresh session never shows
historical decisions.  Nothing here is synthesised: every record came from
``shield.telemetry.write_event``.
"""

from fastapi import APIRouter, Depends, Query

from api.middleware.auth import require_api_key
from shield.telemetry.session import list_events as _list_session_events

router = APIRouter(dependencies=[Depends(require_api_key)])


@router.get("/")
async def list_events(limit: int = Query(default=100, le=500)):
    return _list_session_events(limit=limit)
