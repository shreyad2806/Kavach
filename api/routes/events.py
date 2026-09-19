"""Security event routes.

GET /events returns the REAL authorization decisions emitted by the Kavach
pipeline.  Every decision (ALLOW or DENY) is written as one JSON line to the
Shield audit sink by ``shield.telemetry.events.write_event`` — this route simply
projects that existing sink over HTTP.  No second telemetry system is created.

Event categories are kept distinct by endpoint:
  * authorization events  -> GET /events            (this route, Shield audit log)
  * workflow lifecycle    -> GET /workflows/{id}/events (supervisor-owned)
  * sandbox events        -> sandbox/runtime/security_events.jsonl (runtime sink)

Each event is tagged with ``category`` so consumers can tell them apart.
The serialized shape already matches the frontend contract
(frontend/src/components/AgentActivityPanel.jsx, AuthPipeline.jsx):
    event_id, timestamp, source_agent, action, resource,
    policy_decision, reason_codes, risk_score
"""

import json

from fastapi import APIRouter, Query

from shield.telemetry.events import get_audit_log_path

router = APIRouter()

# The audit sink is append-only and grows across runs; return a bounded,
# most-recent window by default so the feed stays usable. All data is real.
DEFAULT_EVENT_LIMIT = 200


def _read_authorization_events() -> list[dict]:
    path = get_audit_log_path()
    if not path.exists():
        return []
    events: list[dict] = []
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                # A malformed/partial line must not break the whole feed.
                continue
            record.setdefault("category", "authorization")
            events.append(record)
    return events


@router.get("")
async def list_events(
    limit: int = Query(default=DEFAULT_EVENT_LIMIT, ge=1, le=5000),
) -> list[dict]:
    events = _read_authorization_events()
    # Most recent `limit` events, kept in chronological order.
    return events[-limit:]
