"""
Session-scoped authorization event buffer.

The permanent audit trail is the append-only JSONL file owned by
``shield.telemetry.events`` (``logs/kavach/audit.log``).  That file is history:
it survives restarts and is never cleared by the UI.

This module is the *current session* projection of that same telemetry: the
authorization events produced since the process started (or since the last
``clear_events()``).  The dashboard and the Agent Activity panel read from
here so a fresh demo session never shows historical audit-log entries.

It is deliberately a projection of already-emitted telemetry — it does not
compute, infer, or fabricate anything.
"""

import threading
from typing import Any

# Bound the buffer so a long-lived process cannot grow without limit.
_MAX_EVENTS = 500

_lock = threading.Lock()
_events: list[dict[str, Any]] = []


def record_event(event: dict[str, Any]) -> None:
    """Append one already-emitted authorization event to the session buffer."""
    with _lock:
        _events.append(event)
        overflow = len(_events) - _MAX_EVENTS
        if overflow > 0:
            del _events[:overflow]


def list_events(
    limit: int | None = None,
    workflow_id: str | None = None,
) -> list[dict[str, Any]]:
    """Return session events newest-first (the order the UI consumes).

    ``workflow_id`` narrows the result to one workflow's decisions, which is
    how the dashboard shows only the CURRENT workflow session rather than
    every decision this process has ever made.
    """
    with _lock:
        snapshot = list(_events)
    if workflow_id is not None:
        snapshot = [e for e in snapshot if e.get("workflow_id") == workflow_id]
    snapshot.reverse()
    if limit is not None and limit >= 0:
        snapshot = snapshot[:limit]
    return snapshot


def clear_events() -> None:
    """Drop the current session's events. Permanent audit history is untouched."""
    with _lock:
        _events.clear()


def counts(workflow_id: str | None = None) -> dict[str, int]:
    """Return ALLOW/DENY/total counts for the current session (or one workflow)."""
    with _lock:
        snapshot = list(_events)
    if workflow_id is not None:
        snapshot = [e for e in snapshot if e.get("workflow_id") == workflow_id]
    allow = sum(1 for e in snapshot if e.get("policy_decision") == "ALLOW")
    deny = sum(1 for e in snapshot if e.get("policy_decision") == "DENY")
    return {"ALLOW": allow, "DENY": deny, "total": len(snapshot)}
