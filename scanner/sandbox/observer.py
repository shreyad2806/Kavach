"""
Sandbox observer — parses raw container output line by line,
matches against signal patterns, and produces SandboxEvent objects.
"""

from datetime import datetime, timezone

from scanner.models.sandbox import SandboxEvent
from scanner.sandbox.signals import SIGNALS


def observe(artifact_id: str, output: str) -> list[SandboxEvent]:
    """
    Parse container stdout+stderr and return all matched SandboxEvents.
    Each line is checked against every signal pattern.
    Multiple signals can fire on the same line.
    """
    events: list[SandboxEvent] = []
    now = datetime.now(timezone.utc)

    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        for signal in SIGNALS:
            if signal.pattern.search(line):
                events.append(SandboxEvent(
                    artifact_id=artifact_id,
                    event_type=signal.event_type,
                    detail=line[:300],  # cap detail length
                    suspicious=signal.suspicious,
                    timestamp=now,
                ))
                break  # first match wins per line

    return events
