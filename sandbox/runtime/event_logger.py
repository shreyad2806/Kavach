import json
from pathlib import Path

from agents.common.schemas import SecurityEvent


class EventLogger:
    """
    Records structured security events locally.

    This is a simple local implementation for the hackathon.
    It can later be replaced or extended with CloudWatch/EventBridge
    integration without changing the agent contracts.
    """

    def __init__(self, log_file: str = "sandbox/runtime/security_events.jsonl") -> None:
        self.log_file = Path(log_file)
        self.log_file.parent.mkdir(parents=True, exist_ok=True)

    def log(self, event: SecurityEvent) -> None:
        """Write one security event as a JSON line."""
        with self.log_file.open("a", encoding="utf-8") as file:
            file.write(
                json.dumps(
                    {
                        "event_id": event.event_id,
                        "agent_id": event.agent_id,
                        "event_type": event.event_type,
                        "operation": event.operation,
                        "target": event.target,
                        "success": event.success,
                        "metadata": event.metadata,
                        "timestamp": event.timestamp,
                    }
                )
                + "\n"
            )