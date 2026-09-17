from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
import uuid


@dataclass
class ToolRequest:
    agent_id: str
    operation: str
    target: str
    arguments: dict[str, Any]

    request_id: str = field(
        default_factory=lambda: str(uuid.uuid4())
    )

    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    
@dataclass
class ToolResponse:
    request_id: str
    success: bool
    result: Any = None
    error: str | None = None


@dataclass
class SecurityEvent:
    agent_id: str
    event_type: str
    operation: str

    target: str | None = None
    success: bool = True
    metadata: dict[str, Any] = field(default_factory=dict)

    event_id: str = field(
        default_factory=lambda: str(uuid.uuid4())
    )

    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )