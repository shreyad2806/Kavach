from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
import uuid


@dataclass
class AgentMessage:
    sender: str
    receiver: str
    message_type: str
    content: Any

    message_id: str = field(
        default_factory=lambda: str(uuid.uuid4())
    )

    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )