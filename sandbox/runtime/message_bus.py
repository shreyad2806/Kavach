from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Callable
import sys
import logging

from agents.common.messages import AgentMessage
from agents.common.schemas import SecurityEvent
from sandbox.runtime.event_logger import EventLogger
from kavach_logger import get_logger

logger = get_logger("kavach.sandbox.message_bus")


# ============================================================================
# Lightweight supervision metadata (Phase 20B)
# ============================================================================

@dataclass(frozen=True)
class MessageSupervision:
    """
    Lightweight metadata captured for Kavach supervision.

    This is Level 0 communication metadata only. It does NOT represent
    an authorization decision. It does NOT inspect message content.
    It does NOT copy message payloads. The receiving agent must still
    treat received content as untrusted data.
    """
    message_id: str
    source_agent: str
    target_agent: str
    message_type: str
    timestamp: str
    payload_size: int
    route_allowed: bool
    metadata: dict[str, Any] = field(default_factory=dict)


class CommunicationDeniedError(Exception):
    pass


def _compute_payload_size(content: Any) -> int:
    """
    Best-effort payload size estimation without copying.

    Uses sys.getsizeof for primitives; for containers, sums top-level
    element sizes.  Never raises — returns 0 on failure.
    """
    try:
        if content is None:
            return 0
        if isinstance(content, (str, bytes)):
            return len(content)
        if isinstance(content, dict):
            return sum(sys.getsizeof(k) + sys.getsizeof(v) for k, v in content.items())
        if isinstance(content, (list, tuple, set, frozenset)):
            return sum(sys.getsizeof(item) for item in content)
        return sys.getsizeof(content)
    except Exception:
        return 0


class MessageBus:
    """
    Simple in-memory message bus for local agent communication.
    Now acting as a transport boundary that enforces an explicit allowlist
    of communication routes.

    Phase 20B: Emits lightweight supervision metadata after route validation.
    The supervision hook is optional, fire-and-forget, and never blocks delivery.
    """

    ALLOWED_ROUTES = {
        ("orchestrator", "research"),
        ("orchestrator", "coding"),
        ("orchestrator", "deployment"),
        ("orchestrator", "verification"),
        ("research", "orchestrator"),
        ("coding", "orchestrator"),
        ("coding", "research"),
        ("coding", "verification"),
        ("deployment", "orchestrator"),
        ("deployment", "verification"),
        ("verification", "orchestrator"),
    }

    def __init__(
        self,
        event_logger: EventLogger | None = None,
        supervise: Callable[[MessageSupervision], None] | None = None,
    ) -> None:
        self._handlers: dict[str, list[Callable[[AgentMessage], None]]] = (
            defaultdict(list)
        )
        self.event_logger = event_logger or EventLogger()
        self._supervise = supervise

    def subscribe(
        self,
        agent_id: str,
        handler: Callable[[AgentMessage], None],
    ) -> None:
        """Register a handler for messages sent to an agent."""
        self._handlers[agent_id].append(handler)

    def send(self, message: AgentMessage) -> None:
        """Deliver a message to the receiver's registered handlers."""
        route = (message.sender, message.receiver)
        if route not in self.ALLOWED_ROUTES:
            event = SecurityEvent(
                agent_id=message.sender,
                event_type="COMMUNICATION_DENIED",
                operation="send_message",
                target=message.receiver,
                success=False,
                metadata={"content_type": message.message_type}
            )
            self.event_logger.log(event)
            logger.warning(
                "communication denied",
                extra={"from": message.sender, "to": message.receiver, "message_type": message.message_type},
            )
            raise CommunicationDeniedError(
                f"Communication from {message.sender} to {message.receiver} is not allowed."
            )

        # --- Phase 20B: lightweight supervision (fire-and-forget) ---
        if self._supervise is not None:
            try:
                supervision = MessageSupervision(
                    message_id=message.message_id,
                    source_agent=message.sender,
                    target_agent=message.receiver,
                    message_type=message.message_type,
                    timestamp=message.timestamp,
                    payload_size=_compute_payload_size(message.content),
                    route_allowed=True,
                )
                self._supervise(supervision)
            except Exception as exc:
                logger.warning("MessageBus supervision hook failed: %s", exc)

        handlers = self._handlers.get(message.receiver, [])

        for handler in handlers:
            handler(message)
