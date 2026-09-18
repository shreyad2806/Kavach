from collections import defaultdict
from typing import Callable

from agents.common.messages import AgentMessage
from agents.common.schemas import SecurityEvent
from sandbox.runtime.event_logger import EventLogger


class CommunicationDeniedError(Exception):
    pass


class MessageBus:
    """
    Simple in-memory message bus for local agent communication.

    Now acting as a transport boundary that enforces an explicit allowlist
    of communication routes.
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

    def __init__(self, event_logger: EventLogger | None = None) -> None:
        self._handlers: dict[str, list[Callable[[AgentMessage], None]]] = (
            defaultdict(list)
        )
        self.event_logger = event_logger or EventLogger()

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
            raise CommunicationDeniedError(
                f"Communication from {message.sender} to {message.receiver} is not allowed."
            )

        handlers = self._handlers.get(message.receiver, [])

        for handler in handlers:
            handler(message)
