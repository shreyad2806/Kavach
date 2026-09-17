from collections import defaultdict
from typing import Callable

from agents.common.messages import AgentMessage


class MessageBus:
    """
    Simple in-memory message bus for local agent communication.

    The message bus is only a transport mechanism.
    It is NOT a security authority.
    """

    def __init__(self) -> None:
        self._handlers: dict[str, list[Callable[[AgentMessage], None]]] = (
            defaultdict(list)
        )

    def subscribe(
        self,
        agent_id: str,
        handler: Callable[[AgentMessage], None],
    ) -> None:
        """Register a handler for messages sent to an agent."""
        self._handlers[agent_id].append(handler)

    def send(self, message: AgentMessage) -> None:
        """Deliver a message to the receiver's registered handlers."""
        handlers = self._handlers.get(message.receiver, [])

        for handler in handlers:
            handler(message)