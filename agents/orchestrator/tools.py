from typing import Any

from agents.common.messages import AgentMessage
from sandbox.runtime.message_bus import MessageBus


class OrchestratorTools:
    """Tools available to the Orchestrator Agent."""

    def __init__(self, message_bus: MessageBus) -> None:
        self.message_bus = message_bus

    def delegate_task(
        self,
        receiver: str,
        task: dict[str, Any],
    ) -> AgentMessage:
        """Send a task to another agent."""
        message = AgentMessage(
            sender="orchestrator",
            receiver=receiver,
            message_type="TASK",
            content=task,
        )

        self.message_bus.send(message)
        return message