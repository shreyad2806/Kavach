from typing import Any

from agents.common.messages import AgentMessage
from sandbox.runtime.kavach_guard import KavachGuard
from sandbox.runtime.message_bus import MessageBus
from shield.capabilities.models import CapabilityName
from shield.gateway.models import ActionName, ResourceName


# Module-level guard instance shared by all OrchestratorTools instances
_guard = KavachGuard()


class OrchestratorTools:
    """Tools available to the Orchestrator Agent."""

    def __init__(self, message_bus: MessageBus) -> None:
        self.message_bus = message_bus

    @_guard.protect("orchestrator", ActionName.ORCHESTRATOR_DELEGATE, ResourceName.WORKSPACE, CapabilityName.ORCHESTRATOR_DELEGATE)
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