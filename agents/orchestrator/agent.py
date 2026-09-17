from typing import Any

from agents.common.identity import AgentIdentity
from agents.common.messages import AgentMessage
from agents.orchestrator.tools import OrchestratorTools
from sandbox.runtime.message_bus import MessageBus


class OrchestratorAgent:
    """Coordinates work between the other agents."""

    def __init__(self, message_bus: MessageBus) -> None:
        self.identity = AgentIdentity(
            agent_id="orchestrator",
            name="Orchestrator Agent",
            role="coordinator",
            capabilities=frozenset(
                {
                    "task.delegate",
                    "result.receive",
                    "workflow.coordinate",
                }
            ),
        )

        self.tools = OrchestratorTools(message_bus)
        self.received_results: list[AgentMessage] = []

        message_bus.subscribe(
            self.identity.agent_id,
            self.receive_message,
        )

    def receive_message(self, message: AgentMessage) -> None:
        """Receive a message from another agent."""
        self.received_results.append(message)

        print(
            f"[ORCHESTRATOR] Received {message.message_type} "
            f"from {message.sender}"
        )

    def delegate(
        self,
        receiver: str,
        task: dict[str, Any],
    ) -> AgentMessage:
        """Delegate a task to another agent."""
        return self.tools.delegate_task(
            receiver=receiver,
            task=task,
        )

    def get_results(self) -> list[AgentMessage]:
        """Return results received by the Orchestrator."""
        return list(self.received_results)