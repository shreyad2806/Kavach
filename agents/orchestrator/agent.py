from typing import Any

from agents.common.identity import AgentIdentity
from agents.common.messages import AgentMessage
from agents.orchestrator.tools import OrchestratorTools
from sandbox.runtime.message_bus import MessageBus
from kavach_logger import get_logger

_log = get_logger("kavach.agents.orchestrator")


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
        """Receive a result from another agent."""
        self.received_results.append(message)

    def delegate(
        self,
        receiver: str,
        task: dict[str, Any],
    ) -> AgentMessage:
        """Delegate a task to another agent."""
        _log.info(
            "delegating task",
            extra={"agent": "orchestrator", "target": receiver, "task_keys": list(task.keys())},
        )
        result = self.tools.delegate_task(receiver=receiver, task=task)
        _log.info(
            "task delegated",
            extra={"agent": "orchestrator", "target": receiver, "message_id": result.message_id},
        )
        return result

    def get_results(self) -> list[AgentMessage]:
        """Return results received by the Orchestrator."""
        return list(self.received_results)
