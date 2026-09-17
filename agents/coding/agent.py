from typing import Any

from agents.common.identity import AgentIdentity
from agents.common.messages import AgentMessage
from agents.coding.tools import CodingTools
from sandbox.runtime.message_bus import MessageBus


class CodingAgent:
    """Creates and tests application code."""

    def __init__(self, message_bus: MessageBus) -> None:
        self.identity = AgentIdentity(
            agent_id="coding",
            name="Coding Agent",
            role="developer",
            capabilities=frozenset(
                {
                    "file.read",
                    "file.write",
                    "tests.run",
                    "agent.message",
                }
            ),
        )

        self.tools = CodingTools(message_bus)

        self.received_tasks: list[AgentMessage] = []

        message_bus.subscribe(
            self.identity.agent_id,
            self.receive_message,
        )

    def receive_message(
        self,
        message: AgentMessage,
    ) -> None:
        """Receive a task from another agent."""
        self.received_tasks.append(message)

        print(
            f"[CODING] Received {message.message_type} "
            f"from {message.sender}"
        )

    def read_file(
        self,
        filename: str,
    ) -> str:
        """Read a file from the coding workspace."""
        return self.tools.read_file(filename)

    def write_file(
        self,
        filename: str,
        content: str,
    ) -> str:
        """Write a file to the coding workspace."""
        return self.tools.write_file(
            filename,
            content,
        )

    def run_tests(self) -> dict[str, Any]:
        """Run controlled tests."""
        return self.tools.run_tests()

    def send_result(
        self,
        receiver: str,
        content: dict[str, Any],
    ) -> AgentMessage:
        """Send coding results to another agent."""
        return self.tools.send_message(
            receiver,
            content,
        )