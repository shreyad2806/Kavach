from pathlib import Path
from typing import Any

from agents.common.messages import AgentMessage
from sandbox.runtime.message_bus import MessageBus
from sandbox.runtime.workspace import SafeWorkspace


class CodingTools:
    """Tools available to the Coding Agent."""

    def __init__(
        self,
        message_bus: MessageBus,
        workspace: str = "sandbox/workspace/coding",
    ) -> None:
        self.message_bus = message_bus
        self.workspace = SafeWorkspace("coding", workspace)

    def read_file(self, filename: str) -> str:
        """Read a file from the Coding workspace."""
        return self.workspace.read_text(filename)

    def write_file(
        self,
        filename: str,
        content: str,
    ) -> str:
        """Write a file into the Coding workspace."""
        return str(self.workspace.write_text(filename, content))

    def run_tests(self) -> dict[str, Any]:
        """
        Simulate running tests.

        Real test execution will be added only inside the
        sandbox and will not provide unrestricted shell access.
        """
        return {
            "status": "PASSED",
            "tests_run": 3,
            "tests_passed": 3,
            "tests_failed": 0,
        }

    def send_message(
        self,
        receiver: str,
        content: dict[str, Any],
    ) -> AgentMessage:
        """Send a structured message to another agent."""
        message = AgentMessage(
            sender="coding",
            receiver=receiver,
            message_type="RESULT",
            content=content,
        )

        self.message_bus.send(message)

        return message