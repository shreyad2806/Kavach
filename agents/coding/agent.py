from typing import Any

from agents.common.identity import AgentIdentity
from agents.common.messages import AgentMessage
from agents.coding.tools import CodingTools
from sandbox.runtime.message_bus import MessageBus
from kavach_logger import get_logger

_log = get_logger("kavach.agents.coding")


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

    def receive_message(self, message: AgentMessage) -> None:
        """Receive a task from another agent."""
        self.received_tasks.append(message)

    def read_file(self, filename: str) -> str:
        """Read a file from the coding workspace."""
        _log.info("reading file", extra={"agent": "coding", "file": filename})
        content = self.tools.read_file(filename)
        _log.info(
            "file read",
            extra={"agent": "coding", "file": filename, "content_length": len(content)},
        )
        return content

    def write_file(self, filename: str, content: str) -> str:
        """Write a file to the coding workspace."""
        _log.info(
            "writing file",
            extra={"agent": "coding", "file": filename, "content_length": len(content)},
        )
        result = self.tools.write_file(filename, content)
        _log.info("file written", extra={"agent": "coding", "file": filename})
        return result

    def run_tests(self) -> dict[str, Any]:
        """Run controlled tests."""
        _log.info("running tests", extra={"agent": "coding"})
        result = self.tools.run_tests()
        _log.info(
            "tests complete",
            extra={
                "agent": "coding",
                "status": result.get("status"),
                "tests_run": result.get("tests_run"),
                "tests_passed": result.get("tests_passed"),
                "tests_failed": result.get("tests_failed"),
            },
        )
        return result

    def send_result(self, receiver: str, content: dict[str, Any]) -> AgentMessage:
        """Send coding results to another agent."""
        _log.info(
            "sending result",
            extra={"agent": "coding", "target": receiver, "status": content.get("status")},
        )
        return self.tools.send_message(receiver, content)
