from typing import Any

from agents.common.identity import AgentIdentity
from agents.common.messages import AgentMessage
from agents.verification.tools import VerificationTools
from sandbox.runtime.message_bus import MessageBus
from kavach_logger import get_logger

_log = get_logger("kavach.agents.verification")


class VerificationAgent:
    """Inspects outputs and verifies results."""

    def __init__(self, message_bus: MessageBus) -> None:
        self.identity = AgentIdentity(
            agent_id="verification",
            name="Verification Agent",
            role="verifier",
            capabilities=frozenset(
                {
                    "output.inspect",
                    "tests.run",
                    "verification.report",
                    "agent.message",
                }
            ),
        )

        self.tools = VerificationTools(message_bus)
        self.received_tasks: list[AgentMessage] = []

        message_bus.subscribe(
            self.identity.agent_id,
            self.receive_message,
        )

    def receive_message(self, message: AgentMessage) -> None:
        """Receive a task from another agent."""
        self.received_tasks.append(message)

    def inspect_output(self, filename: str) -> dict[str, Any]:
        """Inspect a controlled output file."""
        _log.info("inspecting output", extra={"agent": "verification", "filename": filename})
        result = self.tools.inspect_output(filename)
        _log.info(
            "output inspection complete",
            extra={
                "agent": "verification",
                "filename": filename,
                "status": result.get("status"),
                "size": result.get("size"),
            },
        )
        return result

    def run_tests(self) -> dict[str, Any]:
        """Run controlled verification tests."""
        _log.info("running verification tests", extra={"agent": "verification"})
        result = self.tools.run_tests()
        _log.info(
            "verification tests complete",
            extra={
                "agent": "verification",
                "status": result.get("status"),
                "tests_run": result.get("tests_run"),
                "tests_passed": result.get("tests_passed"),
                "tests_failed": result.get("tests_failed"),
            },
        )
        return result

    def create_report(self, status: str, summary: str) -> dict[str, Any]:
        """Create a verification report."""
        _log.info(
            "creating verification report",
            extra={"agent": "verification", "status": status},
        )
        return self.tools.create_report(status, summary)

    def send_result(self, receiver: str, content: dict[str, Any]) -> AgentMessage:
        """Send verification results to another agent."""
        _log.info(
            "sending result",
            extra={"agent": "verification", "target": receiver, "status": content.get("status")},
        )
        return self.tools.send_message(receiver, content)
