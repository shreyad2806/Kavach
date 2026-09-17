from typing import Any

from agents.common.identity import AgentIdentity
from agents.common.messages import AgentMessage
from agents.verification.tools import VerificationTools
from sandbox.runtime.message_bus import MessageBus


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

    def receive_message(
        self,
        message: AgentMessage,
    ) -> None:
        """Receive a task from another agent."""

        self.received_tasks.append(message)

        print(
            f"[VERIFICATION] Received {message.message_type} "
            f"from {message.sender}"
        )

    def inspect_output(
        self,
        filename: str,
    ) -> dict[str, Any]:
        """Inspect a controlled output."""

        return self.tools.inspect_output(
            filename
        )

    def run_tests(self) -> dict[str, Any]:
        """Run controlled verification tests."""

        return self.tools.run_tests()

    def create_report(
        self,
        status: str,
        summary: str,
    ) -> dict[str, Any]:
        """Create a verification report."""

        return self.tools.create_report(
            status,
            summary,
        )

    def send_result(
        self,
        receiver: str,
        content: dict[str, Any],
    ) -> AgentMessage:
        """Send verification results to another agent."""

        return self.tools.send_message(
            receiver,
            content,
        )