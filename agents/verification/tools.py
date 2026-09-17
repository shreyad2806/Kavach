from pathlib import Path
from typing import Any

from agents.common.messages import AgentMessage
from sandbox.runtime.message_bus import MessageBus


class VerificationTools:
    """Tools available to the Verification Agent."""

    def __init__(
        self,
        message_bus: MessageBus,
        workspace: str = "sandbox/workspace/verification",
    ) -> None:
        self.message_bus = message_bus
        self.workspace = Path(workspace)

        self.workspace.mkdir(
            parents=True,
            exist_ok=True,
        )

    def inspect_output(
        self,
        filename: str,
    ) -> dict[str, Any]:
        """Inspect a file from the controlled verification workspace."""

        file_path = self.workspace / filename

        if not file_path.exists():
            return {
                "status": "NOT_FOUND",
                "file": filename,
            }

        if not file_path.is_file():
            return {
                "status": "INVALID",
                "file": filename,
            }

        content = file_path.read_text(
            encoding="utf-8"
        )

        return {
            "status": "FOUND",
            "file": filename,
            "size": len(content),
            "content": content,
        }

    def run_tests(self) -> dict[str, Any]:
        """Simulate controlled verification tests."""

        return {
            "status": "PASSED",
            "tests_run": 3,
            "tests_passed": 3,
            "tests_failed": 0,
        }

    def create_report(
        self,
        status: str,
        summary: str,
    ) -> dict[str, Any]:
        """Create a structured verification report."""

        return {
            "status": status,
            "summary": summary,
            "verified": status == "PASSED",
        }

    def send_message(
        self,
        receiver: str,
        content: dict[str, Any],
    ) -> AgentMessage:
        """Send a structured message to another agent."""

        message = AgentMessage(
            sender="verification",
            receiver=receiver,
            message_type="RESULT",
            content=content,
        )

        self.message_bus.send(message)

        return message