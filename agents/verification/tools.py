from pathlib import Path
from typing import Any

from agents.common.messages import AgentMessage
from sandbox.runtime.kavach_guard import KavachGuard
from sandbox.runtime.message_bus import MessageBus
from sandbox.runtime.workspace import SafeWorkspace
from shield.capabilities.models import CapabilityName
from shield.gateway.models import ActionName, ResourceName


# Module-level guard instance shared by all VerificationTools instances
_guard = KavachGuard()


class VerificationTools:
    """Tools available to the Verification Agent."""

    def __init__(
        self,
        message_bus: MessageBus,
        workspace: str = "sandbox/workspace/verification",
    ) -> None:
        self.message_bus = message_bus
        self.workspace = SafeWorkspace("verification", workspace)

    @_guard.protect("verification", ActionName.VERIFICATION_TEST, ResourceName.TEST_ENVIRONMENT, CapabilityName.VERIFICATION_TEST)
    def inspect_output(
        self,
        filename: str,
    ) -> dict[str, Any]:
        """Inspect a file from the controlled verification workspace."""
        try:
            content = self.workspace.read_text(filename)
            return {
                "status": "FOUND",
                "file": filename,
                "size": len(content),
                "content": content,
            }
        except FileNotFoundError:
            return {
                "status": "NOT_FOUND",
                "file": filename,
            }
        except ValueError:
            return {
                "status": "INVALID",
                "file": filename,
            }

    @_guard.protect("verification", ActionName.VERIFICATION_TEST, ResourceName.TEST_ENVIRONMENT, CapabilityName.VERIFICATION_TEST)
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