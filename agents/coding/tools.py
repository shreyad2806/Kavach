from pathlib import Path
from typing import Any

from agents.common.messages import AgentMessage
from sandbox.runtime.kavach_guard import KavachGuard
from sandbox.runtime.message_bus import MessageBus
from sandbox.runtime.workspace import SafeWorkspace
from shield.capabilities.models import CapabilityName
from shield.gateway.models import ActionName, ResourceName


# Module-level guard instance shared by all CodingTools instances
_guard = KavachGuard()


class CodingTools:
    """Tools available to the Coding Agent."""

    def __init__(
        self,
        message_bus: MessageBus,
        workspace: str = "sandbox/workspace/coding",
    ) -> None:
        self.message_bus = message_bus
        self.workspace = SafeWorkspace("coding", workspace)

    @_guard.protect("coding", ActionName.CODING_READ, ResourceName.WORKSPACE, CapabilityName.CODING_READ)
    def read_file(self, filename: str) -> str:
        """Read a file from the Coding workspace.

        An artifact that has not been written yet reads as empty content: the
        coding agent inspects the current artifact *before* rewriting it, and on
        a fresh workspace there is simply nothing to inspect yet.  Path
        containment is still enforced by SafeWorkspace on every read — a
        traversal attempt (WorkspaceAccessDeniedError) or a non-file target
        (ValueError) still fails closed.
        """
        try:
            return self.workspace.read_text(filename)
        except FileNotFoundError:
            return ""

    @_guard.protect("coding", ActionName.CODING_WRITE, ResourceName.WORKSPACE, CapabilityName.CODING_WRITE)
    def write_file(
        self,
        filename: str,
        content: str,
    ) -> str:
        """Write a file into the Coding workspace."""
        return str(self.workspace.write_text(filename, content))

    @_guard.protect("coding", ActionName.CODING_TEST, ResourceName.TEST_ENVIRONMENT, CapabilityName.CODING_TEST)
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