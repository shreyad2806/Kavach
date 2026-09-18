from pathlib import Path
from typing import Any

from agents.common.messages import AgentMessage
from sandbox.runtime.kavach_guard import KavachGuard
from sandbox.runtime.message_bus import MessageBus
from sandbox.runtime.workspace import SafeWorkspace
from sandbox.runtime.network import NetworkManager
from shield.capabilities.models import CapabilityName
from shield.gateway.models import ActionName, ResourceName


# Module-level guard instance shared by all ResearchTools instances
_guard = KavachGuard()


class ResearchTools:
    """Tools available to the Research Agent."""

    def __init__(
        self,
        message_bus: MessageBus,
        workspace: str = "sandbox/workspace/research",
        network_manager: NetworkManager | None = None,
    ) -> None:
        self.message_bus = message_bus
        self.workspace = SafeWorkspace("research", workspace)
        self.network_manager = network_manager or NetworkManager()

    @_guard.protect("research", ActionName.RESEARCH_SEARCH, ResourceName.RESEARCH_DATA, CapabilityName.RESEARCH_SEARCH)
    def web_search(self, query: str) -> dict[str, Any]:
        """
        Simulated web search.

        This is intentionally local for the MVP.
        A real web-search provider can be connected later.
        """
        self.network_manager.check_access("research", "web_search")
        return {
            "query": query,
            "results": [
                {
                    "title": "Simulated Research Result",
                    "summary": f"Research information for: {query}",
                }
            ],
        }

    @_guard.protect("research", ActionName.RESEARCH_READ, ResourceName.RESEARCH_DATA, CapabilityName.RESEARCH_READ)
    def read_document(self, filename: str) -> str:
        """Read a document from the Research workspace."""
        return self.workspace.read_text(filename)

    @_guard.protect("research", ActionName.RESEARCH_WRITE, ResourceName.RESEARCH_DATA, CapabilityName.RESEARCH_WRITE)
    def write_research(
        self,
        filename: str,
        content: str,
    ) -> str:
        """Write research output to the Research workspace."""
        return str(self.workspace.write_text(filename, content))

    def send_message(
        self,
        receiver: str,
        content: dict[str, Any],
    ) -> AgentMessage:
        """Send a structured message to another agent."""
        message = AgentMessage(
            sender="research",
            receiver=receiver,
            message_type="RESULT",
            content=content,
        )

        self.message_bus.send(message)

        return message