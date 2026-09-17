from pathlib import Path
from typing import Any

from agents.common.messages import AgentMessage
from sandbox.runtime.message_bus import MessageBus


class ResearchTools:
    """Tools available to the Research Agent."""

    def __init__(
        self,
        message_bus: MessageBus,
        workspace: str = "sandbox/workspace/research",
    ) -> None:
        self.message_bus = message_bus
        self.workspace = Path(workspace)

        self.workspace.mkdir(
            parents=True,
            exist_ok=True,
        )

    def web_search(self, query: str) -> dict[str, Any]:
        """
        Simulated web search.

        This is intentionally local for the MVP.
        A real web-search provider can be connected later.
        """
        return {
            "query": query,
            "results": [
                {
                    "title": "Simulated Research Result",
                    "summary": f"Research information for: {query}",
                }
            ],
        }

    def read_document(self, filename: str) -> str:
        """Read a document from the Research workspace."""
        file_path = self.workspace / filename

        if not file_path.exists():
            raise FileNotFoundError(
                f"Document not found: {filename}"
            )

        if not file_path.is_file():
            raise ValueError(
                f"Not a file: {filename}"
            )

        return file_path.read_text(
            encoding="utf-8"
        )

    def write_research(
        self,
        filename: str,
        content: str,
    ) -> str:
        """Write research output to the Research workspace."""
        file_path = self.workspace / filename

        file_path.write_text(
            content,
            encoding="utf-8",
        )

        return str(file_path)

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