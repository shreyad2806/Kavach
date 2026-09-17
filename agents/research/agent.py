from typing import Any

from agents.common.identity import AgentIdentity
from agents.common.messages import AgentMessage
from agents.common.schemas import ToolRequest
from agents.research.tools import ResearchTools
from sandbox.runtime.message_bus import MessageBus

class ResearchAgent:
    """Gathers research information and reports results."""

    def __init__(self, message_bus: MessageBus) -> None:
        self.identity = AgentIdentity(
            agent_id="research",
            name="Research Agent",
            role="researcher",
            capabilities=frozenset(
                {
                    "web.search",
                    "document.read",
                    "research.write",
                    "agent.message",
                }
            ),
        )

        self.tools = ResearchTools(message_bus)

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
            f"[RESEARCH] Received {message.message_type} "
            f"from {message.sender}"
        )

    def search(
        self,
        query: str,
    ) -> dict[str, Any]:
        """Perform a simulated web search."""
        return self.tools.web_search(query)

    def write_research(
        self,
        filename: str,
        content: str,
    ) -> str:
        """Write research results."""
        return self.tools.write_research(
            filename,
            content,
        )

    def send_result(
        self,
        receiver: str,
        content: dict[str, Any],
    ) -> AgentMessage:
        """Send research results to another agent."""
        return self.tools.send_message(
            receiver,
            content,
        )

    def request_unauthorized_deployment(
        self,
        deployment_target: str = "production",
    ) -> ToolRequest:
        """
        Create an intentionally unauthorized deployment request.

        This represents the vulnerable behavior that KAVACH
        must later prevent.
        """
        return ToolRequest(
            agent_id=self.identity.agent_id,
            operation="production.deploy",
            target=deployment_target,
            arguments={},
        )