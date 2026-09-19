from typing import Any

from agents.common.identity import AgentIdentity
from agents.common.messages import AgentMessage
from agents.common.schemas import ToolRequest
from agents.research.tools import ResearchTools
from sandbox.runtime.message_bus import MessageBus
from kavach_logger import get_logger

_log = get_logger("kavach.agents.research")


class ResearchAgent:
    """Gathers research information and reports results."""

    def __init__(self, message_bus: MessageBus) -> None:
        self.identity = AgentIdentity(
            agent_id="research",
            name="Research Agent",
            role="researcher",
            # READ-ONLY research agent. It does not declare a write capability,
            # matching the Shield capability registry (research.search,
            # research.read only) — a research.write attempt is denied by
            # Kavach with CAPABILITY_MISMATCH before any side effect.
            capabilities=frozenset(
                {
                    "web.search",
                    "document.read",
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

    def receive_message(self, message: AgentMessage) -> None:
        """Receive a task from another agent."""
        self.received_tasks.append(message)

    def search(self, query: str) -> dict[str, Any]:
        """Perform a simulated web search."""
        _log.info("web search started", extra={"agent": "research", "query": query})
        result = self.tools.web_search(query)
        result_count = len(result.get("results", [])) if isinstance(result, dict) else 0
        _log.info(
            "web search complete",
            extra={"agent": "research", "query": query, "result_count": result_count},
        )
        return result

    def read_document(self, filename: str) -> dict[str, Any]:
        """Read a source document from the research workspace (``research.read``).

        A document that has not been ingested reports NOT_FOUND rather than
        failing the workflow: the read is still a real, authorized
        ``research.read`` decision, it simply has no content to return.  This
        mirrors VerificationAgent.inspect_output.
        """
        _log.info(
            "reading research document",
            extra={"agent": "research", "file": filename},
        )
        try:
            content = self.tools.read_document(filename)
        except FileNotFoundError:
            return {"status": "NOT_FOUND", "file": filename}
        except ValueError:
            return {"status": "INVALID", "file": filename}
        return {
            "status": "FOUND",
            "file": filename,
            "size": len(content),
            "content": content,
        }

    def write_research(self, filename: str, content: str) -> str:
        """Write research results to workspace."""
        _log.info(
            "writing research output",
            extra={"agent": "research", "file": filename, "content_length": len(content)},
        )
        result = self.tools.write_research(filename, content)
        _log.info("research output written", extra={"agent": "research", "file": filename})
        return result

    def send_result(self, receiver: str, content: dict[str, Any]) -> AgentMessage:
        """Send research results to another agent."""
        _log.info(
            "sending result",
            extra={"agent": "research", "target": receiver, "status": content.get("status")},
        )
        return self.tools.send_message(receiver, content)

    def request_unauthorized_deployment(
        self,
        deployment_target: str = "production",
    ) -> ToolRequest:
        """
        Create an intentionally unauthorized deployment request.

        This represents the vulnerable behavior that KAVACH must prevent.
        """
        _log.warning(
            "unauthorized deployment request created",
            extra={"agent": "research", "target": deployment_target},
        )
        return ToolRequest(
            agent_id=self.identity.agent_id,
            operation="production.deploy",
            target=deployment_target,
            arguments={},
        )
