from typing import Any

from agents.common.identity import AgentIdentity
from agents.common.messages import AgentMessage
from agents.deployment.tools import DeploymentTools
from sandbox.runtime.message_bus import MessageBus
from kavach_logger import get_logger

_log = get_logger("kavach.agents.deployment")


class DeploymentAgent:
    """Simulates application deployments."""

    def __init__(self, message_bus: MessageBus) -> None:
        self.identity = AgentIdentity(
            agent_id="deployment",
            name="Deployment Agent",
            role="deployer",
            capabilities=frozenset(
                {
                    "deployment.simulate",
                    "infrastructure.inspect",
                    "deployment.status",
                    "agent.message",
                }
            ),
        )

        self.tools = DeploymentTools(message_bus)
        self.received_tasks: list[AgentMessage] = []

        message_bus.subscribe(
            self.identity.agent_id,
            self.receive_message,
        )

    def receive_message(self, message: AgentMessage) -> None:
        """Receive a task from another agent."""
        self.received_tasks.append(message)

    def simulate_deployment(self, target: str) -> dict[str, Any]:
        """Simulate a deployment."""
        _log.info("simulating deployment", extra={"agent": "deployment", "target": target})
        result = self.tools.simulate_deployment(target)
        _log.info(
            "deployment simulation complete",
            extra={
                "agent": "deployment",
                "target": target,
                "status": result.get("status"),
                "simulated": result.get("simulated"),
            },
        )
        return result

    def inspect_infrastructure(self, target: str) -> dict[str, Any]:
        """Inspect simulated infrastructure."""
        _log.info(
            "inspecting infrastructure",
            extra={"agent": "deployment", "target": target},
        )
        result = self.tools.inspect_infrastructure(target)
        _log.info(
            "infrastructure inspection complete",
            extra={
                "agent": "deployment",
                "target": target,
                "environment": result.get("environment"),
                "status": result.get("status"),
            },
        )
        return result

    def deployment_status(self, target: str) -> dict[str, Any]:
        """Check simulated deployment status."""
        _log.info(
            "checking deployment status",
            extra={"agent": "deployment", "target": target},
        )
        result = self.tools.deployment_status(target)
        _log.info(
            "deployment status retrieved",
            extra={"agent": "deployment", "target": target, "status": result.get("status")},
        )
        return result

    def send_result(self, receiver: str, content: dict[str, Any]) -> AgentMessage:
        """Send deployment results to another agent."""
        _log.info(
            "sending result",
            extra={"agent": "deployment", "target": receiver, "status": content.get("status")},
        )
        return self.tools.send_message(receiver, content)
