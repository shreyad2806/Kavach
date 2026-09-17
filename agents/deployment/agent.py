from typing import Any

from agents.common.identity import AgentIdentity
from agents.common.messages import AgentMessage
from agents.deployment.tools import DeploymentTools
from sandbox.runtime.message_bus import MessageBus


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

    def receive_message(
        self,
        message: AgentMessage,
    ) -> None:
        """Receive a task from another agent."""

        self.received_tasks.append(message)

        print(
            f"[DEPLOYMENT] Received {message.message_type} "
            f"from {message.sender}"
        )

    def simulate_deployment(
        self,
        target: str,
    ) -> dict[str, Any]:
        """Simulate a deployment."""

        return self.tools.simulate_deployment(
            target
        )

    def inspect_infrastructure(
        self,
        target: str,
    ) -> dict[str, Any]:
        """Inspect simulated infrastructure."""

        return self.tools.inspect_infrastructure(
            target
        )

    def deployment_status(
        self,
        target: str,
    ) -> dict[str, Any]:
        """Check simulated deployment status."""

        return self.tools.deployment_status(
            target
        )

    def send_result(
        self,
        receiver: str,
        content: dict[str, Any],
    ) -> AgentMessage:
        """Send deployment results to another agent."""

        return self.tools.send_message(
            receiver,
            content,
        )