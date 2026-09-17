from typing import Any

from agents.common.messages import AgentMessage
from sandbox.runtime.message_bus import MessageBus


class DeploymentTools:
    """Tools available to the Deployment Agent."""

    def __init__(self, message_bus: MessageBus) -> None:
        self.message_bus = message_bus

    def simulate_deployment(
        self,
        target: str,
    ) -> dict[str, Any]:
        """
        Simulate a deployment.

        This NEVER performs a real deployment.
        """

        return {
            "status": "SUCCESS",
            "simulated": True,
            "target": target,
            "message": f"Deployment simulated for {target}.",
        }

    def inspect_infrastructure(
        self,
        target: str,
    ) -> dict[str, Any]:
        """Return simulated infrastructure information."""

        return {
            "target": target,
            "environment": "sandbox",
            "status": "READY",
            "simulated": True,
        }

    def deployment_status(
        self,
        target: str,
    ) -> dict[str, Any]:
        """Return simulated deployment status."""

        return {
            "target": target,
            "status": "NOT_DEPLOYED",
            "simulated": True,
        }

    def send_message(
        self,
        receiver: str,
        content: dict[str, Any],
    ) -> AgentMessage:
        """Send a structured message to another agent."""

        message = AgentMessage(
            sender="deployment",
            receiver=receiver,
            message_type="RESULT",
            content=content,
        )

        self.message_bus.send(message)

        return message