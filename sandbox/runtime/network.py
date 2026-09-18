from agents.common.schemas import SecurityEvent
from sandbox.runtime.event_logger import EventLogger

class NetworkAccessDeniedError(Exception):
    pass

class NetworkManager:
    """
    Manages explicit network capabilities for agents.
    For the MVP, only the research agent is allowed simulated web search.
    """

    ALLOWED_AGENTS = {"research"}

    def __init__(self, event_logger: EventLogger | None = None) -> None:
        self.event_logger = event_logger or EventLogger()

    def check_access(self, agent_id: str, operation: str) -> None:
        """
        Verify if the agent is allowed to perform network operations.
        """
        if agent_id not in self.ALLOWED_AGENTS:
            event = SecurityEvent(
                agent_id=agent_id,
                event_type="NETWORK_ACCESS_DENIED",
                operation=operation,
                target="internet",
                success=False,
            )
            self.event_logger.log(event)
            raise NetworkAccessDeniedError(f"Agent '{agent_id}' is not allowed to access the network.")
