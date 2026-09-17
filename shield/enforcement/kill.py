"""
Kill Switch — permanently terminates an agent. Irreversible.
"""

from kavach.identity.models import AgentId, SecurityState
from kavach.identity.service import IdentityService


class KillSwitch:
    def __init__(self, identity_service: IdentityService) -> None:
        self._identity = identity_service

    def terminate(self, agent_id: AgentId) -> None:
        """Permanently set agent state to TERMINATED. Raises KeyError if unknown."""
        self._identity.set_state(agent_id, SecurityState.TERMINATED)
