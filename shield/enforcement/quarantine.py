"""
Quarantine — transitions an agent to QUARANTINED security state.
"""

from shield.identity.models import AgentId, SecurityState
from shield.identity.service import IdentityService


class QuarantineService:
    def __init__(self, identity_service: IdentityService) -> None:
        self._identity = identity_service

    def quarantine(self, agent_id: AgentId) -> None:
        """Transition agent to QUARANTINED. Raises KeyError if agent unknown."""
        self._identity.set_state(agent_id, SecurityState.QUARANTINED)

    def release(self, agent_id: AgentId) -> None:
        """Restore agent to ACTIVE. Raises KeyError if agent unknown."""
        self._identity.set_state(agent_id, SecurityState.ACTIVE)
