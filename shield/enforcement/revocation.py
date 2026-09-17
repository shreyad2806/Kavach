"""
Revocation — runtime capability revocation for compromised agents.
"""

from shield.capabilities.service import CapabilityService
from shield.identity.models import AgentId


class RevocationService:
    def __init__(self, capability_service: CapabilityService) -> None:
        self._capabilities = capability_service

    def revoke_all(self, agent_id: AgentId) -> int:
        """
        Revoke all capabilities for an agent.
        Returns the number of capabilities revoked.
        """
        caps = self._capabilities.get_capabilities(agent_id.value)
        count = len(caps)
        # Clear the agent's capability list in the registry
        self._capabilities._registry[agent_id.value] = []
        return count

    def revoke(self, agent_id: AgentId, capability_name: str) -> bool:
        """
        Revoke a specific capability. Returns True if it was present and removed.
        """
        caps = self._capabilities._registry.get(agent_id.value, [])
        original_len = len(caps)
        self._capabilities._registry[agent_id.value] = [
            c for c in caps if c.name.value != capability_name
        ]
        return len(self._capabilities._registry[agent_id.value]) < original_len
