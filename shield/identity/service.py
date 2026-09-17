"""
Kavach In-Memory Identity Registry and Identity Service.
Answers strictly: "Is this a known Kavach agent, and what is its current security state?"
Contains NO authorization logic, capability checking, or policy decisions.
"""

from copy import deepcopy

from kavach.identity.models import AgentId, AgentIdentity, AgentRole, SecurityState


# Canonical initial specification of all five autonomous agents
CANONICAL_AGENTS: dict[AgentId, dict[str, str]] = {
    AgentId.ORCHESTRATOR_01: {
        "role": AgentRole.ORCHESTRATOR,
        "status": SecurityState.ACTIVE,
    },
    AgentId.RESEARCH_01: {
        "role": AgentRole.RESEARCH,
        "status": SecurityState.ACTIVE,
    },
    AgentId.CODING_01: {
        "role": AgentRole.CODING,
        "status": SecurityState.ACTIVE,
    },
    AgentId.DEPLOYMENT_01: {
        "role": AgentRole.DEPLOYMENT,
        "status": SecurityState.ACTIVE,
    },
    AgentId.VERIFICATION_01: {
        "role": AgentRole.VERIFICATION,
        "status": SecurityState.ACTIVE,
    },
}


class IdentityService:
    """
    In-memory identity service managing the canonical agent registry.
    Provides agent lookup and testable security state mutations.
    """

    def __init__(self) -> None:
        self._registry: dict[AgentId, AgentIdentity] = {}
        self.reset()

    def reset(self) -> None:
        """Resets the in-memory registry to its canonical initial state (all agents ACTIVE)."""
        self._registry = {
            agent_id: AgentIdentity(
                agent_id=agent_id,
                role=spec["role"],
                state=spec["status"],
            )
            for agent_id, spec in CANONICAL_AGENTS.items()
        }

    def _resolve_agent_id(self, agent_id: AgentId | str) -> AgentId | None:
        if isinstance(agent_id, AgentId):
            return agent_id
        try:
            return AgentId(agent_id)
        except ValueError:
            return None

    def _resolve_security_state(self, state: SecurityState | str) -> SecurityState:
        if isinstance(state, SecurityState):
            return state
        try:
            return SecurityState(state)
        except ValueError:
            raise ValueError(
                f"Invalid security state: '{state}'. Must be one of {[s.value for s in SecurityState]}"
            )

    def get_agent(self, agent_id: AgentId | str) -> AgentIdentity | None:
        """
        Retrieves the AgentIdentity for a recognized agent.
        Returns None if the agent_id is unknown or unregistered.
        Never dynamically creates an agent.
        """
        resolved_id = self._resolve_agent_id(agent_id)
        if resolved_id is None or resolved_id not in self._registry:
            return None
        # Return a copy to prevent external mutation bypassing set_state
        return self._registry[resolved_id].model_copy()

    def set_state(self, agent_id: AgentId | str, state: SecurityState | str) -> None:
        """
        Updates the runtime security state of an existing agent.
        Raises KeyError if the agent is unknown (safe failure; does not insert).
        Raises ValueError if the state is not a valid SecurityState.
        """
        resolved_state = self._resolve_security_state(state)
        resolved_id = self._resolve_agent_id(agent_id)
        if resolved_id is None or resolved_id not in self._registry:
            raise KeyError(f"Agent '{agent_id}' not found in identity registry.")

        self._registry[resolved_id].state = resolved_state

    def list_agents(self) -> list[AgentIdentity]:
        """Returns a list of all registered agent identities."""
        return [identity.model_copy() for identity in self._registry.values()]
