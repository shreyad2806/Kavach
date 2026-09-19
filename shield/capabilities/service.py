from typing import List

from shield.capabilities.models import Capability, CapabilityName


class CapabilityService:
    """
    In-memory capability registry service.
    
    Answers: "WHAT capability is assigned to this agent?"
    
    Does NOT answer: "Can this agent perform this requested action?"
    That is a later authorization/policy responsibility.
    """
    
    def __init__(self) -> None:
        # Canonical Phase 5 capability registry
        self._registry: dict[str, List[Capability]] = {
            "orchestrator-01": [
                Capability(
                    name=CapabilityName.ORCHESTRATOR_DELEGATE,
                    description="Authority to delegate tasks to other agents"
                ),
                Capability(
                    name=CapabilityName.ORCHESTRATOR_COORDINATE,
                    description="Authority to coordinate multi-agent workflows"
                ),
            ],
            # research-01 holds READ-ONLY research authority by design.
            # It deliberately does NOT hold research.write: the research agent
            # must not be able to persist artifacts into the workspace.  A
            # research.write request therefore fails the capability gate with
            # CAPABILITY_MISMATCH before Cedar is ever consulted.
            "research-01": [
                Capability(
                    name=CapabilityName.RESEARCH_SEARCH,
                    description="Authority to search information sources"
                ),
                Capability(
                    name=CapabilityName.RESEARCH_READ,
                    description="Authority to read research documents and data"
                ),
            ],
            "coding-01": [
                Capability(
                    name=CapabilityName.CODING_READ,
                    description="Authority to read code repositories"
                ),
                Capability(
                    name=CapabilityName.CODING_WRITE,
                    description="Authority to write and modify code"
                ),
                Capability(
                    name=CapabilityName.CODING_TEST,
                    description="Authority to execute tests and test frameworks"
                ),
            ],
            "deployment-01": [
                Capability(
                    name=CapabilityName.DEPLOYMENT_PREVIEW,
                    description="Authority to deploy to preview environments"
                ),
                Capability(
                    name=CapabilityName.DEPLOYMENT_PRODUCTION,
                    description="Authority to deploy to production environments"
                ),
            ],
            "verification-01": [
                Capability(
                    name=CapabilityName.VERIFICATION_TEST,
                    description="Authority to run verification and validation tests"
                ),
            ],
        }
    
    def get_capabilities(self, agent_id: str) -> List[Capability]:
        """
        Get capabilities assigned to an agent.
        
        Args:
            agent_id: The agent identifier
            
        Returns:
            List of capabilities assigned to the agent.
            Returns empty list for unknown agents.
            Does NOT dynamically create capabilities for unknown agents.
        """
        # Return a copy to prevent external mutation of internal registry
        return list(self._registry.get(agent_id, []))
    
    def has_capability(self, agent_id: str, capability: str) -> bool:
        """
        Check if an agent possesses a specific capability.
        
        This method ONLY checks whether the capability is assigned.
        It does NOT check:
        - requested action
        - resource
        - claimed authority
        - provenance
        - agent state
        - Cedar
        - risk
        - policy
        
        Args:
            agent_id: The agent identifier
            capability: The capability name to check
            
        Returns:
            True if the agent has the capability, False otherwise.
            Returns False for unknown agents or unknown capabilities.
        """
        capabilities = self._registry.get(agent_id, [])
        return any(cap.name.value == capability for cap in capabilities)
