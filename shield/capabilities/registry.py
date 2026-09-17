"""
Capability Registry — maps action names to the required capability name.
Used by the policy engine to verify action-capability alignment.
"""

from kavach.capabilities.models import CapabilityName
from kavach.gateway.models import ActionName

# Each action requires exactly one capability
ACTION_CAPABILITY_MAP: dict[ActionName, CapabilityName] = {
    ActionName.RESEARCH_SEARCH: CapabilityName.RESEARCH_SEARCH,
    ActionName.RESEARCH_READ: CapabilityName.RESEARCH_READ,
    ActionName.CODING_READ: CapabilityName.CODING_READ,
    ActionName.CODING_WRITE: CapabilityName.CODING_WRITE,
    ActionName.CODING_TEST: CapabilityName.CODING_TEST,
    ActionName.DEPLOYMENT_PREVIEW: CapabilityName.DEPLOYMENT_PREVIEW,
    ActionName.DEPLOYMENT_DEPLOY: CapabilityName.DEPLOYMENT_PRODUCTION,
    ActionName.VERIFICATION_TEST: CapabilityName.VERIFICATION_TEST,
    ActionName.ORCHESTRATOR_DELEGATE: CapabilityName.ORCHESTRATOR_DELEGATE,
    ActionName.ORCHESTRATOR_COORDINATE: CapabilityName.ORCHESTRATOR_COORDINATE,
}


def required_capability(action: ActionName) -> CapabilityName | None:
    """Return the capability required to perform the given action, or None if unmapped."""
    return ACTION_CAPABILITY_MAP.get(action)
