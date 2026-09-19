"""
ShieldRuntime — process-level singleton holding all shared security services.

All components that need to share security state (KavachGuard, API routes,
QuarantineService, WorkflowSupervisor) must use get_runtime() to obtain
the same instance. Creating fresh IdentityService/CapabilityService/etc.
per-request breaks the shared-state invariant.

Usage:
    from shield.runtime.services import get_runtime
    runtime = get_runtime()
    runtime.identity_service.set_state(agent_id, SecurityState.QUARANTINED)
"""

import os

from shield.authorization.pipeline import authorize
from shield.capabilities.service import CapabilityService
from shield.enforcement.quarantine import QuarantineService
from shield.identity.dynamo_service import DynamoIdentityService
from shield.identity.models import AgentId, SecurityState
from shield.identity.service import IdentityService
from shield.incidents.dynamo_service import DynamoIncidentService
from shield.incidents.service import IncidentService
from shield.policy.cedar.engine import CedarAdapter


class ShieldRuntime:
    """
    Holds all shared security service instances for the process lifetime.
    Uses DynamoDB-backed services when env vars are set, falls back to
    in-memory for local dev and tests.
    """

    def __init__(self) -> None:
        # Use DynamoDB-backed services when table env vars are present
        self.identity_service: IdentityService = (
            DynamoIdentityService()
            if os.environ.get("SHIELD_AGENTS_TABLE")
            else IdentityService()
        )
        self.incident_service: IncidentService = (
            DynamoIncidentService()
            if os.environ.get("SHIELD_INCIDENTS_TABLE")
            else IncidentService()
        )
        self.capability_service = CapabilityService()
        self.cedar_adapter = CedarAdapter()
        self.quarantine_service = QuarantineService(self.identity_service)

    def authorize(self, request):
        """Run the full authorization pipeline using shared services."""
        return authorize(
            request,
            identity_service=self.identity_service,
            capability_service=self.capability_service,
            cedar_adapter=self.cedar_adapter,
            incident_service=self.incident_service,
        )


# Process-level singleton — created once at import time
_runtime: ShieldRuntime | None = None


def get_runtime() -> ShieldRuntime:
    """Return the process-level ShieldRuntime singleton."""
    global _runtime
    if _runtime is None:
        _runtime = ShieldRuntime()
    return _runtime


def reset_runtime() -> ShieldRuntime:
    """
    Replace the singleton with a fresh instance.
    FOR TESTING ONLY — resets all in-memory security state.
    """
    global _runtime
    _runtime = ShieldRuntime()
    return _runtime


# Aliases for backward compatibility with existing tests and modules
get_shield_runtime = get_runtime
reset_shield_runtime = reset_runtime
