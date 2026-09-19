"""Authoritative in-process service container for the local P1 runtime.

Shield remains the sole authorization authority.  This module only owns the
long-lived service instances that the P1 runtime supplies to that authority.
Keeping them together ensures that a state change such as quarantine is seen
by every subsequent guarded P1 action in this process.
"""

from dataclasses import dataclass, field

from shield.capabilities.service import CapabilityService
from shield.identity.service import IdentityService
from shield.incidents.service import IncidentService
from shield.policy.cedar.engine import CedarAdapter


@dataclass
class ShieldRuntime:
    """The authoritative Shield dependencies for one local Python process."""

    identity_service: IdentityService = field(default_factory=IdentityService)
    capability_service: CapabilityService = field(default_factory=CapabilityService)
    cedar_adapter: CedarAdapter = field(default_factory=CedarAdapter)
    incident_service: IncidentService = field(default_factory=IncidentService)


_runtime = ShieldRuntime()


def get_shield_runtime() -> ShieldRuntime:
    """Return the process-wide Shield runtime used by default P1 components."""
    return _runtime


def reset_shield_runtime() -> ShieldRuntime:
    """Replace the process-wide runtime; intended for controlled test setup."""
    global _runtime
    _runtime = ShieldRuntime()
    return _runtime
