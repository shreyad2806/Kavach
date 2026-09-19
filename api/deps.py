"""Shared, process-wide dependencies for the unified local backend.

There is exactly ONE authoritative Shield state per Python process, owned by
``shield.runtime.services.get_shield_runtime()``.  Every HTTP route resolves
its services from that runtime so the control plane and the real P1 agents
(the WorkflowSupervisor's AgentTools -> KavachGuard path) always observe the
same identity/quarantine/incident state.

Nothing here instantiates a fresh IdentityService, CapabilityService,
CedarAdapter or IncidentService — those live only inside the shared runtime.
The WorkflowSupervisor is a single process-local instance so that a workflow
created by one request is visible to later start/stop/get requests.
"""

from agents.supervisor import WorkflowSupervisor
from shield.enforcement.quarantine import QuarantineService
from shield.identity.service import IdentityService
from shield.incidents.service import IncidentService
from shield.runtime.services import get_shield_runtime

# One supervisor for the whole process (workflows are process-local/in-memory).
_supervisor = WorkflowSupervisor()


def get_supervisor() -> WorkflowSupervisor:
    """Return the process-wide WorkflowSupervisor."""
    return _supervisor


def reset_supervisor() -> WorkflowSupervisor:
    """Replace the process-wide supervisor; intended for controlled test setup."""
    global _supervisor
    _supervisor = WorkflowSupervisor()
    return _supervisor


def get_identity_service() -> IdentityService:
    """Authoritative identity registry, resolved live from the shared runtime."""
    return get_shield_runtime().identity_service


def get_incident_service() -> IncidentService:
    """Authoritative incident store, resolved live from the shared runtime."""
    return get_shield_runtime().incident_service


def get_quarantine_service() -> QuarantineService:
    """Quarantine enforcement bound to the shared runtime's identity service.

    QuarantineService is a thin, stateless enforcement wrapper: it resolves
    ``get_shield_runtime().identity_service`` at construction time, so a fresh
    instance always mutates the SAME registry the real P1 KavachGuard reads.
    """
    return QuarantineService()
