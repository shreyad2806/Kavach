"""
KavachGuard — mandatory enforcement boundary for protected P1 operations.

Every protected P1 capability/action MUST pass through this boundary before
execution. The guard constructs a Shield ActionRequest, calls authorize(),
and either allows execution or raises KavachDeniedError.

Fail-closed: if authorize() raises, returns an invalid result, or is
unavailable, the protected action MUST NOT execute.

This is the ONLY authorization boundary for P1 tool execution.
Normal MessageBus communication does NOT enter this boundary.
"""

import logging
import uuid
from datetime import datetime, timezone
from functools import wraps
from typing import Any, Callable

from shield.authorization.pipeline import authorize
from shield.capabilities.models import CapabilityName
from shield.gateway.models import (
    ActionName,
    ActionRequest,
    AuthorizationDecision,
    AuthorizationResult,
    CheckStatus,
    ResourceName,
)
from shield.identity.models import AgentId
from shield.provenance.models import Provenance
from shield.runtime.services import get_runtime as get_shield_runtime
from kavach_logger import get_logger

logger = get_logger("kavach.sandbox.kavach_guard")


# ============================================================================
# Canonical P1 → Shield agent ID mapping
# ============================================================================

P1_TO_SHIELD_AGENT_ID: dict[str, AgentId] = {
    "orchestrator": AgentId.ORCHESTRATOR_01,
    "research": AgentId.RESEARCH_01,
    "coding": AgentId.CODING_01,
    "deployment": AgentId.DEPLOYMENT_01,
    "verification": AgentId.VERIFICATION_01,
}

# Reverse mapping for quick lookup
_SHIELD_TO_P1_AGENT_ID: dict[AgentId, str] = {
    v: k for k, v in P1_TO_SHIELD_AGENT_ID.items()
}


def configure_all_guards(runtime) -> None:
    """
    Wire all module-level KavachGuard instances in agent tool modules to the
    shared ShieldRuntime. Must be called once at application startup before
    any agent tool is invoked.

    This ensures that quarantine/restore via the API immediately affects
    all protected tool calls — they all share the same IdentityService.
    """
    import agents.coding.tools as _ct
    import agents.deployment.tools as _dt
    import agents.orchestrator.tools as _ot
    import agents.research.tools as _rt
    import agents.verification.tools as _vt

    for module in (_ct, _dt, _ot, _rt, _vt):
        if hasattr(module, "_guard"):
            module._guard.configure_from_runtime(runtime)


class KavachDeniedError(Exception):
    """Raised when Kavach denies a protected P1 operation."""
    def __init__(self, result: AuthorizationResult | None = None, reason: str = "Authorization denied"):
        self.result = result
        self.reason = reason
        super().__init__(reason)


class KavachGuardError(Exception):
    """Raised when the Kavach enforcement boundary itself fails (fail-closed)."""
    pass


# ============================================================================
# KavachGuard
# ============================================================================

class KavachGuard:
    """
    Mandatory enforcement boundary for protected P1 operations.

    Usage:
        guard = KavachGuard()

        @guard.protect("research", ActionName.RESEARCH_SEARCH, ResourceName.RESEARCH_DATA, CapabilityName.RESEARCH_SEARCH)
        def web_search(self, query):
            ...

    The decorated method will only execute if Kavach authorize() returns ALLOW.
    If Kavach is unavailable or raises, the method is blocked (fail-closed).
    """

    def __init__(
        self,
        identity_service=None,
        capability_service=None,
        cedar_adapter=None,
        incident_service=None,
    ) -> None:
        # Keep explicitly injected dependencies for isolated tests.  Missing
        # dependencies are resolved from the runtime at authorization time so
        # every default guard, including module-level tool guards, observes
        # the same authoritative runtime state.
        self._identity_service = identity_service
        self._capability_service = capability_service
        self._cedar_adapter = cedar_adapter
        self._incident_service = incident_service
        self._configured_runtime = None
        # Track authorization calls for testing/telemetry
        self._authorization_calls: list[AuthorizationResult] = []

    def configure_from_runtime(self, runtime) -> None:
        """
        Wire this guard to a ShieldRuntime's shared services.
        Store the runtime reference rather than individual services so that
        reset_shield_runtime() in tests is immediately visible.
        """
        self._configured_runtime = runtime

    @property
    def authorization_calls(self) -> list[AuthorizationResult]:
        """Return a copy of all authorization results for inspection."""
        return list(self._authorization_calls)

    def _resolve_agent_id(self, p1_agent_id: str) -> AgentId:
        """Map a P1 agent ID to a canonical Shield AgentId."""
        shield_id = P1_TO_SHIELD_AGENT_ID.get(p1_agent_id)
        if shield_id is None:
            raise KavachDeniedError(
                reason=f"Unknown P1 agent: '{p1_agent_id}' has no Shield mapping"
            )
        return shield_id

    def _build_request(
        self,
        p1_source_agent: str,
        action: ActionName,
        resource: ResourceName,
        capability: CapabilityName,
        target_agent: str | None = None,
        task_id: str | None = None,
        parent_event_id: str | None = None,
    ) -> ActionRequest:
        """Construct a Shield ActionRequest from P1 context."""
        source_shield = self._resolve_agent_id(p1_source_agent)
        if target_agent:
            target_shield = self._resolve_agent_id(target_agent)
        else:
            target_shield = source_shield

        now = datetime.now(timezone.utc)
        req_id = f"p1-{uuid.uuid4().hex[:12]}"
        t_id = task_id or f"task-{uuid.uuid4().hex[:8]}"

        # Provenance: assume self-originated single-element chain
        # unless we have actual delegation context
        provenance = Provenance(
            task_origin=source_shield,
            delegation_chain=[source_shield],
        )

        return ActionRequest(
            request_id=req_id,
            timestamp=now,
            source_agent=source_shield,
            target_agent=target_shield,
            task_id=t_id,
            parent_event_id=parent_event_id,
            action=action,
            resource=resource,
            claimed_authority=source_shield,
            capability=capability,
            provenance=provenance,
        )

    def authorize(
        self,
        p1_source_agent: str,
        action: ActionName,
        resource: ResourceName,
        capability: CapabilityName,
        target_agent: str | None = None,
        task_id: str | None = None,
    ) -> AuthorizationResult:
        """
        Run the full Kavach authorization pipeline.

        Returns the AuthorizationResult. Raises KavachGuardError on
        infrastructure failure (fail-closed).
        """
        try:
            request = self._build_request(
                p1_source_agent=p1_source_agent,
                action=action,
                resource=resource,
                capability=capability,
                target_agent=target_agent,
                task_id=task_id,
            )

            runtime = get_shield_runtime()
            # Explicit test injections take precedence; otherwise always
            # resolve from the live singleton so reset_shield_runtime() is
            # immediately visible (no stale cached service references).
            kwargs: dict[str, Any] = {
                "identity_service": self._identity_service if self._identity_service is not None else runtime.identity_service,
                "capability_service": self._capability_service if self._capability_service is not None else runtime.capability_service,
                "cedar_adapter": self._cedar_adapter if self._cedar_adapter is not None else runtime.cedar_adapter,
                "incident_service": self._incident_service if self._incident_service is not None else runtime.incident_service,
            }

            result = authorize(request, **kwargs)
            self._authorization_calls.append(result)
            return result

        except KavachDeniedError:
            raise
        except Exception as exc:
            logger.error(
                "authorization boundary failure",
                extra={
                    "agent": p1_source_agent,
                    "action": action.value,
                    "error": str(exc),
                },
                exc_info=True,
            )
            raise KavachGuardError(
                f"Kavach enforcement boundary failed: {exc}"
            ) from exc

    def protect(
        self,
        p1_source_agent: str,
        action: ActionName,
        resource: ResourceName,
        capability: CapabilityName,
        target_agent: str | None = None,
    ) -> Callable:
        """
        Decorator that enforces Kavach authorization before method execution.

        The decorated method only executes if authorize() returns ALLOW.
        If Kavach is unavailable or denies, KavachDeniedError is raised.
        """
        def decorator(fn: Callable) -> Callable:
            @wraps(fn)
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                # Resolve target_agent: use explicit or fall back to source
                tgt = target_agent or p1_source_agent

                result = self.authorize(
                    p1_source_agent=p1_source_agent,
                    action=action,
                    resource=resource,
                    capability=capability,
                    target_agent=tgt,
                )

                if result.decision != AuthorizationDecision.ALLOW:
                    raise KavachDeniedError(
                        result=result,
                        reason=f"Kavach denied {action.value} for {p1_source_agent}: "
                               f"{[rc.value for rc in result.reason_codes]}",
                    )

                # ALLOW: execute the underlying operation
                return fn(*args, **kwargs)

            # Attach guard metadata for introspection
            wrapper._kavach_guard = self
            wrapper._kavach_action = action
            wrapper._kavach_resource = resource
            wrapper._kavach_capability = capability
            wrapper._kavach_agent = p1_source_agent

            return wrapper
        return decorator
