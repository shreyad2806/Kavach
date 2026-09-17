"""
Kavach Authorization Pipeline.

Executes a deterministic sequence of security checks against an ActionRequest.
Every mandatory gate is fail-closed: ANY critical failure = DENY.

Pipeline order:
    1. Identity       — verify the source agent is known
    2. Agent State    — verify the agent is not quarantined/terminated
    3. Capability     — verify the agent possesses the claimed capability
    4. Provenance     — verify delegation chain is valid
    5. Cedar          — evaluate against Cedar authorization policies
    6. Deterministic Rules — enforce structural invariants
    7. Final Decision — synthesize result

Security Invariant:
    ANY critical failure = DENY.
    NEVER allow a later check to override a previous critical DENY.
    Cedar DENY can NEVER become ALLOW.
    There is NO LLM call anywhere in authorize().
"""

from shield.capabilities.service import CapabilityService
from shield.gateway.models import (
    ActionRequest,
    AuthorizationChecks,
    AuthorizationDecision,
    AuthorizationResult,
    ReasonCode,
)
from shield.identity.models import AgentIdentity, SecurityState
from shield.identity.service import IdentityService
from shield.policy.cedar import CedarAdapter
from shield.provenance.validator import (
    ProvenanceValidationResult,
    validate_provenance,
)


def authorize(
    request: ActionRequest,
    identity_service: IdentityService | None = None,
    capability_service: CapabilityService | None = None,
    cedar_adapter: CedarAdapter | None = None,
) -> AuthorizationResult:
    """
    Execute the full Kavach authorization pipeline against an ActionRequest.

    Each check is evaluated in order. Any critical failure short-circuits
    to DENY. The final result populates the existing AuthorizationResult
    contract with full check traceability.

    Parameters:
        request: The ActionRequest to evaluate.
        identity_service: Service for agent identity lookup. Uses default if None.
        capability_service: Service for capability verification. Uses default if None.
        cedar_adapter: Adapter for Cedar policy evaluation. Uses default if None.

    Returns:
        AuthorizationResult with decision, reason codes, check traceability,
        and agent state.
    """
    # Initialize default services if not provided
    if identity_service is None:
        identity_service = IdentityService()
    if capability_service is None:
        capability_service = CapabilityService()
    if cedar_adapter is None:
        cedar_adapter = CedarAdapter()

    # Initialize check tracking
    checks = AuthorizationChecks()
    reason_codes: list[ReasonCode] = []
    decision = AuthorizationDecision.ALLOW
    agent_state = SecurityState.ACTIVE

    # =========================================================================
    # CHECK 1: Identity
    # =========================================================================
    agent_identity = identity_service.get_agent(request.source_agent)

    if agent_identity is None:
        # Unknown agent — critical failure
        checks.identity = False
        decision = AuthorizationDecision.DENY
        reason_codes.append(ReasonCode.IDENTITY_FAILURE)
        agent_state = SecurityState.TERMINATED
        return _build_result(request, decision, reason_codes, checks, agent_state)

    checks.identity = True
    agent_state = agent_identity.state

    # =========================================================================
    # CHECK 2: Agent State
    # =========================================================================
    if agent_identity.state in (SecurityState.QUARANTINED, SecurityState.TERMINATED):
        # Quarantined or terminated agent — critical failure
        checks.identity = True  # Identity was valid
        decision = AuthorizationDecision.DENY
        if agent_identity.state == SecurityState.QUARANTINED:
            reason_codes.append(ReasonCode.AGENT_QUARANTINED)
        else:
            reason_codes.append(ReasonCode.IDENTITY_FAILURE)
        return _build_result(request, decision, reason_codes, checks, agent_state)

    # =========================================================================
    # CHECK 3: Capability
    # =========================================================================
    has_capability = capability_service.has_capability(
        request.source_agent.value,
        request.capability.value,
    )

    if not has_capability:
        # Capability mismatch — critical failure
        checks.capability = False
        decision = AuthorizationDecision.DENY
        reason_codes.append(ReasonCode.CAPABILITY_MISMATCH)
        return _build_result(request, decision, reason_codes, checks, agent_state)

    checks.capability = True

    # =========================================================================
    # CHECK 4: Provenance
    # =========================================================================
    provenance_result: ProvenanceValidationResult = validate_provenance(request)

    if not provenance_result.valid:
        # Invalid provenance — critical failure
        checks.provenance = False
        decision = AuthorizationDecision.DENY
        if provenance_result.reason_code:
            reason_codes.append(provenance_result.reason_code)
        return _build_result(request, decision, reason_codes, checks, agent_state)

    checks.provenance = True

    # =========================================================================
    # CHECK 5: Cedar
    # =========================================================================
    cedar_decision = cedar_adapter.evaluate(request)

    if cedar_decision == AuthorizationDecision.DENY:
        # Cedar denied — critical failure, NEVER overridden
        checks.cedar = False
        decision = AuthorizationDecision.DENY
        reason_codes.append(ReasonCode.POLICY_DENIED)
        return _build_result(request, decision, reason_codes, checks, agent_state)

    checks.cedar = True

    # =========================================================================
    # CHECK 6: Deterministic Security Rules
    # =========================================================================
    # Only evaluate after all previous mandatory checks pass.
    # Minimal rules for Phase 10:
    #   1. deployment.deploy requests must have been allowed by Cedar.
    #   2. No quarantined agent can reach this point.
    #   3. Never convert DENY -> ALLOW.

    rules_passed = True

    # Rule: deployment.deploy must be Cedar-allowed
    from shield.gateway.models import ActionName
    if request.action == ActionName.DEPLOYMENT_DEPLOY:
        if checks.cedar is not True:
            rules_passed = False

    # Rule: no quarantined agent reaches this point (defense-in-depth)
    if agent_state in (SecurityState.QUARANTINED, SecurityState.TERMINATED):
        rules_passed = False

    checks.deterministic_rules = rules_passed

    if not rules_passed:
        decision = AuthorizationDecision.DENY
        return _build_result(request, decision, reason_codes, checks, agent_state)

    # =========================================================================
    # FINAL DECISION
    # =========================================================================
    # All checks passed — ALLOW
    decision = AuthorizationDecision.ALLOW

    return _build_result(request, decision, reason_codes, checks, agent_state)


def _build_result(
    request: ActionRequest,
    decision: AuthorizationDecision,
    reason_codes: list[ReasonCode],
    checks: AuthorizationChecks,
    agent_state: SecurityState,
) -> AuthorizationResult:
    """Build the final AuthorizationResult from the pipeline state."""
    return AuthorizationResult(
        request_id=request.request_id,
        decision=decision,
        reason_codes=reason_codes,
        checks=checks,
        agent_state=agent_state,
    )
