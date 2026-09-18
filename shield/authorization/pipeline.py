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

import logging
from typing import Any, Callable

from shield.capabilities.service import CapabilityService
from shield.detection import detect
from shield.detection.signals import calculate_risk
from shield.gateway.models import (
    ActionRequest,
    AuthorizationChecks,
    AuthorizationDecision,
    AuthorizationResult,
    CheckStatus,
    ReasonCode,
)
from shield.identity.models import AgentIdentity, SecurityState
from shield.identity.service import IdentityService
from shield.policy.cedar import CedarAdapter
from shield.provenance.validator import (
    ProvenanceValidationResult,
    validate_provenance,
)
from shield.incidents import INCIDENT_THRESHOLD, IncidentService
from shield.telemetry import create_authorization_decision_event, write_event

logger = logging.getLogger(__name__)


def authorize(
    request: ActionRequest,
    identity_service: IdentityService | None = None,
    capability_service: CapabilityService | None = None,
    cedar_adapter: CedarAdapter | None = None,
    incident_service: IncidentService | None = None,
    audit_writer: Callable[..., Any] | None = None,
) -> AuthorizationResult:
    """
    Execute the full Kavach authorization pipeline against an ActionRequest.

    Each check is evaluated in order. Any critical failure short-circuits
    to DENY. The final result populates the existing AuthorizationResult
    contract with full check traceability.
    Every completed decision emits exactly one AUTHORIZATION_DECISION event
    to the audit sink.
    If risk_score >= INCIDENT_THRESHOLD, an incident is created.

    Parameters:
        request: The ActionRequest to evaluate.
        identity_service: Service for agent identity lookup. Uses default if None.
        capability_service: Service for capability verification. Uses default if None.
        cedar_adapter: Adapter for Cedar policy evaluation. Uses default if None.
        incident_service: Service for incident creation. Uses default if None.
        audit_writer: Optional custom audit writer callable. Uses write_event if None.

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
    if incident_service is None:
        incident_service = IncidentService()

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
        checks.identity = CheckStatus.FAIL
        decision = AuthorizationDecision.DENY
        reason_codes.append(ReasonCode.IDENTITY_FAILURE)
        agent_state = SecurityState.TERMINATED
        risk_score = calculate_risk(reason_codes)
        result = _build_result(request, decision, reason_codes, checks, agent_state, risk_score)
        _emit_telemetry(request, result, audit_writer)
        return result

    checks.identity = CheckStatus.PASS
    agent_state = agent_identity.state

    # =========================================================================
    # CHECK 2: Agent State
    # =========================================================================
    if agent_identity.state in (SecurityState.QUARANTINED, SecurityState.TERMINATED):
        # Quarantined or terminated agent — critical failure
        checks.agent_state = CheckStatus.FAIL
        decision = AuthorizationDecision.DENY
        if agent_identity.state == SecurityState.QUARANTINED:
            reason_codes.append(ReasonCode.AGENT_QUARANTINED)
        else:
            reason_codes.append(ReasonCode.IDENTITY_FAILURE)
        risk_score = calculate_risk(reason_codes)
        result = _build_result(request, decision, reason_codes, checks, agent_state, risk_score)
        _emit_telemetry(request, result, audit_writer)
        return result

    checks.agent_state = CheckStatus.PASS

    # =========================================================================
    # CHECK 3: Capability
    # =========================================================================
    has_capability = capability_service.has_capability(
        request.source_agent.value,
        request.capability.value,
    )

    if not has_capability:
        # Capability mismatch — critical failure
        checks.capability = CheckStatus.FAIL
        decision = AuthorizationDecision.DENY
        reason_codes.append(ReasonCode.CAPABILITY_MISMATCH)
        risk_score = calculate_risk(reason_codes)
        result = _build_result(request, decision, reason_codes, checks, agent_state, risk_score)
        _emit_telemetry(request, result, audit_writer)
        return result

    checks.capability = CheckStatus.PASS

    # =========================================================================
    # CHECK 4: Provenance
    # =========================================================================
    provenance_result: ProvenanceValidationResult = validate_provenance(request)

    if not provenance_result.valid:
        # Invalid provenance — critical failure
        checks.provenance = CheckStatus.FAIL
        decision = AuthorizationDecision.DENY
        if provenance_result.reason_code:
            reason_codes.append(provenance_result.reason_code)
        risk_score = calculate_risk(reason_codes)
        result = _build_result(request, decision, reason_codes, checks, agent_state, risk_score)
        _emit_telemetry(request, result, audit_writer)
        return result

    checks.provenance = CheckStatus.PASS

    # =========================================================================
    # CHECK 5: Cedar
    # =========================================================================
    cedar_decision = cedar_adapter.evaluate(request)

    if cedar_decision == AuthorizationDecision.DENY:
        # Cedar denied — critical failure, NEVER overridden
        checks.cedar = CheckStatus.DENY
        decision = AuthorizationDecision.DENY
        reason_codes.append(ReasonCode.POLICY_DENIED)
        # Cedar DENY short-circuits deterministic rules (remains NOT_EVALUATED)
        # but proceeds to detection for signal enrichment and risk scoring
    else:
        checks.cedar = CheckStatus.ALLOW

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
            if checks.cedar != CheckStatus.ALLOW:
                rules_passed = False

        # Rule: no quarantined agent reaches this point (defense-in-depth)
        if agent_state in (SecurityState.QUARANTINED, SecurityState.TERMINATED):
            rules_passed = False

        checks.deterministic_rules = CheckStatus.PASS if rules_passed else CheckStatus.BLOCK

        if not rules_passed:
            decision = AuthorizationDecision.DENY

    # =========================================================================
    # CHECK 7: Detection (Phase 11)
    # =========================================================================
    # Evaluate detection signals and enrich reason codes with detection results
    detection_result = detect(request)
    for signal in detection_result.signals:
        if signal.code not in reason_codes:
            reason_codes.append(signal.code)

    # Calculate deterministic aggregate risk score from all active reason codes
    risk_score = calculate_risk(reason_codes)

    # =========================================================================
    # FINAL DECISION
    # =========================================================================
    # Fail-closed invariant: if any check resulted in DENY, it can NEVER become ALLOW.
    # Detection only enriches security explanation and risk score.
    if decision != AuthorizationDecision.DENY:
        decision = AuthorizationDecision.ALLOW

    result = _build_result(request, decision, reason_codes, checks, agent_state, risk_score)
    _emit_telemetry(request, result, audit_writer)
    _create_incident_if_needed(request, result, incident_service)
    return result


def _emit_telemetry(
    request: ActionRequest,
    result: AuthorizationResult,
    audit_writer: Callable[..., Any] | None = None,
) -> None:
    """
    Emit exactly one AUTHORIZATION_DECISION event to the audit sink.

    Telemetry is an audit side effect, NOT an authorization gate:
    Failures in telemetry MUST NOT alter or prevent the authorization verdict.
    """
    try:
        event = create_authorization_decision_event(request, result)
        writer = audit_writer if audit_writer is not None else write_event
        writer(event)
    except Exception as exc:
        logger.warning("Failed to emit security telemetry event: %s", exc)


def _build_result(
    request: ActionRequest,
    decision: AuthorizationDecision,
    reason_codes: list[ReasonCode],
    checks: AuthorizationChecks,
    agent_state: SecurityState,
    risk_score: int | None = None,
) -> AuthorizationResult:
    """Build the final AuthorizationResult from the pipeline state."""
    return AuthorizationResult(
        request_id=request.request_id,
        decision=decision,
        reason_codes=reason_codes,
        risk_score=risk_score,
        checks=checks,
        agent_state=agent_state,
    )


def _create_incident_if_needed(
    request: ActionRequest,
    result: AuthorizationResult,
    incident_service: IncidentService,
) -> None:
    """
    Create an incident if risk_score >= INCIDENT_THRESHOLD.

    Incident creation is a consequence of the decision, not an authorization mechanism.
    Failures in incident creation MUST NOT alter or prevent the authorization verdict.
    """
    try:
        if incident_service.should_create_incident(result):
            incident_service.create(request.source_agent, result)
    except Exception as exc:
        logger.warning("Failed to create security incident: %s", exc)
