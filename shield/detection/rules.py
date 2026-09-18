"""
Detection Rules — deterministic security rules and signal evaluations for Kavach Phase 11.

Evaluates observable request-level properties to identify capability mismatches,
authority mismatches, provenance anomalies, privilege escalations, and suspicious behavior.
"""

from shield.capabilities.models import CapabilityName
from shield.capabilities.registry import required_capability
from shield.gateway.models import ActionName, ActionRequest, ReasonCode
from shield.identity.models import AgentId
from shield.provenance.validator import validate_provenance


def check_capability_mismatch(request: ActionRequest) -> bool:
    """
    Fire when the request's declared capability does not match the capability
    required by the requested action according to Kavach's deterministic mapping.
    """
    req_cap = required_capability(request.action)
    if req_cap is None:
        return True
    return request.capability != req_cap


def check_authority_mismatch(request: ActionRequest) -> bool:
    """
    Fire when claimed_authority conflicts with the validated delegation chain
    or source identity according to deterministic provenance semantics:
      - Self-originated single-element chain: claimed_authority must equal source_agent.
      - Delegated chain: claimed_authority must equal the direct delegator (chain[-2]).
      - Chain must terminate at source_agent.
    """
    chain = request.provenance.delegation_chain
    if not chain:
        return True

    # Chain must terminate at source agent
    if chain[-1] != request.source_agent:
        return True

    if len(chain) == 1:
        return request.claimed_authority != request.source_agent
    return request.claimed_authority != chain[-2]


def check_provenance_anomaly(request: ActionRequest) -> bool:
    """
    Fire when provenance violates structural delegation chain integrity rules.
    Reuses validate_provenance(request) from shield.provenance.validator.
    """
    result = validate_provenance(request)
    return result.reason_code == ReasonCode.PROVENANCE_ANOMALY


def check_privilege_escalation(request: ActionRequest) -> bool:
    """
    Fire when the requested action represents a privilege increase relative to the
    agent's assigned role and capabilities.

    Explicit deterministic rule using frozen agent/capability/action definitions:
      1. Deployment operations (deployment.deploy, deployment.production, deployment.preview)
         require deployment authority. Attempted by any non-deployment agent
         (e.g., research-01, coding-01, verification-01, orchestrator-01) triggers
         PRIVILEGE_ESCALATION.
      2. Orchestration operations (orchestrator.delegate, orchestrator.coordinate)
         require orchestrator authority. Attempted by non-orchestrator agents triggers
         PRIVILEGE_ESCALATION.
      3. Code modification operations (coding.write) require coding authority.
         Attempted by non-coding agents (research-01, verification-01) triggers
         PRIVILEGE_ESCALATION.
    """
    action_val = request.action.value if isinstance(request.action, ActionName) else str(request.action)
    source = request.source_agent

    # 1. Deployment privilege escalation
    is_deployment_action = (
        action_val in ("deployment.deploy", "deployment.preview", "deployment.production")
        or request.action in (ActionName.DEPLOYMENT_DEPLOY, ActionName.DEPLOYMENT_PREVIEW)
        or required_capability(request.action) in (
            CapabilityName.DEPLOYMENT_PRODUCTION,
            CapabilityName.DEPLOYMENT_PREVIEW,
        )
    )
    if is_deployment_action and source != AgentId.DEPLOYMENT_01:
        return True

    # 2. Orchestration privilege escalation
    is_orchestrator_action = (
        action_val in ("orchestrator.delegate", "orchestrator.coordinate")
        or request.action in (ActionName.ORCHESTRATOR_DELEGATE, ActionName.ORCHESTRATOR_COORDINATE)
        or required_capability(request.action) in (
            CapabilityName.ORCHESTRATOR_DELEGATE,
            CapabilityName.ORCHESTRATOR_COORDINATE,
        )
    )
    if is_orchestrator_action and source != AgentId.ORCHESTRATOR_01:
        return True

    # 3. Code modification privilege escalation
    is_code_write = (
        action_val == "coding.write"
        or request.action == ActionName.CODING_WRITE
        or required_capability(request.action) == CapabilityName.CODING_WRITE
    )
    if is_code_write and source != AgentId.CODING_01:
        return True

    return False


def check_suspicious_behavior(
    request: ActionRequest,
    triggered_codes: set[ReasonCode] | None = None,
) -> bool:
    """
    Deterministic rule for SUSPICIOUS_BEHAVIOR (+10).

    Triggers when a high-risk compound violation is observed:
    PRIVILEGE_ESCALATION combined with at least one other violation
    (CAPABILITY_MISMATCH, AUTHORITY_MISMATCH, or PROVENANCE_ANOMALY).
    """
    if triggered_codes is None:
        triggered_codes = set()
        if check_capability_mismatch(request):
            triggered_codes.add(ReasonCode.CAPABILITY_MISMATCH)
        if check_authority_mismatch(request):
            triggered_codes.add(ReasonCode.AUTHORITY_MISMATCH)
        if check_provenance_anomaly(request):
            triggered_codes.add(ReasonCode.PROVENANCE_ANOMALY)
        if check_privilege_escalation(request):
            triggered_codes.add(ReasonCode.PRIVILEGE_ESCALATION)

    has_priv_esc = ReasonCode.PRIVILEGE_ESCALATION in triggered_codes
    has_other = any(
        code in triggered_codes
        for code in (
            ReasonCode.CAPABILITY_MISMATCH,
            ReasonCode.AUTHORITY_MISMATCH,
            ReasonCode.PROVENANCE_ANOMALY,
        )
    )
    return has_priv_esc and has_other
