"""
Context-aware runtime detection for Kavach.

Detection is deliberately deterministic and explainable. It scores observable
properties of a typed ActionRequest; the score is advisory and MUST NEVER
override the authorization pipeline's fail-closed decision.
"""
from __future__ import annotations

from shield.capabilities.models import CapabilityName
from shield.capabilities.registry import required_capability
from shield.gateway.models import ActionName, ActionRequest, ReasonCode, ResourceName
from shield.identity.models import AgentId
from shield.provenance.validator import validate_provenance


def check_capability_mismatch(request: ActionRequest) -> bool:
    required = required_capability(request.action)
    return required is None or request.capability != required


def check_authority_mismatch(request: ActionRequest) -> bool:
    chain = request.provenance.delegation_chain
    if not chain or chain[-1] != request.source_agent:
        return True
    expected = request.source_agent if len(chain) == 1 else chain[-2]
    return request.claimed_authority != expected


def check_provenance_anomaly(request: ActionRequest) -> bool:
    result = validate_provenance(request)
    return not result.valid and result.reason_code == ReasonCode.PROVENANCE_ANOMALY


def check_privilege_escalation(request: ActionRequest) -> bool:
    required = required_capability(request.action)
    owner_by_capability = {
        CapabilityName.DEPLOYMENT_PRODUCTION: AgentId.DEPLOYMENT_01,
        CapabilityName.DEPLOYMENT_PREVIEW: AgentId.DEPLOYMENT_01,
        CapabilityName.ORCHESTRATOR_DELEGATE: AgentId.ORCHESTRATOR_01,
        CapabilityName.ORCHESTRATOR_COORDINATE: AgentId.ORCHESTRATOR_01,
        CapabilityName.CODING_WRITE: AgentId.CODING_01,
        CapabilityName.RESEARCH_WRITE: AgentId.RESEARCH_01,
    }
    expected_owner = owner_by_capability.get(required)
    return expected_owner is not None and request.source_agent != expected_owner


def check_sensitive_resource_mismatch(request: ActionRequest) -> bool:
    """Flag actions that are structurally incompatible with resource sensitivity."""
    action = request.action
    resource = request.resource
    if resource == ResourceName.PRODUCTION_ENVIRONMENT:
        return action != ActionName.DEPLOYMENT_DEPLOY
    if resource == ResourceName.STAGING_ENVIRONMENT:
        return action not in (ActionName.DEPLOYMENT_PREVIEW, ActionName.DEPLOYMENT_DEPLOY)
    if resource == ResourceName.TEST_ENVIRONMENT:
        return action not in (ActionName.CODING_TEST, ActionName.VERIFICATION_TEST)
    if resource == ResourceName.WORKSPACE:
        return action not in (
            ActionName.CODING_READ, ActionName.CODING_WRITE, ActionName.CODING_TEST,
            ActionName.RESEARCH_READ, ActionName.RESEARCH_WRITE,
        )
    if resource == ResourceName.RESEARCH_DATA:
        return action not in (ActionName.RESEARCH_SEARCH, ActionName.RESEARCH_READ)
    return True


def check_delegation_depth(request: ActionRequest) -> bool:
    """Return true for a lineage longer than the currently supported delegation model."""
    return len(request.provenance.delegation_chain) > 2


def check_environment_context(request: ActionRequest) -> bool:
    """Flag explicit unsafe environment tags; absence of optional tags is neutral."""
    tags = {str(k).lower(): str(v).strip().lower()
            for k, v in request.context.environment_tags.items()}
    prod_like = tags.get("environment") in {"prod", "production"}
    untrusted = tags.get("trust") in {"untrusted", "external", "unknown"}
    debug = tags.get("debug") in {"true", "1", "enabled"}
    return (prod_like and debug) or (prod_like and untrusted)


def check_suspicious_behavior(
    request: ActionRequest,
    triggered_codes: set[ReasonCode] | None = None,
) -> bool:
    if triggered_codes is None:
        triggered_codes = set()
        checks = (
            (ReasonCode.CAPABILITY_MISMATCH, check_capability_mismatch),
            (ReasonCode.AUTHORITY_MISMATCH, check_authority_mismatch),
            (ReasonCode.PROVENANCE_ANOMALY, check_provenance_anomaly),
            (ReasonCode.PRIVILEGE_ESCALATION, check_privilege_escalation),
        )
        for code, check in checks:
            if check(request):
                triggered_codes.add(code)
    primary = {
        ReasonCode.CAPABILITY_MISMATCH,
        ReasonCode.AUTHORITY_MISMATCH,
        ReasonCode.PROVENANCE_ANOMALY,
        ReasonCode.PRIVILEGE_ESCALATION,
    }
    return len(triggered_codes.intersection(primary)) >= 2
