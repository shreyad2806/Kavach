"""
Security Regression — Capability Escalation Tests.

Verifies that research-01 cannot escalate from research.search to
deployment actions, and that legitimate requests remain ALLOW.

Each test gets fresh services. No state leakage.
"""

from datetime import datetime, timezone

import pytest

from shield.authorization.pipeline import authorize
from shield.capabilities.models import CapabilityName
from shield.gateway.models import (
    ActionName,
    AuthorizationDecision,
    CheckStatus,
    ReasonCode,
    ResourceName,
)
from shield.identity.models import AgentId, SecurityState
from shield.identity.service import IdentityService
from shield.provenance.models import Provenance
from shield.gateway.models import ActionRequest, RequestContext


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _make_request(
    source_agent: AgentId = AgentId.RESEARCH_01,
    target_agent: AgentId = AgentId.RESEARCH_01,
    action: ActionName = ActionName.RESEARCH_SEARCH,
    resource: ResourceName = ResourceName.RESEARCH_DATA,
    capability: CapabilityName = CapabilityName.RESEARCH_SEARCH,
    claimed_authority: AgentId | None = None,
    task_origin: AgentId | None = None,
    delegation_chain: list[AgentId] | None = None,
    request_id: str | None = None,
) -> ActionRequest:
    if claimed_authority is None:
        claimed_authority = source_agent
    if task_origin is None:
        task_origin = source_agent
    if delegation_chain is None:
        delegation_chain = [source_agent]
    if request_id is None:
        request_id = f"req-cap-{source_agent.value}-{action.value}"
    return ActionRequest(
        request_id=request_id,
        timestamp=datetime.now(timezone.utc),
        source_agent=source_agent,
        target_agent=target_agent,
        task_id="task-cap-escalation",
        action=action,
        resource=resource,
        claimed_authority=claimed_authority,
        capability=capability,
        provenance=Provenance(
            task_origin=task_origin,
            delegation_chain=delegation_chain,
        ),
        context=RequestContext(),
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestCapabilityEscalation:
    """Verify capability escalation is blocked by the authorization pipeline."""

    def test_research_deploy_production_denied(self):
        """research-01 with capability=research.search attempting deployment.deploy => DENY."""
        identity = IdentityService()
        request = _make_request(
            source_agent=AgentId.RESEARCH_01,
            target_agent=AgentId.DEPLOYMENT_01,
            action=ActionName.DEPLOYMENT_DEPLOY,
            resource=ResourceName.PRODUCTION_ENVIRONMENT,
            capability=CapabilityName.RESEARCH_SEARCH,
        )
        result = authorize(request, identity_service=identity)

        assert result.decision == AuthorizationDecision.DENY
        assert ReasonCode.CAPABILITY_MISMATCH in result.reason_codes

    def test_research_deploy_production_cedar_deny(self):
        """research-01 deployment.deploy also gets Cedar POLICY_DENIED."""
        identity = IdentityService()
        request = _make_request(
            source_agent=AgentId.RESEARCH_01,
            target_agent=AgentId.DEPLOYMENT_01,
            action=ActionName.DEPLOYMENT_DEPLOY,
            resource=ResourceName.PRODUCTION_ENVIRONMENT,
            capability=CapabilityName.RESEARCH_SEARCH,
        )
        result = authorize(request, identity_service=identity)

        assert ReasonCode.POLICY_DENIED in result.reason_codes

    def test_research_deploy_production_privilege_escalation(self):
        """research-01 deployment.deploy triggers PRIVILEGE_ESCALATION detection."""
        identity = IdentityService()
        request = _make_request(
            source_agent=AgentId.RESEARCH_01,
            target_agent=AgentId.DEPLOYMENT_01,
            action=ActionName.DEPLOYMENT_DEPLOY,
            resource=ResourceName.PRODUCTION_ENVIRONMENT,
            capability=CapabilityName.RESEARCH_SEARCH,
        )
        result = authorize(request, identity_service=identity)

        assert ReasonCode.PRIVILEGE_ESCALATION in result.reason_codes

    def test_research_deploy_production_suspicious_behavior(self):
        """research-01 deployment.deploy triggers SUSPICIOUS_BEHAVIOR (compound signal)."""
        identity = IdentityService()
        request = _make_request(
            source_agent=AgentId.RESEARCH_01,
            target_agent=AgentId.DEPLOYMENT_01,
            action=ActionName.DEPLOYMENT_DEPLOY,
            resource=ResourceName.PRODUCTION_ENVIRONMENT,
            capability=CapabilityName.RESEARCH_SEARCH,
        )
        result = authorize(request, identity_service=identity)

        assert ReasonCode.SUSPICIOUS_BEHAVIOR in result.reason_codes

    def test_research_deploy_production_risk_score(self):
        """research-01 deployment.deploy produces risk=55 via real detection signals."""
        identity = IdentityService()
        request = _make_request(
            source_agent=AgentId.RESEARCH_01,
            target_agent=AgentId.DEPLOYMENT_01,
            action=ActionName.DEPLOYMENT_DEPLOY,
            resource=ResourceName.PRODUCTION_ENVIRONMENT,
            capability=CapabilityName.RESEARCH_SEARCH,
        )
        result = authorize(request, identity_service=identity)

        # risk = CAPABILITY_MISMATCH(30) + PRIVILEGE_ESCALATION(15) + SUSPICIOUS_BEHAVIOR(10) = 55
        assert result.risk_score == 55

    def test_research_deploy_staging_denied(self):
        """research-01 attempting deployment.preview on staging => DENY."""
        identity = IdentityService()
        request = _make_request(
            source_agent=AgentId.RESEARCH_01,
            target_agent=AgentId.DEPLOYMENT_01,
            action=ActionName.DEPLOYMENT_PREVIEW,
            resource=ResourceName.STAGING_ENVIRONMENT,
            capability=CapabilityName.RESEARCH_SEARCH,
        )
        result = authorize(request, identity_service=identity)

        assert result.decision == AuthorizationDecision.DENY
        assert ReasonCode.POLICY_DENIED in result.reason_codes

    def test_legitimate_research_allowed(self):
        """research-01 with research.search on research-data => ALLOW."""
        identity = IdentityService()
        request = _make_request(
            source_agent=AgentId.RESEARCH_01,
            action=ActionName.RESEARCH_SEARCH,
            resource=ResourceName.RESEARCH_DATA,
            capability=CapabilityName.RESEARCH_SEARCH,
        )
        result = authorize(request, identity_service=identity)

        assert result.decision == AuthorizationDecision.ALLOW
        assert result.reason_codes == []
        assert result.risk_score == 0

    def test_legitimate_research_read_allowed(self):
        """research-01 with research.read on research-data => ALLOW."""
        identity = IdentityService()
        request = _make_request(
            source_agent=AgentId.RESEARCH_01,
            action=ActionName.RESEARCH_READ,
            resource=ResourceName.RESEARCH_DATA,
            capability=CapabilityName.RESEARCH_READ,
        )
        result = authorize(request, identity_service=identity)

        assert result.decision == AuthorizationDecision.ALLOW
        assert result.reason_codes == []

    def test_deployment_01_deploy_production_allowed(self):
        """deployment-01 with deployment.deploy on production-environment => ALLOW."""
        identity = IdentityService()
        request = _make_request(
            source_agent=AgentId.DEPLOYMENT_01,
            target_agent=AgentId.DEPLOYMENT_01,
            action=ActionName.DEPLOYMENT_DEPLOY,
            resource=ResourceName.PRODUCTION_ENVIRONMENT,
            capability=CapabilityName.DEPLOYMENT_PRODUCTION,
            task_origin=AgentId.DEPLOYMENT_01,
            delegation_chain=[AgentId.DEPLOYMENT_01],
        )
        result = authorize(request, identity_service=identity)

        assert result.decision == AuthorizationDecision.ALLOW
        assert result.reason_codes == []
