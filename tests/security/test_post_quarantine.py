"""
Security Regression — Post-Quarantine Blocking Tests.

Verifies that after quarantine, ALL requests from the quarantined agent
are denied regardless of target, action, or resource:
  - Research -> Coding
  - Research -> Deployment
  - Research -> tool/AWS boundary

Each test gets fresh services. No state leakage.
"""

from datetime import datetime, timezone

import pytest

from shield.authorization.pipeline import authorize
from shield.capabilities.models import CapabilityName
from shield.enforcement.quarantine import QuarantineService
from shield.gateway.models import (
    ActionName,
    AuthorizationDecision,
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
    request_id: str | None = None,
) -> ActionRequest:
    if request_id is None:
        request_id = f"req-pq-{uuid.uuid4().hex[:8]}"
    return ActionRequest(
        request_id=request_id,
        timestamp=datetime.now(timezone.utc),
        source_agent=source_agent,
        target_agent=target_agent,
        task_id="task-post-quarantine",
        action=action,
        resource=resource,
        claimed_authority=source_agent,
        capability=capability,
        provenance=Provenance(
            task_origin=source_agent,
            delegation_chain=[source_agent],
        ),
        context=RequestContext(),
    )


import uuid


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestPostQuarantineBlocking:
    """Verify all requests from quarantined agent are denied."""

    @pytest.fixture(autouse=True)
    def _quarantine_research(self):
        """Quarantine research-01 before each test."""
        self.identity = IdentityService()
        QuarantineService(self.identity).quarantine(AgentId.RESEARCH_01)

    def test_research_to_coding_write_denied(self):
        """Research -> Coding (coding.write) => DENY AGENT_QUARANTINED."""
        request = _make_request(
            source_agent=AgentId.RESEARCH_01,
            target_agent=AgentId.CODING_01,
            action=ActionName.CODING_WRITE,
            resource=ResourceName.WORKSPACE,
            capability=CapabilityName.RESEARCH_SEARCH,
        )
        result = authorize(request, identity_service=self.identity)

        assert result.decision == AuthorizationDecision.DENY
        assert ReasonCode.AGENT_QUARANTINED in result.reason_codes

    def test_research_to_coding_read_denied(self):
        """Research -> Coding (coding.read) => DENY AGENT_QUARANTINED."""
        request = _make_request(
            source_agent=AgentId.RESEARCH_01,
            target_agent=AgentId.CODING_01,
            action=ActionName.CODING_READ,
            resource=ResourceName.WORKSPACE,
            capability=CapabilityName.RESEARCH_SEARCH,
        )
        result = authorize(request, identity_service=self.identity)

        assert result.decision == AuthorizationDecision.DENY
        assert ReasonCode.AGENT_QUARANTINED in result.reason_codes

    def test_research_to_deployment_deploy_denied(self):
        """Research -> Deployment (deployment.deploy) => DENY AGENT_QUARANTINED."""
        request = _make_request(
            source_agent=AgentId.RESEARCH_01,
            target_agent=AgentId.DEPLOYMENT_01,
            action=ActionName.DEPLOYMENT_DEPLOY,
            resource=ResourceName.PRODUCTION_ENVIRONMENT,
            capability=CapabilityName.RESEARCH_SEARCH,
        )
        result = authorize(request, identity_service=self.identity)

        assert result.decision == AuthorizationDecision.DENY
        assert ReasonCode.AGENT_QUARANTINED in result.reason_codes

    def test_research_to_deployment_preview_denied(self):
        """Research -> Deployment (deployment.preview) => DENY AGENT_QUARANTINED."""
        request = _make_request(
            source_agent=AgentId.RESEARCH_01,
            target_agent=AgentId.DEPLOYMENT_01,
            action=ActionName.DEPLOYMENT_PREVIEW,
            resource=ResourceName.STAGING_ENVIRONMENT,
            capability=CapabilityName.RESEARCH_SEARCH,
        )
        result = authorize(request, identity_service=self.identity)

        assert result.decision == AuthorizationDecision.DENY
        assert ReasonCode.AGENT_QUARANTINED in result.reason_codes

    def test_research_tool_boundary_denied(self):
        """Research -> tool/AWS boundary (deployment.preview staging) => DENY."""
        request = _make_request(
            source_agent=AgentId.RESEARCH_01,
            target_agent=AgentId.DEPLOYMENT_01,
            action=ActionName.DEPLOYMENT_PREVIEW,
            resource=ResourceName.STAGING_ENVIRONMENT,
            capability=CapabilityName.RESEARCH_SEARCH,
        )
        result = authorize(request, identity_service=self.identity)

        assert result.decision == AuthorizationDecision.DENY
        assert ReasonCode.AGENT_QUARANTINED in result.reason_codes

    def test_research_own_action_denied(self):
        """Research -> own action (research.search) still DENIED after quarantine."""
        request = _make_request(
            source_agent=AgentId.RESEARCH_01,
            action=ActionName.RESEARCH_SEARCH,
            resource=ResourceName.RESEARCH_DATA,
            capability=CapabilityName.RESEARCH_SEARCH,
        )
        result = authorize(request, identity_service=self.identity)

        assert result.decision == AuthorizationDecision.DENY
        assert ReasonCode.AGENT_QUARANTINED in result.reason_codes

    def test_all_post_quarantine_requests_denied(self):
        """Comprehensive: all action types denied after quarantine."""
        test_cases = [
            (ActionName.RESEARCH_SEARCH, ResourceName.RESEARCH_DATA, CapabilityName.RESEARCH_SEARCH),
            (ActionName.RESEARCH_READ, ResourceName.RESEARCH_DATA, CapabilityName.RESEARCH_READ),
            (ActionName.CODING_WRITE, ResourceName.WORKSPACE, CapabilityName.RESEARCH_SEARCH),
            (ActionName.CODING_READ, ResourceName.WORKSPACE, CapabilityName.RESEARCH_SEARCH),
            (ActionName.DEPLOYMENT_DEPLOY, ResourceName.PRODUCTION_ENVIRONMENT, CapabilityName.RESEARCH_SEARCH),
            (ActionName.DEPLOYMENT_PREVIEW, ResourceName.STAGING_ENVIRONMENT, CapabilityName.RESEARCH_SEARCH),
        ]

        for action, resource, cap in test_cases:
            request = _make_request(
                source_agent=AgentId.RESEARCH_01,
                action=action,
                resource=resource,
                capability=cap,
            )
            result = authorize(request, identity_service=self.identity)

            assert result.decision == AuthorizationDecision.DENY, (
                f"Expected DENY for {action.value} on {resource.value}"
            )
            assert ReasonCode.AGENT_QUARANTINED in result.reason_codes, (
                f"Expected AGENT_QUARANTINED for {action.value}"
            )
