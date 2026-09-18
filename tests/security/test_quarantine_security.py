"""
Security Regression — Quarantine Security Tests.

Verifies the quarantine mechanism:
  - ACTIVE -> QUARANTINED transition
  - Same valid request becomes DENY after quarantine
  - Pipeline short-circuits after state check
  - Multiple action types all blocked

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
    action: ActionName = ActionName.RESEARCH_SEARCH,
    resource: ResourceName = ResourceName.RESEARCH_DATA,
    capability: CapabilityName = CapabilityName.RESEARCH_SEARCH,
    request_id: str | None = None,
) -> ActionRequest:
    if request_id is None:
        request_id = f"req-qsec-{uuid.uuid4().hex[:8]}"
    return ActionRequest(
        request_id=request_id,
        timestamp=datetime.now(timezone.utc),
        source_agent=source_agent,
        target_agent=source_agent,
        task_id="task-quarantine-sec",
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

class TestQuarantineSecurity:
    """Verify quarantine security behavior."""

    def test_active_to_quarantined_transition(self):
        """research-01 transitions from ACTIVE to QUARANTINED."""
        identity = IdentityService()
        quarantine_svc = QuarantineService(identity)

        agent = identity.get_agent(AgentId.RESEARCH_01)
        assert agent.state == SecurityState.ACTIVE

        quarantine_svc.quarantine(AgentId.RESEARCH_01)

        agent = identity.get_agent(AgentId.RESEARCH_01)
        assert agent.state == SecurityState.QUARANTINED

    def test_same_valid_request_denied_after_quarantine(self):
        """Same valid request becomes DENY after quarantine."""
        identity = IdentityService()

        request = _make_request(
            source_agent=AgentId.RESEARCH_01,
            action=ActionName.RESEARCH_SEARCH,
            resource=ResourceName.RESEARCH_DATA,
            capability=CapabilityName.RESEARCH_SEARCH,
        )

        # Before quarantine: ALLOW
        result_before = authorize(request, identity_service=identity)
        assert result_before.decision == AuthorizationDecision.ALLOW

        # Quarantine
        QuarantineService(identity).quarantine(AgentId.RESEARCH_01)

        # After quarantine: DENY
        result_after = authorize(request, identity_service=identity)
        assert result_after.decision == AuthorizationDecision.DENY
        assert ReasonCode.AGENT_QUARANTINED in result_after.reason_codes

    def test_pipeline_short_circuits_after_state_check(self):
        """Quarantined agent: identity=PASS, agent_state=FAIL, rest=NOT_EVALUATED."""
        identity = IdentityService()
        QuarantineService(identity).quarantine(AgentId.RESEARCH_01)

        request = _make_request(
            source_agent=AgentId.RESEARCH_01,
            action=ActionName.RESEARCH_SEARCH,
            resource=ResourceName.RESEARCH_DATA,
            capability=CapabilityName.RESEARCH_SEARCH,
        )
        result = authorize(request, identity_service=identity)

        assert result.checks.identity == CheckStatus.PASS
        assert result.checks.agent_state == CheckStatus.FAIL
        assert result.checks.capability == CheckStatus.NOT_EVALUATED
        assert result.checks.provenance == CheckStatus.NOT_EVALUATED
        assert result.checks.cedar == CheckStatus.NOT_EVALUATED

    def test_quarantine_blocks_research_search(self):
        """Quarantined research-01 cannot perform research.search."""
        identity = IdentityService()
        QuarantineService(identity).quarantine(AgentId.RESEARCH_01)

        request = _make_request(
            source_agent=AgentId.RESEARCH_01,
            action=ActionName.RESEARCH_SEARCH,
            resource=ResourceName.RESEARCH_DATA,
            capability=CapabilityName.RESEARCH_SEARCH,
        )
        result = authorize(request, identity_service=identity)

        assert result.decision == AuthorizationDecision.DENY
        assert ReasonCode.AGENT_QUARANTINED in result.reason_codes

    def test_quarantine_blocks_research_read(self):
        """Quarantined research-01 cannot perform research.read."""
        identity = IdentityService()
        QuarantineService(identity).quarantine(AgentId.RESEARCH_01)

        request = _make_request(
            source_agent=AgentId.RESEARCH_01,
            action=ActionName.RESEARCH_READ,
            resource=ResourceName.RESEARCH_DATA,
            capability=CapabilityName.RESEARCH_READ,
        )
        result = authorize(request, identity_service=identity)

        assert result.decision == AuthorizationDecision.DENY
        assert ReasonCode.AGENT_QUARANTINED in result.reason_codes

    def test_quarantine_blocks_deployment_deploy(self):
        """Quarantined research-01 cannot perform deployment.deploy."""
        identity = IdentityService()
        QuarantineService(identity).quarantine(AgentId.RESEARCH_01)

        request = _make_request(
            source_agent=AgentId.RESEARCH_01,
            action=ActionName.DEPLOYMENT_DEPLOY,
            resource=ResourceName.PRODUCTION_ENVIRONMENT,
            capability=CapabilityName.RESEARCH_SEARCH,
        )
        result = authorize(request, identity_service=identity)

        assert result.decision == AuthorizationDecision.DENY
        assert ReasonCode.AGENT_QUARANTINED in result.reason_codes

    def test_quarantine_blocks_even_valid_cedar_request(self):
        """Quarantine blocks even a request Cedar would normally permit."""
        identity = IdentityService()

        request = _make_request(
            source_agent=AgentId.RESEARCH_01,
            action=ActionName.RESEARCH_SEARCH,
            resource=ResourceName.RESEARCH_DATA,
            capability=CapabilityName.RESEARCH_SEARCH,
        )

        # Before quarantine: Cedar allows
        result_before = authorize(request, identity_service=identity)
        assert result_before.decision == AuthorizationDecision.ALLOW

        # Quarantine
        QuarantineService(identity).quarantine(AgentId.RESEARCH_01)

        # After quarantine: DENY
        result_after = authorize(request, identity_service=identity)
        assert result_after.decision == AuthorizationDecision.DENY
        assert ReasonCode.AGENT_QUARANTINED in result_after.reason_codes

    def test_quarantine_idempotent(self):
        """Double-quarantine keeps agent QUARANTINED."""
        identity = IdentityService()
        quarantine_svc = QuarantineService(identity)

        quarantine_svc.quarantine(AgentId.RESEARCH_01)
        quarantine_svc.quarantine(AgentId.RESEARCH_01)

        agent = identity.get_agent(AgentId.RESEARCH_01)
        assert agent.state == SecurityState.QUARANTINED

    def test_quarantine_does_not_modify_existing_decision(self):
        """Quarantine changes agent state, not existing AuthorizationResult objects."""
        identity = IdentityService()

        request = _make_request(
            source_agent=AgentId.RESEARCH_01,
            action=ActionName.RESEARCH_SEARCH,
            resource=ResourceName.RESEARCH_DATA,
            capability=CapabilityName.RESEARCH_SEARCH,
        )
        result_before = authorize(request, identity_service=identity)
        original_decision = result_before.decision
        original_reasons = list(result_before.reason_codes)

        QuarantineService(identity).quarantine(AgentId.RESEARCH_01)

        # Original result unchanged
        assert result_before.decision == original_decision
        assert result_before.reason_codes == original_reasons

        # New request gets DENIED
        result_after = authorize(request, identity_service=identity)
        assert result_after.decision == AuthorizationDecision.DENY
