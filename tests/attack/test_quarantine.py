"""
Security Regression — Quarantine Tests.

Verifies:
  - ACTIVE -> QUARANTINED transition
  - Legitimate request is ALLOW before quarantine
  - Every request is DENY after quarantine with AGENT_QUARANTINED
  - Pipeline short-circuits after state check for quarantined agents
  - Multiple actions all blocked post-quarantine
  - Quarantine blocks even valid Cedar-authorized requests

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
        request_id = f"req-q-{source_agent.value}-{action.value}"
    return ActionRequest(
        request_id=request_id,
        timestamp=datetime.now(timezone.utc),
        source_agent=source_agent,
        target_agent=target_agent,
        task_id="task-quarantine",
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

class TestQuarantine:
    """Verify quarantine transitions and post-quarantine blocking."""

    def test_active_to_quarantined(self):
        """research-01 transitions from ACTIVE to QUARANTINED."""
        identity = IdentityService()
        quarantine_svc = QuarantineService(identity)

        agent = identity.get_agent(AgentId.RESEARCH_01)
        assert agent.state == SecurityState.ACTIVE

        quarantine_svc.quarantine(AgentId.RESEARCH_01)

        agent = identity.get_agent(AgentId.RESEARCH_01)
        assert agent.state == SecurityState.QUARANTINED

    def test_legitimate_request_allowed_before_quarantine(self):
        """research-01 research.search is ALLOW when ACTIVE."""
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

    def test_same_request_denied_after_quarantine(self):
        """Same valid request becomes DENY after quarantine."""
        identity = IdentityService()

        # Before quarantine: ALLOW
        request = _make_request(
            source_agent=AgentId.RESEARCH_01,
            action=ActionName.RESEARCH_SEARCH,
            resource=ResourceName.RESEARCH_DATA,
            capability=CapabilityName.RESEARCH_SEARCH,
        )
        result_before = authorize(request, identity_service=identity)
        assert result_before.decision == AuthorizationDecision.ALLOW

        # Quarantine
        quarantine_svc = QuarantineService(identity)
        quarantine_svc.quarantine(AgentId.RESEARCH_01)

        # After quarantine: DENY
        result_after = authorize(request, identity_service=identity)
        assert result_after.decision == AuthorizationDecision.DENY
        assert ReasonCode.AGENT_QUARANTINED in result_after.reason_codes

    def test_pipeline_short_circuits_after_state_check(self):
        """Quarantined agent: identity=PASS, agent_state=FAIL, rest=NOT_EVALUATED."""
        identity = IdentityService()
        quarantine_svc = QuarantineService(identity)
        quarantine_svc.quarantine(AgentId.RESEARCH_01)

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
            target_agent=AgentId.DEPLOYMENT_01,
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

        # Verify Cedar normally allows this request
        request = _make_request(
            source_agent=AgentId.RESEARCH_01,
            action=ActionName.RESEARCH_SEARCH,
            resource=ResourceName.RESEARCH_DATA,
            capability=CapabilityName.RESEARCH_SEARCH,
        )
        result_before = authorize(request, identity_service=identity)
        assert result_before.decision == AuthorizationDecision.ALLOW

        # Quarantine
        QuarantineService(identity).quarantine(AgentId.RESEARCH_01)

        # Same request after quarantine
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

        # Create result before quarantine
        request = _make_request(
            source_agent=AgentId.RESEARCH_01,
            action=ActionName.RESEARCH_SEARCH,
            resource=ResourceName.RESEARCH_DATA,
            capability=CapabilityName.RESEARCH_SEARCH,
        )
        result_before = authorize(request, identity_service=identity)
        original_decision = result_before.decision
        original_reasons = list(result_before.reason_codes)

        # Quarantine
        QuarantineService(identity).quarantine(AgentId.RESEARCH_01)

        # Original result unchanged
        assert result_before.decision == original_decision
        assert result_before.reason_codes == original_reasons

        # New request gets DENIED
        result_after = authorize(request, identity_service=identity)
        assert result_after.decision == AuthorizationDecision.DENY
