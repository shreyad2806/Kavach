"""
Security Regression — Full Attack Chain Tests.

Verifies the complete currently-supported attack chain:
  1. legitimate request => ALLOW
  2. capability escalation => DENY
  3. authority forgery => DENY
  4. repeated suspicious requests => actual risk recorded
  5. incident mechanism => verified when threshold condition is met
  6. quarantine => QUARANTINED
  7. post-quarantine requests => DENY

Important architectural note:
  Behavioral accumulation is not yet implemented. Individual request risk
  maxes at 55 through the Cedar-deny path. The default INCIDENT_THRESHOLD
  (80) is not naturally reached by any single request. This test verifies
  the incident/quarantine mechanisms independently using a configured
  threshold that matches the naturally-produced risk score.

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
from shield.incidents import INCIDENT_THRESHOLD
from shield.incidents.models import IncidentStatus
from shield.incidents.service import IncidentService
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
        request_id = f"req-chain-{source_agent.value}-{action.value}"
    return ActionRequest(
        request_id=request_id,
        timestamp=datetime.now(timezone.utc),
        source_agent=source_agent,
        target_agent=target_agent,
        task_id="task-full-chain",
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


def _run(request, *, identity_service=None, incident_threshold=None):
    ids = identity_service or IdentityService()
    inc = IncidentService(threshold=incident_threshold) if incident_threshold is not None else IncidentService()
    return authorize(request, identity_service=ids, incident_service=inc), inc


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestFullAttackChain:
    """End-to-end attack chain verifying all security layers work together."""

    def test_step1_legitimate_request_allowed(self):
        """Step 1: Legitimate research request => ALLOW."""
        identity = IdentityService()
        request = _make_request(
            source_agent=AgentId.RESEARCH_01,
            action=ActionName.RESEARCH_SEARCH,
            resource=ResourceName.RESEARCH_DATA,
            capability=CapabilityName.RESEARCH_SEARCH,
            request_id="req-chain-step1",
        )
        result, _ = _run(request, identity_service=identity)

        assert result.decision == AuthorizationDecision.ALLOW
        assert result.reason_codes == []
        assert result.checks.identity == CheckStatus.PASS
        assert result.checks.agent_state == CheckStatus.PASS
        assert result.checks.capability == CheckStatus.PASS
        assert result.checks.provenance == CheckStatus.PASS
        assert result.checks.cedar == CheckStatus.ALLOW
        assert result.risk_score == 0

    def test_step2_capability_escalation_denied(self):
        """Step 2: Capability escalation => DENY with CAPABILITY_MISMATCH."""
        identity = IdentityService()
        request = _make_request(
            source_agent=AgentId.RESEARCH_01,
            target_agent=AgentId.DEPLOYMENT_01,
            action=ActionName.DEPLOYMENT_DEPLOY,
            resource=ResourceName.PRODUCTION_ENVIRONMENT,
            capability=CapabilityName.RESEARCH_SEARCH,
            request_id="req-chain-step2",
        )
        result, _ = _run(request, identity_service=identity)

        assert result.decision == AuthorizationDecision.DENY
        assert ReasonCode.CAPABILITY_MISMATCH in result.reason_codes
        assert ReasonCode.POLICY_DENIED in result.reason_codes
        assert ReasonCode.PRIVILEGE_ESCALATION in result.reason_codes
        assert ReasonCode.SUSPICIOUS_BEHAVIOR in result.reason_codes
        assert result.risk_score == 55

    def test_step3_authority_forgery_denied(self):
        """Step 3: Authority forgery => DENY with AUTHORITY_MISMATCH."""
        identity = IdentityService()
        request = _make_request(
            source_agent=AgentId.RESEARCH_01,
            claimed_authority=AgentId.ORCHESTRATOR_01,
            delegation_chain=[AgentId.RESEARCH_01],
            request_id="req-chain-step3",
        )
        result, _ = _run(request, identity_service=identity)

        assert result.decision == AuthorizationDecision.DENY
        assert ReasonCode.AUTHORITY_MISMATCH in result.reason_codes
        assert result.checks.provenance == CheckStatus.FAIL
        assert result.checks.cedar == CheckStatus.NOT_EVALUATED
        assert result.risk_score == 25

    def test_step4_repeated_suspicious_requests(self):
        """Step 4: Repeated suspicious requests produce real detection signals."""
        identity = IdentityService()

        req_a = _make_request(
            source_agent=AgentId.RESEARCH_01,
            target_agent=AgentId.DEPLOYMENT_01,
            action=ActionName.DEPLOYMENT_DEPLOY,
            resource=ResourceName.PRODUCTION_ENVIRONMENT,
            capability=CapabilityName.RESEARCH_SEARCH,
            claimed_authority=AgentId.ORCHESTRATOR_01,
            task_origin=AgentId.ORCHESTRATOR_01,
            delegation_chain=[AgentId.ORCHESTRATOR_01, AgentId.RESEARCH_01],
            request_id="req-chain-step4a",
        )
        result_a, _ = _run(req_a, identity_service=identity)

        req_b = _make_request(
            source_agent=AgentId.RESEARCH_01,
            target_agent=AgentId.DEPLOYMENT_01,
            action=ActionName.DEPLOYMENT_DEPLOY,
            resource=ResourceName.PRODUCTION_ENVIRONMENT,
            capability=CapabilityName.RESEARCH_SEARCH,
            claimed_authority=AgentId.ORCHESTRATOR_01,
            task_origin=AgentId.ORCHESTRATOR_01,
            delegation_chain=[AgentId.ORCHESTRATOR_01, AgentId.RESEARCH_01],
            request_id="req-chain-step4b",
        )
        result_b, _ = _run(req_b, identity_service=identity)

        assert result_a.decision == AuthorizationDecision.DENY
        assert result_b.decision == AuthorizationDecision.DENY
        assert ReasonCode.CAPABILITY_MISMATCH in result_a.reason_codes
        assert ReasonCode.PRIVILEGE_ESCALATION in result_a.reason_codes
        assert ReasonCode.SUSPICIOUS_BEHAVIOR in result_a.reason_codes
        assert result_a.risk_score == 55
        assert result_b.risk_score == 55

    def test_step5_incident_creation_mechanism(self):
        """Step 5: Incident created when risk >= threshold (mechanism test)."""
        identity = IdentityService()
        request = _make_request(
            source_agent=AgentId.RESEARCH_01,
            target_agent=AgentId.DEPLOYMENT_01,
            action=ActionName.DEPLOYMENT_DEPLOY,
            resource=ResourceName.PRODUCTION_ENVIRONMENT,
            capability=CapabilityName.RESEARCH_SEARCH,
            claimed_authority=AgentId.ORCHESTRATOR_01,
            task_origin=AgentId.ORCHESTRATOR_01,
            delegation_chain=[AgentId.ORCHESTRATOR_01, AgentId.RESEARCH_01],
            request_id="req-chain-step5",
        )
        # Use threshold=55 to match naturally-produced risk
        result, inc_svc = _run(request, identity_service=identity, incident_threshold=55)

        assert result.decision == AuthorizationDecision.DENY
        assert result.risk_score == 55

        incidents = inc_svc.list_all()
        assert len(incidents) >= 1
        incident = incidents[-1]
        assert incident.status == IncidentStatus.OPEN
        assert incident.agent_id == AgentId.RESEARCH_01
        assert ReasonCode.CAPABILITY_MISMATCH in incident.reason_codes

    def test_step5_incident_not_created_below_threshold(self):
        """Step 5: No incident when risk < threshold."""
        identity = IdentityService()
        request = _make_request(
            source_agent=AgentId.RESEARCH_01,
            action=ActionName.RESEARCH_SEARCH,
            resource=ResourceName.RESEARCH_DATA,
            capability=CapabilityName.RESEARCH_SEARCH,
            request_id="req-chain-step5-below",
        )
        # Use default threshold (80); legitimate request has risk=0
        result, inc_svc = _run(request, identity_service=identity)

        assert result.decision == AuthorizationDecision.ALLOW
        assert result.risk_score == 0
        assert len(inc_svc.list_all()) == 0

    def test_step6_quarantine_blocks_all_requests(self):
        """Step 6: After quarantine, all requests => DENY AGENT_QUARANTINED."""
        identity = IdentityService()
        QuarantineService(identity).quarantine(AgentId.RESEARCH_01)

        # Test multiple action types
        test_cases = [
            (ActionName.RESEARCH_SEARCH, ResourceName.RESEARCH_DATA, CapabilityName.RESEARCH_SEARCH),
            (ActionName.RESEARCH_READ, ResourceName.RESEARCH_DATA, CapabilityName.RESEARCH_READ),
            (ActionName.DEPLOYMENT_DEPLOY, ResourceName.PRODUCTION_ENVIRONMENT, CapabilityName.RESEARCH_SEARCH),
        ]

        for action, resource, cap in test_cases:
            request = _make_request(
                source_agent=AgentId.RESEARCH_01,
                action=action,
                resource=resource,
                capability=cap,
                request_id=f"req-chain-step6-{action.value}",
            )
            result, _ = _run(request, identity_service=identity)

            assert result.decision == AuthorizationDecision.DENY
            assert ReasonCode.AGENT_QUARANTINED in result.reason_codes

    def test_step7_post_quarantine_coding_request(self):
        """Step 7: Post-quarantine research-01 -> coding-01 => DENY."""
        identity = IdentityService()
        QuarantineService(identity).quarantine(AgentId.RESEARCH_01)

        request = _make_request(
            source_agent=AgentId.RESEARCH_01,
            target_agent=AgentId.CODING_01,
            action=ActionName.CODING_WRITE,
            resource=ResourceName.WORKSPACE,
            capability=CapabilityName.RESEARCH_SEARCH,
            request_id="req-chain-step7",
        )
        result, _ = _run(request, identity_service=identity)

        assert result.decision == AuthorizationDecision.DENY
        assert ReasonCode.AGENT_QUARANTINED in result.reason_codes

    def test_step7_post_quarantine_deployment_request(self):
        """Step 7: Post-quarantine research-01 -> deployment-01 => DENY."""
        identity = IdentityService()
        QuarantineService(identity).quarantine(AgentId.RESEARCH_01)

        request = _make_request(
            source_agent=AgentId.RESEARCH_01,
            target_agent=AgentId.DEPLOYMENT_01,
            action=ActionName.DEPLOYMENT_DEPLOY,
            resource=ResourceName.PRODUCTION_ENVIRONMENT,
            capability=CapabilityName.RESEARCH_SEARCH,
            request_id="req-chain-step7-deploy",
        )
        result, _ = _run(request, identity_service=identity)

        assert result.decision == AuthorizationDecision.DENY
        assert ReasonCode.AGENT_QUARANTINED in result.reason_codes

    def test_step7_post_quarantine_tool_boundary(self):
        """Step 7: Post-quarantine research-01 -> tool/AWS boundary => DENY."""
        identity = IdentityService()
        QuarantineService(identity).quarantine(AgentId.RESEARCH_01)

        request = _make_request(
            source_agent=AgentId.RESEARCH_01,
            target_agent=AgentId.DEPLOYMENT_01,
            action=ActionName.DEPLOYMENT_PREVIEW,
            resource=ResourceName.STAGING_ENVIRONMENT,
            capability=CapabilityName.RESEARCH_SEARCH,
            request_id="req-chain-step7-tool",
        )
        result, _ = _run(request, identity_service=identity)

        assert result.decision == AuthorizationDecision.DENY
        assert ReasonCode.AGENT_QUARANTINED in result.reason_codes

    def test_incident_threshold_documentation(self):
        """Document that default INCIDENT_THRESHOLD=80 exceeds natural max risk=55.

        Behavioral accumulation is not yet implemented; Phase 19 verifies
        the incident/quarantine mechanisms independently.
        """
        assert INCIDENT_THRESHOLD == 80
        # Max per-request risk through Cedar-deny path is 55
        # CAPABILITY_MISMATCH(30) + PRIVILEGE_ESCALATION(15) + SUSPICIOUS_BEHAVIOR(10)
        max_natural_risk = 30 + 15 + 10
        assert max_natural_risk == 55
        assert INCIDENT_THRESHOLD > max_natural_risk
