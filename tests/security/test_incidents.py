"""
Security Regression — Incident Tests.

Verifies the incident creation mechanism:
  - risk >= threshold creates incident with status=OPEN, severity=HIGH
  - incident.reason_codes come from the final Decision
  - risk < threshold does not create incident
  - mechanism works independently of production threshold

Important: does NOT lower the production threshold. Uses controlled
AuthorizationResult injection for mechanism tests.
"""

from datetime import datetime, timezone

import pytest

from shield.authorization.pipeline import authorize
from shield.capabilities.models import CapabilityName
from shield.gateway.models import (
    ActionName,
    ActionRequest,
    AuthorizationChecks,
    AuthorizationDecision,
    AuthorizationResult,
    CheckStatus,
    ReasonCode,
    RequestContext,
    ResourceName,
)
from shield.identity.models import AgentId, SecurityState
from shield.identity.service import IdentityService
from shield.incidents import INCIDENT_THRESHOLD
from shield.incidents.models import IncidentSeverity, IncidentStatus
from shield.incidents.service import IncidentService
from shield.provenance.models import Provenance


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
        request_id = f"req-inc-{uuid.uuid4().hex[:8]}"
    return ActionRequest(
        request_id=request_id,
        timestamp=datetime.now(timezone.utc),
        source_agent=source_agent,
        target_agent=target_agent,
        task_id="task-incidents",
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


def _make_result(
    request: ActionRequest,
    decision: AuthorizationDecision = AuthorizationDecision.ALLOW,
    risk_score: int = 0,
    reason_codes: list[ReasonCode] | None = None,
    agent_state: SecurityState = SecurityState.ACTIVE,
) -> AuthorizationResult:
    if reason_codes is None:
        reason_codes = []
    return AuthorizationResult(
        request_id=request.request_id,
        decision=decision,
        reason_codes=reason_codes,
        risk_score=risk_score,
        checks=AuthorizationChecks(
            identity=CheckStatus.PASS,
            agent_state=CheckStatus.PASS,
            capability=CheckStatus.PASS,
            provenance=CheckStatus.PASS,
            cedar=CheckStatus.ALLOW if decision == AuthorizationDecision.ALLOW else CheckStatus.DENY,
            deterministic_rules=CheckStatus.PASS,
        ),
        agent_state=agent_state,
    )


import uuid


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestIncidents:
    """Verify incident creation mechanism."""

    def test_incident_created_when_risk_above_threshold(self):
        """risk >= threshold creates incident with status=OPEN, severity=HIGH."""
        service = IncidentService()
        request = _make_request()
        result = _make_result(request, risk_score=INCIDENT_THRESHOLD)

        incident = service.create(request.source_agent, result)

        assert incident.status == IncidentStatus.OPEN
        assert incident.severity == IncidentSeverity.HIGH
        assert incident.agent_id == request.source_agent

    def test_incident_created_at_boundary(self):
        """risk == threshold creates incident."""
        service = IncidentService()
        request = _make_request()
        result = _make_result(request, risk_score=INCIDENT_THRESHOLD)

        assert service.should_create_incident(result) is True

    def test_no_incident_below_threshold(self):
        """risk < threshold does not create incident."""
        service = IncidentService()
        request = _make_request()
        result = _make_result(request, risk_score=INCIDENT_THRESHOLD - 1)

        assert service.should_create_incident(result) is False

    def test_incident_reason_codes_from_decision(self):
        """incident.reason_codes come from the final Decision."""
        service = IncidentService()
        request = _make_request()
        result = _make_result(
            request,
            risk_score=90,
            reason_codes=[ReasonCode.CAPABILITY_MISMATCH, ReasonCode.POLICY_DENIED],
        )

        incident = service.create(request.source_agent, result)

        assert incident.reason_codes == [ReasonCode.CAPABILITY_MISMATCH, ReasonCode.POLICY_DENIED]

    def test_incident_agent_id_is_source_agent(self):
        """incident.agent_id is the source agent, not target agent."""
        service = IncidentService()
        request = _make_request(
            source_agent=AgentId.RESEARCH_01,
            target_agent=AgentId.DEPLOYMENT_01,
        )
        result = _make_result(request, risk_score=90)

        incident = service.create(request.source_agent, result)

        assert incident.agent_id == AgentId.RESEARCH_01
        assert incident.agent_id != request.target_agent

    def test_incident_does_not_modify_authorization_result(self):
        """Incident creation does not change the AuthorizationResult."""
        service = IncidentService()
        request = _make_request()
        result = _make_result(request, risk_score=90)

        original_decision = result.decision
        original_reasons = list(result.reason_codes)
        original_risk = result.risk_score

        service.create(request.source_agent, result)

        assert result.decision == original_decision
        assert result.reason_codes == original_reasons
        assert result.risk_score == original_risk

    def test_production_threshold_not_lowered(self):
        """Verify production INCIDENT_THRESHOLD is still 80."""
        assert INCIDENT_THRESHOLD == 80

    def test_mechanism_test_with_injected_result(self):
        """Mechanism test: inject controlled result with risk >= threshold."""
        service = IncidentService()
        request = _make_request(
            source_agent=AgentId.RESEARCH_01,
            action=ActionName.DEPLOYMENT_DEPLOY,
            resource=ResourceName.PRODUCTION_ENVIRONMENT,
            capability=CapabilityName.RESEARCH_SEARCH,
        )
        result = _make_result(
            request,
            decision=AuthorizationDecision.DENY,
            risk_score=94,
            reason_codes=[
                ReasonCode.CAPABILITY_MISMATCH,
                ReasonCode.AUTHORITY_MISMATCH,
                ReasonCode.PROVENANCE_ANOMALY,
            ],
        )

        assert service.should_create_incident(result) is True

        incident = service.create(request.source_agent, result)

        assert incident.status == IncidentStatus.OPEN
        assert incident.severity == IncidentSeverity.HIGH
        assert incident.agent_id == AgentId.RESEARCH_01
        assert incident.reason_codes == [
            ReasonCode.CAPABILITY_MISMATCH,
            ReasonCode.AUTHORITY_MISMATCH,
            ReasonCode.PROVENANCE_ANOMALY,
        ]

    def test_incident_failure_does_not_change_decision(self):
        """Incident creation failure does not alter authorization result."""
        class FailingIncidentService:
            def should_create_incident(self, result):
                return True

            def create(self, agent_id, result):
                raise IOError("Incident store unavailable")

        identity = IdentityService()
        request = _make_request(
            source_agent=AgentId.RESEARCH_01,
            action=ActionName.RESEARCH_SEARCH,
            resource=ResourceName.RESEARCH_DATA,
            capability=CapabilityName.RESEARCH_SEARCH,
        )
        result = authorize(request, identity_service=identity, incident_service=FailingIncidentService())

        assert result.decision == AuthorizationDecision.ALLOW
        assert result.reason_codes == []
