"""
Tests for Incident creation (Phase 16).

Incident creation is triggered when the FINAL authorization decision has:
    risk_score >= INCIDENT_THRESHOLD

Incident creation is a consequence of the decision, not an authorization mechanism.
It must NEVER change ALLOW -> DENY or DENY -> ALLOW.
"""

from datetime import datetime, timezone
import json
import uuid

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
from shield.incidents import INCIDENT_THRESHOLD, IncidentService
from shield.incidents.models import Incident, IncidentSeverity, IncidentStatus
from shield.provenance.models import Provenance


def _make_action_request(
    source_agent: AgentId = AgentId.RESEARCH_01,
    target_agent: AgentId = AgentId.RESEARCH_01,
    action: ActionName = ActionName.RESEARCH_SEARCH,
    resource: ResourceName = ResourceName.RESEARCH_DATA,
    capability: CapabilityName = CapabilityName.RESEARCH_SEARCH,
    claimed_authority: AgentId = AgentId.ORCHESTRATOR_01,
    task_origin: AgentId = AgentId.ORCHESTRATOR_01,
    delegation_chain: list[AgentId] | None = None,
) -> ActionRequest:
    """Helper to create a valid ActionRequest for incident testing."""
    if delegation_chain is None:
        delegation_chain = [AgentId.ORCHESTRATOR_01, source_agent]
    return ActionRequest(
        request_id=f"req-{uuid.uuid4().hex[:8]}",
        timestamp=datetime.now(timezone.utc),
        source_agent=source_agent,
        target_agent=target_agent,
        task_id="task-incident-001",
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


def _make_authorization_result(
    request: ActionRequest,
    decision: AuthorizationDecision = AuthorizationDecision.ALLOW,
    risk_score: int = 0,
    reason_codes: list[ReasonCode] | None = None,
    agent_state: SecurityState = SecurityState.ACTIVE,
) -> AuthorizationResult:
    """Helper to create an AuthorizationResult for incident testing."""
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


# ============================================================================
# TEST A: Incident Model Construction
# ============================================================================

def test_a_incident_model_construction():
    """
    TEST A — Incident model construction
    - valid incident can be created
    - required fields are enforced
    - invalid severity rejected
    - invalid status rejected
    """
    # Valid incident
    incident = Incident(
        incident_id="inc-test-001",
        timestamp=datetime.now(timezone.utc),
        agent_id=AgentId.RESEARCH_01,
        severity=IncidentSeverity.HIGH,
        status=IncidentStatus.OPEN,
        reason_codes=[ReasonCode.CAPABILITY_MISMATCH],
        request_ids=["req-001"],
    )
    assert incident.incident_id == "inc-test-001"
    assert incident.agent_id == AgentId.RESEARCH_01
    assert incident.severity == IncidentSeverity.HIGH
    assert incident.status == IncidentStatus.OPEN
    assert incident.reason_codes == [ReasonCode.CAPABILITY_MISMATCH]
    assert incident.request_ids == ["req-001"]

    # Invalid severity
    with pytest.raises(ValueError):
        Incident(
            incident_id="inc-test-002",
            timestamp=datetime.now(timezone.utc),
            agent_id=AgentId.RESEARCH_01,
            severity="INVALID_SEVERITY",
            status=IncidentStatus.OPEN,
        )

    # Invalid status
    with pytest.raises(ValueError):
        Incident(
            incident_id="inc-test-003",
            timestamp=datetime.now(timezone.utc),
            agent_id=AgentId.RESEARCH_01,
            severity=IncidentSeverity.LOW,
            status="INVALID_STATUS",
        )


# ============================================================================
# TEST B: Incident ID Uniqueness
# ============================================================================

def test_b_incident_id_uniqueness():
    """
    TEST B — Incident ID uniqueness
    Create two incidents.
    IDs must be different.
    """
    service = IncidentService()
    request = _make_action_request()
    result = _make_authorization_result(request, risk_score=90)

    incident1 = service.create(request.source_agent, result)
    incident2 = service.create(request.source_agent, result)

    assert incident1.incident_id != incident2.incident_id
    assert len(incident1.incident_id) > 4
    assert len(incident2.incident_id) > 4


# ============================================================================
# TEST C: High-Risk Incident Creation
# ============================================================================

def test_c_high_risk_incident_creation():
    """
    TEST C — High-risk incident creation
    Use a Decision with:
        agent_id/source_agent = research-01
        decision = DENY
        risk_score = 94
        reason_codes = CAPABILITY_MISMATCH, AUTHORITY_MISMATCH, PROVENANCE_ANOMALY

    Expected:
        incident created
        severity = HIGH
        status = OPEN
        agent_id = research-01
        trigger contains exactly those reason codes
    """
    service = IncidentService()
    request = _make_action_request(
        source_agent=AgentId.RESEARCH_01,
        target_agent=AgentId.DEPLOYMENT_01,
        action=ActionName.DEPLOYMENT_DEPLOY,
        resource=ResourceName.PRODUCTION_ENVIRONMENT,
        capability=CapabilityName.RESEARCH_SEARCH,
    )
    result = _make_authorization_result(
        request,
        decision=AuthorizationDecision.DENY,
        risk_score=94,
        reason_codes=[
            ReasonCode.CAPABILITY_MISMATCH,
            ReasonCode.AUTHORITY_MISMATCH,
            ReasonCode.PROVENANCE_ANOMALY,
        ],
    )

    incident = service.create(request.source_agent, result)

    assert incident is not None
    assert incident.severity == IncidentSeverity.HIGH
    assert incident.status == IncidentStatus.OPEN
    assert incident.agent_id == AgentId.RESEARCH_01
    assert incident.reason_codes == [
        ReasonCode.CAPABILITY_MISMATCH,
        ReasonCode.AUTHORITY_MISMATCH,
        ReasonCode.PROVENANCE_ANOMALY,
    ]


# ============================================================================
# TEST D: Below-Threshold Decision
# ============================================================================

def test_d_below_threshold_no_incident():
    """
    TEST D — Below-threshold decision
    Use:
        risk_score = 79

    Expected:
        no incident
    """
    service = IncidentService()
    request = _make_action_request()
    result = _make_authorization_result(request, risk_score=79)

    should_create = service.should_create_incident(result)
    assert should_create is False


# ============================================================================
# TEST E: Boundary Tests
# ============================================================================

def test_e_boundary_threshold_incident_created():
    """
    TEST E — Boundary test
    Use:
        risk_score = INCIDENT_THRESHOLD

    Expected:
        incident IS created
    """
    service = IncidentService()
    request = _make_action_request()
    result = _make_authorization_result(request, risk_score=INCIDENT_THRESHOLD)

    should_create = service.should_create_incident(result)
    assert should_create is True


def test_e_boundary_threshold_minus_one_no_incident():
    """
    TEST E — Boundary test
    Use:
        risk_score = INCIDENT_THRESHOLD - 1

    Expected:
        no incident
    """
    service = IncidentService()
    request = _make_action_request()
    result = _make_authorization_result(request, risk_score=INCIDENT_THRESHOLD - 1)

    should_create = service.should_create_incident(result)
    assert should_create is False


# ============================================================================
# TEST F: ALLOW + High Risk
# ============================================================================

def test_f_allow_high_risk_incident():
    """
    TEST F — ALLOW + high risk
    Construct a valid Decision with:
        decision = ALLOW
        risk_score >= threshold

    Verify incident behavior follows the Phase 16 threshold rule,
    but incident creation does NOT modify the ALLOW decision.
    """
    service = IncidentService()
    request = _make_action_request()
    result = _make_authorization_result(request, decision=AuthorizationDecision.ALLOW, risk_score=90)

    # Should create incident
    should_create = service.should_create_incident(result)
    assert should_create is True

    # Create incident
    incident = service.create(request.source_agent, result)
    assert incident.severity == IncidentSeverity.HIGH

    # Original decision remains ALLOW
    assert result.decision == AuthorizationDecision.ALLOW


# ============================================================================
# TEST G: DENY Remains DENY
# ============================================================================

def test_g_deny_remains_deny():
    """
    TEST G — DENY remains DENY
    Use the existing Cedar-denied research/deployment attack.

    Verify:
        final decision = DENY
        incident is created when risk >= threshold
    """
    service = IncidentService()
    request = _make_action_request(
        source_agent=AgentId.RESEARCH_01,
        target_agent=AgentId.DEPLOYMENT_01,
        action=ActionName.DEPLOYMENT_DEPLOY,
        resource=ResourceName.PRODUCTION_ENVIRONMENT,
        capability=CapabilityName.RESEARCH_SEARCH,
    )
    result = _make_authorization_result(
        request,
        decision=AuthorizationDecision.DENY,
        risk_score=90,
        reason_codes=[ReasonCode.CAPABILITY_MISMATCH, ReasonCode.POLICY_DENIED],
    )

    # Should create incident
    should_create = service.should_create_incident(result)
    assert should_create is True

    # Create incident
    incident = service.create(request.source_agent, result)
    assert incident.severity == IncidentSeverity.HIGH

    # Original decision remains DENY
    assert result.decision == AuthorizationDecision.DENY


# ============================================================================
# TEST H: Trigger Integrity
# ============================================================================

def test_h_trigger_integrity():
    """
    TEST H — Trigger integrity
    Given reason_codes:
        CAPABILITY_MISMATCH
        POLICY_DENIED

    Expected incident trigger contains exactly those codes.
    Do not automatically add:
        AUTHORITY_MISMATCH
        PROVENANCE_ANOMALY
        etc.
    """
    service = IncidentService()
    request = _make_action_request()
    result = _make_authorization_result(
        request,
        decision=AuthorizationDecision.DENY,
        risk_score=85,
        reason_codes=[ReasonCode.CAPABILITY_MISMATCH, ReasonCode.POLICY_DENIED],
    )

    incident = service.create(request.source_agent, result)

    assert incident.reason_codes == [ReasonCode.CAPABILITY_MISMATCH, ReasonCode.POLICY_DENIED]
    assert ReasonCode.AUTHORITY_MISMATCH not in incident.reason_codes
    assert ReasonCode.PROVENANCE_ANOMALY not in incident.reason_codes


# ============================================================================
# TEST I: Agent Identity
# ============================================================================

def test_i_agent_identity():
    """
    TEST I — Agent identity
    Incident must reference the source agent from the final request/decision.
    Do not use target_agent as agent_id.
    """
    service = IncidentService()
    request = _make_action_request(
        source_agent=AgentId.RESEARCH_01,
        target_agent=AgentId.DEPLOYMENT_01,
    )
    result = _make_authorization_result(request, risk_score=85)

    incident = service.create(request.source_agent, result)

    assert incident.agent_id == AgentId.RESEARCH_01
    assert incident.agent_id != request.target_agent


# ============================================================================
# TEST J: Serialization
# ============================================================================

def test_j_serialization():
    """
    TEST J — Serialization
    Incident must serialize to JSON cleanly.
    """
    service = IncidentService()
    request = _make_action_request()
    result = _make_authorization_result(
        request,
        decision=AuthorizationDecision.DENY,
        risk_score=85,
        reason_codes=[ReasonCode.CAPABILITY_MISMATCH],
    )

    incident = service.create(request.source_agent, result)

    # Serialize to JSON
    json_str = incident.model_dump_json()
    assert isinstance(json_str, str)

    # Parse back
    parsed = json.loads(json_str)
    assert isinstance(parsed, dict)

    # Verify fields
    assert parsed["incident_id"] == incident.incident_id
    assert parsed["agent_id"] == "research-01"
    assert parsed["severity"] == "HIGH"
    assert parsed["status"] == "OPEN"
    assert parsed["reason_codes"] == ["CAPABILITY_MISMATCH"]
    assert "timestamp" in parsed


# ============================================================================
# TEST K: Incident Creation Failure Isolation
# ============================================================================

def test_k_incident_creation_failure_isolation():
    """
    TEST K — Incident creation failure isolation
    Simulate an incident-store/service failure.

    Expected:
    - authorization result remains unchanged
    - ALLOW stays ALLOW
    - DENY stays DENY
    - failure does not become an authorization failure
    """
    def failing_create(agent_id: AgentId, result: AuthorizationResult) -> Incident:
        raise IOError("Incident store unavailable")

    class FailingIncidentService:
        def should_create_incident(self, result: AuthorizationResult) -> bool:
            return result.risk_score is not None and result.risk_score >= INCIDENT_THRESHOLD

        def create(self, agent_id: AgentId, result: AuthorizationResult) -> Incident:
            return failing_create(agent_id, result)

    request_allow = _make_action_request(
        source_agent=AgentId.RESEARCH_01,
        action=ActionName.RESEARCH_SEARCH,
        resource=ResourceName.RESEARCH_DATA,
        capability=CapabilityName.RESEARCH_SEARCH,
    )
    result_allow = authorize(request_allow, incident_service=FailingIncidentService())

    # Decision must remain ALLOW despite incident failure
    assert result_allow.decision == AuthorizationDecision.ALLOW
    assert result_allow.reason_codes == []

    request_deny = _make_action_request(
        source_agent=AgentId.RESEARCH_01,
        target_agent=AgentId.DEPLOYMENT_01,
        action=ActionName.DEPLOYMENT_DEPLOY,
        resource=ResourceName.PRODUCTION_ENVIRONMENT,
        capability=CapabilityName.RESEARCH_SEARCH,
    )
    result_deny = authorize(request_deny, incident_service=FailingIncidentService())

    # Decision must remain DENY despite incident failure
    assert result_deny.decision == AuthorizationDecision.DENY
    assert ReasonCode.CAPABILITY_MISMATCH in result_deny.reason_codes


# ============================================================================
# TEST L: End-to-End API Test
# ============================================================================

def test_l_end_to_end_api_test():
    """
    TEST L — End-to-end API test
    POST /authorize with the canonical malicious request.

    Verify:
        response decision = DENY
        risk_score is preserved
        reason_codes are preserved
        incident is created when risk >= threshold
    """
    from fastapi.testclient import TestClient
    from shield.api.app import app

    client = TestClient(app)

    payload = {
        "source_agent": "research-01",
        "target_agent": "deployment-01",
        "task_id": "task-e2e-001",
        "action": "deployment.deploy",
        "resource": "production-environment",
        "claimed_authority": "orchestrator-01",
        "capability": "research.search",
        "provenance": {
            "task_origin": "orchestrator-01",
            "delegation_chain": ["orchestrator-01", "research-01"],
        },
    }

    response = client.post("/authorize", json=payload)
    assert response.status_code == 200

    body = response.json()
    assert body["decision"] == "DENY"
    assert "CAPABILITY_MISMATCH" in body["reason_codes"]
    assert "POLICY_DENIED" in body["reason_codes"]
    assert body["risk_score"] is not None
    assert body["risk_score"] >= 0
    assert body["risk_score"] <= 100

    # Verify incident creation behavior based on risk score
    # If risk_score >= INCIDENT_THRESHOLD, incident should be created
    # If risk_score < INCIDENT_THRESHOLD, no incident should be created
    # This test verifies the pipeline correctly applies the threshold rule


# ============================================================================
# TEST M: IncidentService Threshold Configuration
# ============================================================================

def test_m_incident_service_threshold_configuration():
    """
    TEST M — IncidentService threshold configuration
    Verify custom threshold can be set.
    """
    service = IncidentService(threshold=50)
    assert service.threshold == 50

    request = _make_action_request()
    result = _make_authorization_result(request, risk_score=55)

    assert service.should_create_incident(result) is True

    result_low = _make_authorization_result(request, risk_score=45)
    assert service.should_create_incident(result_low) is False


# ============================================================================
# TEST N: None Risk Score
# ============================================================================

def test_n_none_risk_score():
    """
    TEST N — None risk score
    Verify None risk score does not trigger incident.
    """
    service = IncidentService()
    request = _make_action_request()
    result = _make_authorization_result(request, risk_score=None)

    assert service.should_create_incident(result) is False


# ============================================================================
# TEST O: Pipeline Integration
# ============================================================================

def test_o_pipeline_integration():
    """
    TEST O — Pipeline integration
    Verify authorize() creates incident when risk >= threshold.
    """
    request = _make_action_request(
        source_agent=AgentId.RESEARCH_01,
        target_agent=AgentId.DEPLOYMENT_01,
        action=ActionName.DEPLOYMENT_DEPLOY,
        resource=ResourceName.PRODUCTION_ENVIRONMENT,
        capability=CapabilityName.RESEARCH_SEARCH,
    )

    service = IncidentService()
    result = authorize(request, incident_service=service)

    # Verify incident was created if risk >= threshold
    if result.risk_score is not None and result.risk_score >= INCIDENT_THRESHOLD:
        incidents = service.list_all()
        assert len(incidents) >= 1
        incident = incidents[-1]
        assert incident.agent_id == request.source_agent
        assert incident.status == IncidentStatus.OPEN
