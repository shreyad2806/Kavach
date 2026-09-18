"""
Tests for SecurityEvent construction, serialization, and telemetry mapping.
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
from shield.provenance.models import Provenance
from shield.telemetry.events import (
    EventType,
    SecurityEvent,
    create_authorization_decision_event,
)


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
    """Helper to create a valid ActionRequest for telemetry testing."""
    if delegation_chain is None:
        delegation_chain = [AgentId.ORCHESTRATOR_01, source_agent]
    return ActionRequest(
        request_id=f"req-{uuid.uuid4().hex[:8]}",
        timestamp=datetime.now(timezone.utc),
        source_agent=source_agent,
        target_agent=target_agent,
        task_id="task-telemetry-001",
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


# ============================================================================
# TEST A: SecurityEvent Construction
# ============================================================================

def test_a_security_event_construction():
    """
    TEST A — SecurityEvent construction
    Given a valid request and decision, verify all required fields exist.
    """
    request = _make_action_request()
    result = AuthorizationResult(
        request_id=request.request_id,
        decision=AuthorizationDecision.ALLOW,
        reason_codes=[],
        risk_score=0,
        checks=AuthorizationChecks(
            identity=CheckStatus.PASS,
            agent_state=CheckStatus.PASS,
            capability=CheckStatus.PASS,
            provenance=CheckStatus.PASS,
            cedar=CheckStatus.ALLOW,
            deterministic_rules=CheckStatus.PASS,
        ),
        agent_state=SecurityState.ACTIVE,
    )

    event = create_authorization_decision_event(request, result)

    assert isinstance(event, SecurityEvent)
    assert event.event_id.startswith("evt-")
    assert event.event_type == EventType.AUTHORIZATION_DECISION
    assert event.timestamp is not None
    assert event.source_agent == request.source_agent
    assert event.target_agent == request.target_agent
    assert event.request_id == request.request_id
    assert event.task_id == request.task_id
    assert event.action == request.action
    assert event.resource == request.resource
    assert event.policy_decision == AuthorizationDecision.ALLOW
    assert event.risk_score == 0
    assert event.reason_codes == []


# ============================================================================
# TEST B: Event Serialization
# ============================================================================

def test_b_event_serialization():
    """
    TEST B — Event serialization
    Serialize SecurityEvent to JSON.
    Verify:
    - valid JSON
    - enums serialize consistently as strings
    - reason_codes serialize as strings
    - timestamp serializes in ISO 8601 format
    - event_id exists
    """
    request = _make_action_request(
        action=ActionName.DEPLOYMENT_DEPLOY,
        resource=ResourceName.PRODUCTION_ENVIRONMENT,
    )
    result = AuthorizationResult(
        request_id=request.request_id,
        decision=AuthorizationDecision.DENY,
        reason_codes=[ReasonCode.POLICY_DENIED, ReasonCode.CAPABILITY_MISMATCH],
        risk_score=30,
        checks=AuthorizationChecks(cedar=CheckStatus.DENY),
        agent_state=SecurityState.ACTIVE,
    )

    event = create_authorization_decision_event(request, result)
    json_str = event.model_dump_json()

    # Must be valid JSON
    parsed = json.loads(json_str)
    assert isinstance(parsed, dict)

    # Required fields and string enum values
    assert parsed["event_id"] == event.event_id
    assert parsed["event_type"] == "AUTHORIZATION_DECISION"
    assert parsed["source_agent"] == "research-01"
    assert parsed["target_agent"] == "research-01"
    assert parsed["action"] == "deployment.deploy"
    assert parsed["resource"] == "production-environment"
    assert parsed["policy_decision"] == "DENY"
    assert parsed["risk_score"] == 30
    assert parsed["reason_codes"] == ["POLICY_DENIED", "CAPABILITY_MISMATCH"]

    # Timestamp serializes as ISO-8601 string
    assert isinstance(parsed["timestamp"], str)
    datetime.fromisoformat(parsed["timestamp"].replace("Z", "+00:00"))


# ============================================================================
# TEST C: Unique Event IDs
# ============================================================================

def test_c_unique_event_ids():
    """
    TEST C — Unique event IDs
    Two generated events must never produce the same event_id.
    """
    request = _make_action_request()
    result = AuthorizationResult(
        request_id=request.request_id,
        decision=AuthorizationDecision.ALLOW,
        reason_codes=[],
        risk_score=0,
        checks=AuthorizationChecks(),
        agent_state=SecurityState.ACTIVE,
    )

    event1 = create_authorization_decision_event(request, result)
    event2 = create_authorization_decision_event(request, result)

    assert event1.event_id != event2.event_id
    assert len(event1.event_id) > 4
    assert len(event2.event_id) > 4


# ============================================================================
# TEST D: Timestamp Validity
# ============================================================================

def test_d_timestamp_validity():
    """
    TEST D — Timestamp
    Verify timestamp exists, is valid, and uses UTC timezone.
    """
    request = _make_action_request()
    result = AuthorizationResult(
        request_id=request.request_id,
        decision=AuthorizationDecision.ALLOW,
        reason_codes=[],
        risk_score=0,
        checks=AuthorizationChecks(),
        agent_state=SecurityState.ACTIVE,
    )

    before = datetime.now(timezone.utc)
    event = create_authorization_decision_event(request, result)
    after = datetime.now(timezone.utc)

    assert event.timestamp is not None
    assert event.timestamp.tzinfo is not None
    assert before <= event.timestamp <= after


# ============================================================================
# TEST E: ALLOW Event Creation
# ============================================================================

def test_e_allow_event_creation():
    """
    TEST E — ALLOW event
    Valid research request (research-01, research.search, research-data)
    Expected event:
    - event_type = AUTHORIZATION_DECISION
    - policy_decision = ALLOW
    - risk_score = 0
    """
    request = _make_action_request(
        source_agent=AgentId.RESEARCH_01,
        target_agent=AgentId.RESEARCH_01,
        action=ActionName.RESEARCH_SEARCH,
        resource=ResourceName.RESEARCH_DATA,
        capability=CapabilityName.RESEARCH_SEARCH,
    )

    captured_events: list[SecurityEvent] = []
    result = authorize(request, audit_writer=captured_events.append)

    assert result.decision == AuthorizationDecision.ALLOW
    assert len(captured_events) == 1

    event = captured_events[0]
    assert event.event_type == EventType.AUTHORIZATION_DECISION
    assert event.policy_decision == AuthorizationDecision.ALLOW
    assert event.risk_score == 0
    assert event.source_agent == AgentId.RESEARCH_01
    assert event.action == ActionName.RESEARCH_SEARCH
    assert event.resource == ResourceName.RESEARCH_DATA
    assert event.reason_codes == []


# ============================================================================
# TEST F: DENY Event Creation
# ============================================================================

def test_f_deny_event_creation():
    """
    TEST F — DENY event
    Research production deployment attempt:
    research-01 | deployment.deploy | production-environment | capability research.search
    Expected:
    - policy_decision = DENY
    - reason_codes contains the actual reasons returned by Kavach
    - risk_score matches the calculated deterministic score
    """
    request = _make_action_request(
        source_agent=AgentId.RESEARCH_01,
        target_agent=AgentId.DEPLOYMENT_01,
        action=ActionName.DEPLOYMENT_DEPLOY,
        resource=ResourceName.PRODUCTION_ENVIRONMENT,
        capability=CapabilityName.RESEARCH_SEARCH,
    )

    captured_events: list[SecurityEvent] = []
    result = authorize(request, audit_writer=captured_events.append)

    assert result.decision == AuthorizationDecision.DENY
    assert len(captured_events) == 1

    event = captured_events[0]
    assert event.event_type == EventType.AUTHORIZATION_DECISION
    assert event.policy_decision == AuthorizationDecision.DENY
    assert ReasonCode.POLICY_DENIED in event.reason_codes
    assert ReasonCode.CAPABILITY_MISMATCH in event.reason_codes
    assert ReasonCode.PRIVILEGE_ESCALATION in event.reason_codes
    assert event.risk_score == result.risk_score
    assert event.risk_score == 55


# ============================================================================
# TEST I: Cedar DENY Preserved Even With Low Risk
# ============================================================================

def test_i_cedar_deny_preserved_in_telemetry():
    """
    TEST I — Cedar DENY preserved
    Construct a Cedar-denied request with zero risk score.
    Verify telemetry records policy_decision = DENY.
    """
    class MockCedarDeny:
        def evaluate(self, req):
            return AuthorizationDecision.DENY

    request = _make_action_request(
        source_agent=AgentId.RESEARCH_01,
        target_agent=AgentId.RESEARCH_01,
        action=ActionName.RESEARCH_SEARCH,
        resource=ResourceName.RESEARCH_DATA,
        capability=CapabilityName.RESEARCH_SEARCH,
    )

    captured_events: list[SecurityEvent] = []
    result = authorize(
        request,
        cedar_adapter=MockCedarDeny(),
        audit_writer=captured_events.append,
    )

    assert result.decision == AuthorizationDecision.DENY
    assert len(captured_events) == 1

    event = captured_events[0]
    assert event.policy_decision == AuthorizationDecision.DENY
    assert ReasonCode.POLICY_DENIED in event.reason_codes
