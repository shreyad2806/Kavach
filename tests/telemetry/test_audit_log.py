"""
Tests for local audit log sink, JSONL file writing, and telemetry failure isolation.
"""

from datetime import datetime, timezone
import json
from pathlib import Path
import uuid

from fastapi.testclient import TestClient
import pytest

from shield.api.app import app
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
    DEFAULT_AUDIT_LOG_PATH,
    EventType,
    SecurityEvent,
    create_authorization_decision_event,
    write_event,
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
    """Helper to create a valid ActionRequest."""
    if delegation_chain is None:
        delegation_chain = [AgentId.ORCHESTRATOR_01, source_agent]
    return ActionRequest(
        request_id=f"req-{uuid.uuid4().hex[:8]}",
        timestamp=datetime.now(timezone.utc),
        source_agent=source_agent,
        target_agent=target_agent,
        task_id="task-audit-001",
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
# TEST G: Audit Log Write
# ============================================================================

def test_g_audit_log_write_single_event(tmp_path: Path):
    """
    TEST G — Audit log write
    Write one event.
    Read audit.log.
    Verify:
    - exactly one new line
    - line is valid JSON
    - parsed event matches original event
    """
    log_file = tmp_path / "audit.log"

    request = _make_action_request()
    result = AuthorizationResult(
        request_id=request.request_id,
        decision=AuthorizationDecision.ALLOW,
        reason_codes=[],
        risk_score=0,
        checks=AuthorizationChecks(),
        agent_state=SecurityState.ACTIVE,
    )

    event = create_authorization_decision_event(request, result)
    write_event(event, log_path=log_file)

    assert log_file.exists()

    with open(log_file, "r", encoding="utf-8") as f:
        lines = f.readlines()

    assert len(lines) == 1
    raw_line = lines[0].strip()

    parsed = json.loads(raw_line)
    assert parsed["event_id"] == event.event_id
    assert parsed["event_type"] == "AUTHORIZATION_DECISION"
    assert parsed["request_id"] == request.request_id
    assert parsed["policy_decision"] == "ALLOW"
    assert parsed["risk_score"] == 0
    assert parsed["reason_codes"] == []


# ============================================================================
# TEST H: Multiple Events
# ============================================================================

def test_h_audit_log_multiple_events(tmp_path: Path):
    """
    TEST H — Multiple events
    Perform two authorization requests.
    Verify two JSON lines exist.
    Each event must have a unique event_id.
    """
    log_file = tmp_path / "audit.log"

    # Request 1: Valid research search
    req1 = _make_action_request(
        source_agent=AgentId.RESEARCH_01,
        action=ActionName.RESEARCH_SEARCH,
        resource=ResourceName.RESEARCH_DATA,
        capability=CapabilityName.RESEARCH_SEARCH,
    )
    res1 = authorize(req1, audit_writer=lambda e: write_event(e, log_path=log_file))

    # Request 2: Attack deployment attempt
    req2 = _make_action_request(
        source_agent=AgentId.RESEARCH_01,
        target_agent=AgentId.DEPLOYMENT_01,
        action=ActionName.DEPLOYMENT_DEPLOY,
        resource=ResourceName.PRODUCTION_ENVIRONMENT,
        capability=CapabilityName.RESEARCH_SEARCH,
    )
    res2 = authorize(req2, audit_writer=lambda e: write_event(e, log_path=log_file))

    assert res1.decision == AuthorizationDecision.ALLOW
    assert res2.decision == AuthorizationDecision.DENY

    with open(log_file, "r", encoding="utf-8") as f:
        lines = [line.strip() for line in f if line.strip()]

    assert len(lines) == 2

    event1_data = json.loads(lines[0])
    event2_data = json.loads(lines[1])

    assert event1_data["event_id"] != event2_data["event_id"]
    assert event1_data["policy_decision"] == "ALLOW"
    assert event2_data["policy_decision"] == "DENY"
    assert event1_data["request_id"] == req1.request_id
    assert event2_data["request_id"] == req2.request_id


# ============================================================================
# TEST J: Telemetry Failure Isolation
# ============================================================================

def test_j_telemetry_failure_isolation():
    """
    TEST J — Telemetry failure isolation
    Force the audit writer to fail.
    Call authorize().
    Expected:
    - authorization decision is unchanged
    - telemetry failure does not convert ALLOW to DENY
    - telemetry failure does not convert DENY to ALLOW
    - no exception is raised out of authorize()
    """
    def failing_writer(event: SecurityEvent) -> None:
        raise IOError("Disk full or permission denied")

    # 1. ALLOW request with broken writer
    req_allow = _make_action_request(
        source_agent=AgentId.RESEARCH_01,
        action=ActionName.RESEARCH_SEARCH,
        resource=ResourceName.RESEARCH_DATA,
        capability=CapabilityName.RESEARCH_SEARCH,
    )
    result_allow = authorize(req_allow, audit_writer=failing_writer)

    # Decision must remain ALLOW despite telemetry failure
    assert result_allow.decision == AuthorizationDecision.ALLOW
    assert result_allow.reason_codes == []

    # 2. DENY request with broken writer
    req_deny = _make_action_request(
        source_agent=AgentId.RESEARCH_01,
        target_agent=AgentId.DEPLOYMENT_01,
        action=ActionName.DEPLOYMENT_DEPLOY,
        resource=ResourceName.PRODUCTION_ENVIRONMENT,
        capability=CapabilityName.RESEARCH_SEARCH,
    )
    result_deny = authorize(req_deny, audit_writer=failing_writer)

    # Decision must remain DENY despite telemetry failure
    assert result_deny.decision == AuthorizationDecision.DENY
    assert ReasonCode.POLICY_DENIED in result_deny.reason_codes


# ============================================================================
# TEST 14: End-to-End POST /authorize to Audit Log Correlation
# ============================================================================

def test_end_to_end_post_authorize_emits_telemetry(monkeypatch, tmp_path: Path):
    """
    TEST 14 — END-TO-END TEST
    Perform POST /authorize for research-01 deployment.deploy attempt.
    Verify:
    - HTTP response is 200 with decision DENY
    - audit.log contains a corresponding AUTHORIZATION_DECISION event
    - request_id, decision/policy_decision, risk_score, and reason_codes correlate
    """
    test_log = tmp_path / "audit.log"
    monkeypatch.setenv("KAVACH_AUDIT_LOG_PATH", str(test_log))

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

    # Verify audit log was created and contains correlated event
    assert test_log.exists()
    with open(test_log, "r", encoding="utf-8") as f:
        lines = [l.strip() for l in f if l.strip()]

    assert len(lines) >= 1

    # Find the matching event by request_id
    matched_event = None
    for line in lines:
        evt = json.loads(line)
        if evt.get("request_id") == body["request_id"]:
            matched_event = evt
            break

    assert matched_event is not None, f"Event with request_id {body['request_id']} not found in audit log"
    assert matched_event["event_type"] == "AUTHORIZATION_DECISION"
    assert matched_event["policy_decision"] == body["decision"]
    assert matched_event["risk_score"] == body["risk_score"]
    assert matched_event["reason_codes"] == body["reason_codes"]
    assert matched_event["source_agent"] == "research-01"
    assert matched_event["action"] == "deployment.deploy"
    assert matched_event["resource"] == "production-environment"
