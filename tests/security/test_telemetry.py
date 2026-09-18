"""
Security Regression — Telemetry Tests.

Verifies that every completed authorization request produces exactly one
AUTHORIZATION_DECISION event with correct correlation to the pipeline result.

Uses existing Phase 15 telemetry implementation. No new logging system.
"""

from datetime import datetime, timezone
import json
from pathlib import Path
import uuid

import pytest

from shield.authorization.pipeline import authorize
from shield.capabilities.models import CapabilityName
from shield.gateway.models import (
    ActionName,
    ActionRequest,
    AuthorizationDecision,
    ReasonCode,
    RequestContext,
    ResourceName,
)
from shield.identity.models import AgentId, SecurityState
from shield.identity.service import IdentityService
from shield.provenance.models import Provenance
from shield.telemetry.events import (
    EventType,
    SecurityEvent,
    create_authorization_decision_event,
    write_event,
)


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
        request_id = f"req-tel-{uuid.uuid4().hex[:8]}"
    return ActionRequest(
        request_id=request_id,
        timestamp=datetime.now(timezone.utc),
        source_agent=source_agent,
        target_agent=target_agent,
        task_id="task-telemetry",
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

class TestSecurityTelemetry:
    """Verify telemetry event correlation with authorization pipeline results."""

    def test_allow_event_correlation(self, tmp_path: Path):
        """ALLOW request produces event with matching request_id, source_agent, decision."""
        log_file = tmp_path / "audit.log"
        identity = IdentityService()

        request = _make_request(
            source_agent=AgentId.RESEARCH_01,
            action=ActionName.RESEARCH_SEARCH,
            resource=ResourceName.RESEARCH_DATA,
            capability=CapabilityName.RESEARCH_SEARCH,
        )
        result = authorize(
            request,
            identity_service=identity,
            audit_writer=lambda e: write_event(e, log_path=log_file),
        )

        assert result.decision == AuthorizationDecision.ALLOW

        # Read audit log
        assert log_file.exists()
        with open(log_file, "r", encoding="utf-8") as f:
            lines = [l.strip() for l in f if l.strip()]

        assert len(lines) == 1
        event = json.loads(lines[0])

        assert event["event_type"] == "AUTHORIZATION_DECISION"
        assert event["request_id"] == request.request_id
        assert event["source_agent"] == "research-01"
        assert event["policy_decision"] == "ALLOW"
        assert event["reason_codes"] == []
        assert event["risk_score"] == 0

    def test_deny_event_correlation(self, tmp_path: Path):
        """DENY request produces event with matching request_id, source_agent, decision, reason_codes."""
        log_file = tmp_path / "audit.log"
        identity = IdentityService()

        request = _make_request(
            source_agent=AgentId.RESEARCH_01,
            target_agent=AgentId.DEPLOYMENT_01,
            action=ActionName.DEPLOYMENT_DEPLOY,
            resource=ResourceName.PRODUCTION_ENVIRONMENT,
            capability=CapabilityName.RESEARCH_SEARCH,
        )
        result = authorize(
            request,
            identity_service=identity,
            audit_writer=lambda e: write_event(e, log_path=log_file),
        )

        assert result.decision == AuthorizationDecision.DENY

        with open(log_file, "r", encoding="utf-8") as f:
            lines = [l.strip() for l in f if l.strip()]

        assert len(lines) == 1
        event = json.loads(lines[0])

        assert event["request_id"] == request.request_id
        assert event["source_agent"] == "research-01"
        assert event["policy_decision"] == "DENY"
        assert event["reason_codes"] == [c.value for c in result.reason_codes]
        assert event["risk_score"] == result.risk_score

    def test_exactly_one_event_per_request(self, tmp_path: Path):
        """Each authorize() call produces exactly one event."""
        log_file = tmp_path / "audit.log"
        identity = IdentityService()

        request = _make_request(
            source_agent=AgentId.RESEARCH_01,
            action=ActionName.RESEARCH_SEARCH,
            resource=ResourceName.RESEARCH_DATA,
            capability=CapabilityName.RESEARCH_SEARCH,
        )
        authorize(
            request,
            identity_service=identity,
            audit_writer=lambda e: write_event(e, log_path=log_file),
        )

        with open(log_file, "r", encoding="utf-8") as f:
            lines = [l.strip() for l in f if l.strip()]

        assert len(lines) == 1

    def test_event_request_id_matches_result(self, tmp_path: Path):
        """event.request_id == result.request_id."""
        log_file = tmp_path / "audit.log"
        identity = IdentityService()

        request = _make_request(
            source_agent=AgentId.RESEARCH_01,
            action=ActionName.RESEARCH_SEARCH,
            resource=ResourceName.RESEARCH_DATA,
            capability=CapabilityName.RESEARCH_SEARCH,
        )
        result = authorize(
            request,
            identity_service=identity,
            audit_writer=lambda e: write_event(e, log_path=log_file),
        )

        with open(log_file, "r", encoding="utf-8") as f:
            event = json.loads(f.readline().strip())

        assert event["request_id"] == result.request_id

    def test_event_source_agent_matches_request(self, tmp_path: Path):
        """event.source_agent == request.source_agent."""
        log_file = tmp_path / "audit.log"
        identity = IdentityService()

        request = _make_request(
            source_agent=AgentId.RESEARCH_01,
            action=ActionName.RESEARCH_SEARCH,
            resource=ResourceName.RESEARCH_DATA,
            capability=CapabilityName.RESEARCH_SEARCH,
        )
        authorize(
            request,
            identity_service=identity,
            audit_writer=lambda e: write_event(e, log_path=log_file),
        )

        with open(log_file, "r", encoding="utf-8") as f:
            event = json.loads(f.readline().strip())

        assert event["source_agent"] == request.source_agent.value

    def test_event_policy_decision_matches_result(self, tmp_path: Path):
        """event.policy_decision == result.decision."""
        log_file = tmp_path / "audit.log"
        identity = IdentityService()

        request = _make_request(
            source_agent=AgentId.RESEARCH_01,
            action=ActionName.RESEARCH_SEARCH,
            resource=ResourceName.RESEARCH_DATA,
            capability=CapabilityName.RESEARCH_SEARCH,
        )
        result = authorize(
            request,
            identity_service=identity,
            audit_writer=lambda e: write_event(e, log_path=log_file),
        )

        with open(log_file, "r", encoding="utf-8") as f:
            event = json.loads(f.readline().strip())

        assert event["policy_decision"] == result.decision.value

    def test_event_reason_codes_match_result(self, tmp_path: Path):
        """event.reason_codes == result.reason_codes."""
        log_file = tmp_path / "audit.log"
        identity = IdentityService()

        request = _make_request(
            source_agent=AgentId.RESEARCH_01,
            target_agent=AgentId.DEPLOYMENT_01,
            action=ActionName.DEPLOYMENT_DEPLOY,
            resource=ResourceName.PRODUCTION_ENVIRONMENT,
            capability=CapabilityName.RESEARCH_SEARCH,
        )
        result = authorize(
            request,
            identity_service=identity,
            audit_writer=lambda e: write_event(e, log_path=log_file),
        )

        with open(log_file, "r", encoding="utf-8") as f:
            event = json.loads(f.readline().strip())

        assert event["reason_codes"] == [c.value for c in result.reason_codes]

    def test_telemetry_failure_does_not_change_decision(self):
        """Broken audit writer does not alter authorization decision."""
        def failing_writer(event):
            raise IOError("Disk full")

        identity = IdentityService()

        # ALLOW with broken writer
        req_allow = _make_request(
            source_agent=AgentId.RESEARCH_01,
            action=ActionName.RESEARCH_SEARCH,
            resource=ResourceName.RESEARCH_DATA,
            capability=CapabilityName.RESEARCH_SEARCH,
        )
        result_allow = authorize(req_allow, identity_service=identity, audit_writer=failing_writer)
        assert result_allow.decision == AuthorizationDecision.ALLOW

        # DENY with broken writer
        req_deny = _make_request(
            source_agent=AgentId.RESEARCH_01,
            target_agent=AgentId.DEPLOYMENT_01,
            action=ActionName.DEPLOYMENT_DEPLOY,
            resource=ResourceName.PRODUCTION_ENVIRONMENT,
            capability=CapabilityName.RESEARCH_SEARCH,
        )
        result_deny = authorize(req_deny, identity_service=identity, audit_writer=failing_writer)
        assert result_deny.decision == AuthorizationDecision.DENY
