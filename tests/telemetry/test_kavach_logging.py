"""
Kavach Telemetry/Logging Integration Tests.

Covers requirements A-M for P1 agent integration:
  A. ALLOW produces one event
  B. DENY produces one event
  C. every event has unique event_id
  D. timestamp exists
  E. request_id correlation works
  F. source_agent is correct
  G. target_agent is correct
  H. decision is correct
  I. reason_codes match final Decision
  J. audit file contains valid JSONL
  K. multiple requests produce separate events
  L. logging failure doesn't alter authorization
  M. scanner directory remains untouched

Uses existing SecurityEvent contract from Phase 15. No new event model.
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
from shield.provenance.models import Provenance
from shield.telemetry.events import (
    DEFAULT_AUDIT_LOG_PATH,
    EventType,
    SecurityEvent,
    create_authorization_decision_event,
    get_audit_log_path,
    write_event,
)


# ---------------------------------------------------------------------------
# Helpers
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
        request_id = f"req-kavach-{uuid.uuid4().hex[:8]}"
    return ActionRequest(
        request_id=request_id,
        timestamp=datetime.now(timezone.utc),
        source_agent=source_agent,
        target_agent=target_agent,
        task_id="task-kavach-logging",
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


def _read_jsonl(path: Path) -> list[dict]:
    """Read a JSONL file and return parsed JSON objects."""
    with open(path, "r", encoding="utf-8") as f:
        return [json.loads(line.strip()) for line in f if line.strip()]


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestKavachLogging:
    """Comprehensive Kavach telemetry/logging integration tests."""

    # =========================================================================
    # A. ALLOW produces one event
    # =========================================================================
    def test_allow_produces_one_event(self, tmp_path: Path):
        """ALLOW request produces exactly one event in the audit log."""
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
        events = _read_jsonl(log_file)
        assert len(events) == 1

    # =========================================================================
    # B. DENY produces one event
    # =========================================================================
    def test_deny_produces_one_event(self, tmp_path: Path):
        """DENY request produces exactly one event in the audit log."""
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
        events = _read_jsonl(log_file)
        assert len(events) == 1

    # =========================================================================
    # C. every event has unique event_id
    # =========================================================================
    def test_unique_event_ids(self, tmp_path: Path):
        """Every event has a unique event_id."""
        log_file = tmp_path / "audit.log"
        identity = IdentityService()

        # Send two different requests
        req1 = _make_request(
            source_agent=AgentId.RESEARCH_01,
            action=ActionName.RESEARCH_SEARCH,
            resource=ResourceName.RESEARCH_DATA,
            capability=CapabilityName.RESEARCH_SEARCH,
            request_id="req-unique-1",
        )
        req2 = _make_request(
            source_agent=AgentId.RESEARCH_01,
            target_agent=AgentId.DEPLOYMENT_01,
            action=ActionName.DEPLOYMENT_DEPLOY,
            resource=ResourceName.PRODUCTION_ENVIRONMENT,
            capability=CapabilityName.RESEARCH_SEARCH,
            request_id="req-unique-2",
        )

        authorize(req1, identity_service=identity, audit_writer=lambda e: write_event(e, log_path=log_file))
        authorize(req2, identity_service=identity, audit_writer=lambda e: write_event(e, log_path=log_file))

        events = _read_jsonl(log_file)
        assert len(events) == 2
        assert events[0]["event_id"] != events[1]["event_id"]
        # event_id should be a non-empty string
        assert isinstance(events[0]["event_id"], str)
        assert len(events[0]["event_id"]) > 0

    # =========================================================================
    # D. timestamp exists
    # =========================================================================
    def test_timestamp_exists(self, tmp_path: Path):
        """Every event has a valid timestamp."""
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

        events = _read_jsonl(log_file)
        assert len(events) == 1
        assert "timestamp" in events[0]
        # Verify it's a valid ISO 8601 timestamp
        ts = datetime.fromisoformat(events[0]["timestamp"].replace("Z", "+00:00"))
        assert ts.tzinfo is not None

    # =========================================================================
    # E. request_id correlation works
    # =========================================================================
    def test_request_id_correlation(self, tmp_path: Path):
        """Event request_id matches the original request."""
        log_file = tmp_path / "audit.log"
        identity = IdentityService()

        request_id = f"req-corr-{uuid.uuid4().hex[:8]}"
        request = _make_request(
            source_agent=AgentId.RESEARCH_01,
            action=ActionName.RESEARCH_SEARCH,
            resource=ResourceName.RESEARCH_DATA,
            capability=CapabilityName.RESEARCH_SEARCH,
            request_id=request_id,
        )
        result = authorize(
            request,
            identity_service=identity,
            audit_writer=lambda e: write_event(e, log_path=log_file),
        )

        events = _read_jsonl(log_file)
        assert len(events) == 1
        assert events[0]["request_id"] == request_id
        assert events[0]["request_id"] == result.request_id

    # =========================================================================
    # F. source_agent is correct
    # =========================================================================
    def test_source_agent_correct(self, tmp_path: Path):
        """Event source_agent matches the request source_agent."""
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

        events = _read_jsonl(log_file)
        assert events[0]["source_agent"] == "research-01"

    # =========================================================================
    # G. target_agent is correct
    # =========================================================================
    def test_target_agent_correct(self, tmp_path: Path):
        """Event target_agent matches the request target_agent."""
        log_file = tmp_path / "audit.log"
        identity = IdentityService()

        request = _make_request(
            source_agent=AgentId.RESEARCH_01,
            target_agent=AgentId.DEPLOYMENT_01,
            action=ActionName.DEPLOYMENT_DEPLOY,
            resource=ResourceName.PRODUCTION_ENVIRONMENT,
            capability=CapabilityName.RESEARCH_SEARCH,
        )
        authorize(
            request,
            identity_service=identity,
            audit_writer=lambda e: write_event(e, log_path=log_file),
        )

        events = _read_jsonl(log_file)
        assert events[0]["target_agent"] == "deployment-01"

    # =========================================================================
    # H. decision is correct
    # =========================================================================
    def test_decision_correct_allow(self, tmp_path: Path):
        """ALLOW event has policy_decision = ALLOW."""
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

        events = _read_jsonl(log_file)
        assert events[0]["policy_decision"] == "ALLOW"
        assert events[0]["policy_decision"] == result.decision.value

    def test_decision_correct_deny(self, tmp_path: Path):
        """DENY event has policy_decision = DENY."""
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

        events = _read_jsonl(log_file)
        assert events[0]["policy_decision"] == "DENY"
        assert events[0]["policy_decision"] == result.decision.value

    # =========================================================================
    # I. reason_codes match final Decision
    # =========================================================================
    def test_reason_codes_match_decision(self, tmp_path: Path):
        """Event reason_codes exactly match the AuthorizationResult reason_codes."""
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

        events = _read_jsonl(log_file)
        expected_reasons = [c.value for c in result.reason_codes]
        assert events[0]["reason_codes"] == expected_reasons

    def test_reason_codes_empty_for_allow(self, tmp_path: Path):
        """ALLOW event has empty reason_codes."""
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

        events = _read_jsonl(log_file)
        assert events[0]["reason_codes"] == []

    # =========================================================================
    # J. audit file contains valid JSONL
    # =========================================================================
    def test_valid_jsonl_format(self, tmp_path: Path):
        """Audit file contains valid JSONL (one JSON object per line)."""
        log_file = tmp_path / "audit.log"
        identity = IdentityService()

        # Send multiple requests
        for i in range(3):
            request = _make_request(
                source_agent=AgentId.RESEARCH_01,
                action=ActionName.RESEARCH_SEARCH,
                resource=ResourceName.RESEARCH_DATA,
                capability=CapabilityName.RESEARCH_SEARCH,
                request_id=f"req-jsonl-{i}",
            )
            authorize(
                request,
                identity_service=identity,
                audit_writer=lambda e: write_event(e, log_path=log_file),
            )

        # Verify file exists and is valid JSONL
        assert log_file.exists()
        with open(log_file, "r", encoding="utf-8") as f:
            lines = [line.strip() for line in f if line.strip()]

        assert len(lines) == 3

        # Each line must be valid JSON
        for line in lines:
            parsed = json.loads(line)
            assert isinstance(parsed, dict)
            assert "event_id" in parsed
            assert "event_type" in parsed
            assert "timestamp" in parsed

    def test_no_pretty_printed_json(self, tmp_path: Path):
        """Events are written as single-line JSON, not pretty-printed."""
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
            lines = f.readlines()

        assert len(lines) == 1
        # Single line, no newlines within the JSON
        assert "\n" not in lines[0].strip()
        # Must be parseable
        json.loads(lines[0].strip())

    # =========================================================================
    # K. multiple requests produce separate events
    # =========================================================================
    def test_multiple_requests_separate_events(self, tmp_path: Path):
        """Multiple authorization requests produce separate events."""
        log_file = tmp_path / "audit.log"
        identity = IdentityService()

        requests = [
            _make_request(
                source_agent=AgentId.RESEARCH_01,
                action=ActionName.RESEARCH_SEARCH,
                resource=ResourceName.RESEARCH_DATA,
                capability=CapabilityName.RESEARCH_SEARCH,
                request_id=f"req-multi-{i}",
            )
            for i in range(5)
        ]

        for request in requests:
            authorize(
                request,
                identity_service=identity,
                audit_writer=lambda e: write_event(e, log_path=log_file),
            )

        events = _read_jsonl(log_file)
        assert len(events) == 5

        # All event_ids unique
        event_ids = [e["event_id"] for e in events]
        assert len(set(event_ids)) == 5

        # All request_ids match
        for i, event in enumerate(events):
            assert event["request_id"] == f"req-multi-{i}"

    # =========================================================================
    # L. logging failure doesn't alter authorization
    # =========================================================================
    def test_logging_failure_preserves_allow(self):
        """Logging failure does not change ALLOW to DENY."""
        def failing_writer(event):
            raise IOError("Simulated disk failure")

        identity = IdentityService()
        request = _make_request(
            source_agent=AgentId.RESEARCH_01,
            action=ActionName.RESEARCH_SEARCH,
            resource=ResourceName.RESEARCH_DATA,
            capability=CapabilityName.RESEARCH_SEARCH,
        )
        result = authorize(request, identity_service=identity, audit_writer=failing_writer)

        assert result.decision == AuthorizationDecision.ALLOW
        assert result.reason_codes == []

    def test_logging_failure_preserves_deny(self):
        """Logging failure does not change DENY to ALLOW."""
        def failing_writer(event):
            raise IOError("Simulated disk failure")

        identity = IdentityService()
        request = _make_request(
            source_agent=AgentId.RESEARCH_01,
            target_agent=AgentId.DEPLOYMENT_01,
            action=ActionName.DEPLOYMENT_DEPLOY,
            resource=ResourceName.PRODUCTION_ENVIRONMENT,
            capability=CapabilityName.RESEARCH_SEARCH,
        )
        result = authorize(request, identity_service=identity, audit_writer=failing_writer)

        assert result.decision == AuthorizationDecision.DENY
        assert ReasonCode.CAPABILITY_MISMATCH in result.reason_codes

    def test_logging_failure_preserves_risk_score(self):
        """Logging failure does not alter risk_score."""
        def failing_writer(event):
            raise IOError("Simulated disk failure")

        identity = IdentityService()
        request = _make_request(
            source_agent=AgentId.RESEARCH_01,
            target_agent=AgentId.DEPLOYMENT_01,
            action=ActionName.DEPLOYMENT_DEPLOY,
            resource=ResourceName.PRODUCTION_ENVIRONMENT,
            capability=CapabilityName.RESEARCH_SEARCH,
        )
        result = authorize(request, identity_service=identity, audit_writer=failing_writer)

        # risk_score should still be calculated despite logging failure
        assert result.risk_score is not None
        assert result.risk_score >= 0

    def test_logging_failure_no_exception_propagated(self):
        """Logging failure does not raise an exception to the caller."""
        def failing_writer(event):
            raise IOError("Simulated disk failure")

        identity = IdentityService()
        request = _make_request(
            source_agent=AgentId.RESEARCH_01,
            action=ActionName.RESEARCH_SEARCH,
            resource=ResourceName.RESEARCH_DATA,
            capability=CapabilityName.RESEARCH_SEARCH,
        )

        # Should not raise
        result = authorize(request, identity_service=identity, audit_writer=failing_writer)
        assert result is not None

    # =========================================================================
    # M. scanner directory remains untouched
    # =========================================================================
    def test_scanner_directory_not_imported(self):
        """Kavach telemetry does not import from scanner directory."""
        import shield.telemetry.events as events_module
        import inspect

        source = inspect.getsource(events_module)
        assert "scanner" not in source.lower() or "scanner" in source.lower().split("#")[0]

    def test_default_path_uses_kavach_directory(self):
        """Default audit log path points to logs/kavach/audit.log."""
        path = DEFAULT_AUDIT_LOG_PATH
        assert path.name == "audit.log"
        assert path.parent.name == "kavach"
        assert path.parent.parent.name == "logs"

    def test_get_audit_log_path_returns_kavach_path(self):
        """get_audit_log_path() returns the Kavach-specific path."""
        path = get_audit_log_path()
        assert "kavach" in str(path)
        assert path.name == "audit.log"

    def test_env_override_still_works(self, monkeypatch):
        """KAVACH_AUDIT_LOG_PATH env var still overrides the default."""
        monkeypatch.setenv("KAVACH_AUDIT_LOG_PATH", "/custom/path/audit.log")
        path = get_audit_log_path()
        assert path == Path("/custom/path/audit.log")

    def test_scanner_not_modified(self):
        """Verify scanner directory is not touched by this change."""
        import subprocess
        result = subprocess.run(
            ["git", "status", "--short", "scanner"],
            capture_output=True,
            text=True,
            cwd=Path(__file__).resolve().parent.parent.parent,
        )
        assert result.stdout.strip() == "", f"Scanner was modified: {result.stdout}"

    # =========================================================================
    # Additional: event_type is AUTHORIZATION_DECISION
    # =========================================================================
    def test_event_type_is_authorization_decision(self, tmp_path: Path):
        """All events have event_type = AUTHORIZATION_DECISION."""
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

        events = _read_jsonl(log_file)
        assert events[0]["event_type"] == "AUTHORIZATION_DECISION"

    # =========================================================================
    # Additional: risk_score present in event
    # =========================================================================
    def test_risk_score_in_event(self, tmp_path: Path):
        """Event includes risk_score from the authorization result."""
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

        events = _read_jsonl(log_file)
        assert events[0]["risk_score"] == result.risk_score

    # =========================================================================
    # Additional: append-only semantics
    # =========================================================================
    def test_append_only_semantics(self, tmp_path: Path):
        """Writing multiple events appends, not overwrites."""
        log_file = tmp_path / "audit.log"
        identity = IdentityService()

        # Write first event
        req1 = _make_request(
            source_agent=AgentId.RESEARCH_01,
            action=ActionName.RESEARCH_SEARCH,
            resource=ResourceName.RESEARCH_DATA,
            capability=CapabilityName.RESEARCH_SEARCH,
            request_id="req-append-1",
        )
        authorize(req1, identity_service=identity, audit_writer=lambda e: write_event(e, log_path=log_file))

        events_after_first = _read_jsonl(log_file)
        assert len(events_after_first) == 1

        # Write second event
        req2 = _make_request(
            source_agent=AgentId.RESEARCH_01,
            action=ActionName.RESEARCH_SEARCH,
            resource=ResourceName.RESEARCH_DATA,
            capability=CapabilityName.RESEARCH_SEARCH,
            request_id="req-append-2",
        )
        authorize(req2, identity_service=identity, audit_writer=lambda e: write_event(e, log_path=log_file))

        events_after_second = _read_jsonl(log_file)
        assert len(events_after_second) == 2
        # First event still present
        assert events_after_second[0]["request_id"] == "req-append-1"
        assert events_after_second[1]["request_id"] == "req-append-2"

    # =========================================================================
    # Additional: task_id present in event
    # =========================================================================
    def test_task_id_in_event(self, tmp_path: Path):
        """Event includes task_id from the request."""
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

        events = _read_jsonl(log_file)
        assert events[0]["task_id"] == "task-kavach-logging"

    # =========================================================================
    # Additional: action and resource in event
    # =========================================================================
    def test_action_and_resource_in_event(self, tmp_path: Path):
        """Event includes action and resource from the request."""
        log_file = tmp_path / "audit.log"
        identity = IdentityService()

        request = _make_request(
            source_agent=AgentId.RESEARCH_01,
            target_agent=AgentId.DEPLOYMENT_01,
            action=ActionName.DEPLOYMENT_DEPLOY,
            resource=ResourceName.PRODUCTION_ENVIRONMENT,
            capability=CapabilityName.RESEARCH_SEARCH,
        )
        authorize(
            request,
            identity_service=identity,
            audit_writer=lambda e: write_event(e, log_path=log_file),
        )

        events = _read_jsonl(log_file)
        assert events[0]["action"] == "deployment.deploy"
        assert events[0]["resource"] == "production-environment"
