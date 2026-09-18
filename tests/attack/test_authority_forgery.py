"""
Security Regression — Authority Forgery Tests.

Verifies that research-01 claiming false authority (e.g., orchestrator-01)
is caught by the provenance validator, and that the pipeline short-circuits
at provenance before detection runs.

Each test gets fresh services. No state leakage.
"""

from datetime import datetime, timezone

import pytest

from shield.authorization.pipeline import authorize
from shield.capabilities.models import CapabilityName
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
from shield.provenance.validator import validate_provenance
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
        request_id = f"req-auth-{source_agent.value}-{action.value}"
    return ActionRequest(
        request_id=request_id,
        timestamp=datetime.now(timezone.utc),
        source_agent=source_agent,
        target_agent=target_agent,
        task_id="task-auth-forgery",
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

class TestAuthorityForgery:
    """Verify authority forgery is caught by provenance validation."""

    def test_single_element_chain_forged_authority_denied(self):
        """research-01 claiming orchestrator-01 with single-element chain => DENY."""
        identity = IdentityService()
        request = _make_request(
            source_agent=AgentId.RESEARCH_01,
            claimed_authority=AgentId.ORCHESTRATOR_01,
            delegation_chain=[AgentId.RESEARCH_01],
            request_id="req-forgery-single",
        )
        result = authorize(request, identity_service=identity)

        assert result.decision == AuthorizationDecision.DENY
        assert ReasonCode.AUTHORITY_MISMATCH in result.reason_codes

    def test_provenance_validator_catches_forgery(self):
        """validate_provenance returns AUTHORITY_MISMATCH for forged authority."""
        request = _make_request(
            source_agent=AgentId.RESEARCH_01,
            claimed_authority=AgentId.ORCHESTRATOR_01,
            delegation_chain=[AgentId.RESEARCH_01],
        )
        result = validate_provenance(request)

        assert result.valid is False
        assert result.reason_code == ReasonCode.AUTHORITY_MISMATCH

    def test_forgery_short_circuits_pipeline(self):
        """Authority forgery short-circuits at provenance; Cedar never runs."""
        identity = IdentityService()
        request = _make_request(
            source_agent=AgentId.RESEARCH_01,
            claimed_authority=AgentId.ORCHESTRATOR_01,
            delegation_chain=[AgentId.RESEARCH_01],
            request_id="req-forgery-sc",
        )
        result = authorize(request, identity_service=identity)

        assert result.checks.provenance == CheckStatus.FAIL
        assert result.checks.cedar == CheckStatus.NOT_EVALUATED

    def test_forgery_risk_score(self):
        """Authority forgery produces risk=25 (AUTHORITY_MISMATCH weight)."""
        identity = IdentityService()
        request = _make_request(
            source_agent=AgentId.RESEARCH_01,
            claimed_authority=AgentId.ORCHESTRATOR_01,
            delegation_chain=[AgentId.RESEARCH_01],
        )
        result = authorize(request, identity_service=identity)

        assert result.risk_score == 25

    def test_forgery_no_detection_signals(self):
        """Authority forgery does not produce detection signals (short-circuits)."""
        identity = IdentityService()
        request = _make_request(
            source_agent=AgentId.RESEARCH_01,
            claimed_authority=AgentId.ORCHESTRATOR_01,
            delegation_chain=[AgentId.RESEARCH_01],
        )
        result = authorize(request, identity_service=identity)

        assert ReasonCode.CAPABILITY_MISMATCH not in result.reason_codes
        assert ReasonCode.PRIVILEGE_ESCALATION not in result.reason_codes
        assert ReasonCode.SUSPICIOUS_BEHAVIOR not in result.reason_codes

    def test_valid_delegation_not_forgery(self):
        """Valid orchestrator-01 -> research-01 delegation is NOT a forgery."""
        identity = IdentityService()
        request = _make_request(
            source_agent=AgentId.RESEARCH_01,
            claimed_authority=AgentId.ORCHESTRATOR_01,
            task_origin=AgentId.ORCHESTRATOR_01,
            delegation_chain=[AgentId.ORCHESTRATOR_01, AgentId.RESEARCH_01],
        )
        result = authorize(request, identity_service=identity)

        assert ReasonCode.AUTHORITY_MISMATCH not in result.reason_codes
        assert result.checks.provenance == CheckStatus.PASS

    def test_self_authority_single_element_chain_valid(self):
        """research-01 claiming its own authority with single-element chain is valid."""
        identity = IdentityService()
        request = _make_request(
            source_agent=AgentId.RESEARCH_01,
            claimed_authority=AgentId.RESEARCH_01,
            delegation_chain=[AgentId.RESEARCH_01],
        )
        result = authorize(request, identity_service=identity)

        assert ReasonCode.AUTHORITY_MISMATCH not in result.reason_codes
        assert result.checks.provenance == CheckStatus.PASS
