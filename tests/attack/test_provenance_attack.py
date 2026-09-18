"""
Security Regression — Provenance Attack Tests.

Verifies the provenance validator catches:
  - chain/source mismatch
  - impossible delegation (research -> deployment)
  - delegation loops
  - forged authority
  - invalid chain root

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
        request_id = f"req-prov-{source_agent.value}"
    return ActionRequest(
        request_id=request_id,
        timestamp=datetime.now(timezone.utc),
        source_agent=source_agent,
        target_agent=target_agent,
        task_id="task-prov-attack",
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

class TestProvenanceAttacks:
    """Verify provenance validator catches structural delegation attacks."""

    def test_chain_source_mismatch(self):
        """Chain ends at coding-01 but source_agent is research-01 => PROVENANCE_ANOMALY."""
        request = _make_request(
            source_agent=AgentId.RESEARCH_01,
            delegation_chain=[AgentId.ORCHESTRATOR_01, AgentId.CODING_01],
            task_origin=AgentId.ORCHESTRATOR_01,
            claimed_authority=AgentId.ORCHESTRATOR_01,
        )
        result = validate_provenance(request)

        assert result.valid is False
        assert result.reason_code == ReasonCode.PROVENANCE_ANOMALY

    def test_impossible_delegation_research_to_deployment(self):
        """research-01 -> deployment-01 is not an allowed delegation => PROVENANCE_ANOMALY."""
        request = _make_request(
            source_agent=AgentId.DEPLOYMENT_01,
            delegation_chain=[AgentId.RESEARCH_01, AgentId.DEPLOYMENT_01],
            task_origin=AgentId.RESEARCH_01,
            claimed_authority=AgentId.RESEARCH_01,
        )
        result = validate_provenance(request)

        assert result.valid is False
        assert result.reason_code == ReasonCode.PROVENANCE_ANOMALY

    def test_delegation_loop(self):
        """Chain [orchestrator-01, research-01, orchestrator-01] has a loop => PROVENANCE_ANOMALY."""
        request = _make_request(
            source_agent=AgentId.ORCHESTRATOR_01,
            delegation_chain=[
                AgentId.ORCHESTRATOR_01,
                AgentId.RESEARCH_01,
                AgentId.ORCHESTRATOR_01,
            ],
            task_origin=AgentId.ORCHESTRATOR_01,
            claimed_authority=AgentId.RESEARCH_01,
        )
        result = validate_provenance(request)

        assert result.valid is False
        assert result.reason_code == ReasonCode.PROVENANCE_ANOMALY

    def test_invalid_chain_root_rejected_by_model(self):
        """Chain root != task_origin is rejected at the Provenance model boundary."""
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            Provenance(
                task_origin=AgentId.ORCHESTRATOR_01,
                delegation_chain=[AgentId.CODING_01, AgentId.RESEARCH_01],
            )

    def test_forged_authority_single_element(self):
        """Single-element chain with wrong claimed_authority => AUTHORITY_MISMATCH."""
        request = _make_request(
            source_agent=AgentId.RESEARCH_01,
            delegation_chain=[AgentId.RESEARCH_01],
            claimed_authority=AgentId.ORCHESTRATOR_01,
        )
        result = validate_provenance(request)

        assert result.valid is False
        assert result.reason_code == ReasonCode.AUTHORITY_MISMATCH

    def test_forged_authority_two_element_chain(self):
        """Two-element chain with wrong claimed_authority => AUTHORITY_MISMATCH."""
        request = _make_request(
            source_agent=AgentId.RESEARCH_01,
            delegation_chain=[AgentId.ORCHESTRATOR_01, AgentId.RESEARCH_01],
            task_origin=AgentId.ORCHESTRATOR_01,
            claimed_authority=AgentId.CODING_01,
        )
        result = validate_provenance(request)

        assert result.valid is False
        assert result.reason_code == ReasonCode.AUTHORITY_MISMATCH

    def test_valid_single_element_chain(self):
        """Single-element chain with matching claimed_authority is valid."""
        request = _make_request(
            source_agent=AgentId.RESEARCH_01,
            delegation_chain=[AgentId.RESEARCH_01],
            claimed_authority=AgentId.RESEARCH_01,
        )
        result = validate_provenance(request)

        assert result.valid is True
        assert result.reason_code is None

    def test_valid_delegation_chain(self):
        """Valid orchestrator-01 -> research-01 delegation chain is valid."""
        request = _make_request(
            source_agent=AgentId.RESEARCH_01,
            delegation_chain=[AgentId.ORCHESTRATOR_01, AgentId.RESEARCH_01],
            task_origin=AgentId.ORCHESTRATOR_01,
            claimed_authority=AgentId.ORCHESTRATOR_01,
        )
        result = validate_provenance(request)

        assert result.valid is True
        assert result.reason_code is None

    def test_provenance_failure_short_circuits_pipeline(self):
        """Provenance failure short-circuits the pipeline; Cedar never runs."""
        identity = IdentityService()
        request = _make_request(
            source_agent=AgentId.RESEARCH_01,
            delegation_chain=[AgentId.ORCHESTRATOR_01, AgentId.CODING_01],
            task_origin=AgentId.ORCHESTRATOR_01,
            claimed_authority=AgentId.ORCHESTRATOR_01,
            request_id="req-prov-sc",
        )
        result = authorize(request, identity_service=identity)

        assert result.decision == AuthorizationDecision.DENY
        assert ReasonCode.PROVENANCE_ANOMALY in result.reason_codes
        assert result.checks.provenance == CheckStatus.FAIL
        assert result.checks.cedar == CheckStatus.NOT_EVALUATED
