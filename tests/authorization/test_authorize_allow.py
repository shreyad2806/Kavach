"""
Authorization pipeline tests — successful ALLOW cases.

Tests that valid requests with correct identity, capability, provenance,
and Cedar policies result in ALLOW decisions.
"""

from datetime import datetime, timezone

import pytest

from shield.authorization.pipeline import authorize
from shield.gateway.models import (
    ActionName,
    ActionRequest,
    AuthorizationDecision,
    CapabilityName,
    CheckStatus,
    ResourceName,
)
from shield.identity.models import AgentId, SecurityState
from shield.provenance.models import Provenance


def _make_request(
    source_agent: AgentId,
    action: ActionName,
    resource: ResourceName,
    capability: CapabilityName,
) -> ActionRequest:
    """Helper to create a valid ActionRequest."""
    return ActionRequest(
        request_id=f"test-{source_agent.value}-{action.value}",
        timestamp=datetime.now(timezone.utc),
        source_agent=source_agent,
        target_agent=source_agent,
        task_id="task-test",
        action=action,
        resource=resource,
        claimed_authority=source_agent,
        capability=capability,
        provenance=Provenance(
            task_origin=source_agent,
            delegation_chain=[source_agent],
        ),
    )


# ============================================================================
# TEST 1 — Valid research request => ALLOW
# ============================================================================

def test_1_valid_research_request_allow():
    """research-01 | research.search | research-data | capability research.search => ALLOW."""
    request = _make_request(
        source_agent=AgentId.RESEARCH_01,
        action=ActionName.RESEARCH_SEARCH,
        resource=ResourceName.RESEARCH_DATA,
        capability=CapabilityName.RESEARCH_SEARCH,
    )
    result = authorize(request)

    assert result.decision == AuthorizationDecision.ALLOW
    assert result.request_id == request.request_id
    assert result.reason_codes == []
    assert result.checks.identity == CheckStatus.PASS
    assert result.checks.capability == CheckStatus.PASS
    assert result.checks.provenance == CheckStatus.PASS
    assert result.checks.cedar == CheckStatus.ALLOW
    assert result.checks.deterministic_rules == CheckStatus.PASS
    assert result.agent_state == SecurityState.ACTIVE


# ============================================================================
# TEST 8 — Valid coding request => ALLOW
# ============================================================================

def test_8_valid_coding_request_allow():
    """coding-01 | coding.write | workspace | capability coding.write => ALLOW."""
    request = _make_request(
        source_agent=AgentId.CODING_01,
        action=ActionName.CODING_WRITE,
        resource=ResourceName.WORKSPACE,
        capability=CapabilityName.CODING_WRITE,
    )
    result = authorize(request)

    assert result.decision == AuthorizationDecision.ALLOW
    assert result.checks.identity == CheckStatus.PASS
    assert result.checks.capability == CheckStatus.PASS
    assert result.checks.provenance == CheckStatus.PASS
    assert result.checks.cedar == CheckStatus.ALLOW
    assert result.checks.deterministic_rules == CheckStatus.PASS
    assert result.agent_state == SecurityState.ACTIVE


# ============================================================================
# TEST 9 — Valid deployment production request => ALLOW
# ============================================================================

def test_9_valid_deployment_production_request_allow():
    """deployment-01 | deployment.deploy | production-environment | capability deployment.production => ALLOW."""
    request = _make_request(
        source_agent=AgentId.DEPLOYMENT_01,
        action=ActionName.DEPLOYMENT_DEPLOY,
        resource=ResourceName.PRODUCTION_ENVIRONMENT,
        capability=CapabilityName.DEPLOYMENT_PRODUCTION,
    )
    result = authorize(request)

    assert result.decision == AuthorizationDecision.ALLOW
    assert result.checks.identity == CheckStatus.PASS
    assert result.checks.capability == CheckStatus.PASS
    assert result.checks.provenance == CheckStatus.PASS
    assert result.checks.cedar == CheckStatus.ALLOW
    assert result.checks.deterministic_rules == CheckStatus.PASS
    assert result.agent_state == SecurityState.ACTIVE
