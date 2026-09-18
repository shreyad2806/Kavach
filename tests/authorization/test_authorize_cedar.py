"""
Authorization pipeline tests — Cedar denials.

Tests that Cedar policy denials result in DENY and cannot be overridden.
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
    ReasonCode,
    ResourceName,
)
from shield.identity.models import AgentId, SecurityState
from shield.policy.cedar import CedarAdapter
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
# TEST 6 — Cedar denial => DENY with POLICY_DENIED
# ============================================================================

def test_6_cedar_denial_deny():
    """
    Cedar denial (research-01 attempting deployment.deploy) => DENY.
    The request passes identity, capability, and provenance but Cedar denies.
    """
    request = _make_request(
        source_agent=AgentId.RESEARCH_01,
        action=ActionName.DEPLOYMENT_DEPLOY,
        resource=ResourceName.PRODUCTION_ENVIRONMENT,
        capability=CapabilityName.RESEARCH_SEARCH,
    )

    result = authorize(request)

    assert result.decision == AuthorizationDecision.DENY
    assert ReasonCode.POLICY_DENIED in result.reason_codes
    assert result.checks.identity == CheckStatus.PASS
    assert result.checks.capability == CheckStatus.PASS
    assert result.checks.provenance == CheckStatus.PASS
    assert result.checks.cedar == CheckStatus.DENY


# ============================================================================
# TEST 7 — Critical invariant: Cedar DENY can NEVER become ALLOW
# ============================================================================

def test_7_cedar_deny_never_overridden():
    """
    CRITICAL: Cedar DENY can NEVER become ALLOW, even if deterministic
    rules would otherwise pass.
    """
    request = _make_request(
        source_agent=AgentId.RESEARCH_01,
        action=ActionName.DEPLOYMENT_DEPLOY,
        resource=ResourceName.PRODUCTION_ENVIRONMENT,
        capability=CapabilityName.RESEARCH_SEARCH,
    )

    result = authorize(request)

    # Cedar denied
    assert result.decision == AuthorizationDecision.DENY
    assert result.checks.cedar == CheckStatus.DENY
    assert ReasonCode.POLICY_DENIED in result.reason_codes

    # Even though deterministic_rules might pass (defense-in-depth check),
    # the overall decision must remain DENY
    assert result.decision != AuthorizationDecision.ALLOW


# ============================================================================
# TEST — Cedar denial short-circuits deterministic rules
# ============================================================================

def test_cedar_denial_prevents_allow():
    """
    When Cedar denies, the pipeline must not proceed to allow via
    deterministic rules.
    """
    cedar_adapter = CedarAdapter()

    request = _make_request(
        source_agent=AgentId.RESEARCH_01,
        action=ActionName.DEPLOYMENT_DEPLOY,
        resource=ResourceName.PRODUCTION_ENVIRONMENT,
        capability=CapabilityName.RESEARCH_SEARCH,
    )

    result = authorize(request, cedar_adapter=cedar_adapter)

    # Verify Cedar was evaluated and denied
    assert result.checks.cedar == CheckStatus.DENY

    # Verify the final decision is DENY (not overridden by rules)
    assert result.decision == AuthorizationDecision.DENY
    assert ReasonCode.POLICY_DENIED in result.reason_codes
