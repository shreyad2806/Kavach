"""
Tests for Quarantine (Phase 17).

Quarantine transitions an agent to QUARANTINED security state.
After quarantine, EVERY subsequent authorization request from that agent
must automatically return DENY with AGENT_QUARANTINED reason code.
"""

from datetime import datetime, timezone
import uuid

import pytest

from shield.authorization.pipeline import authorize
from shield.capabilities.models import CapabilityName
from shield.enforcement.quarantine import QuarantineService
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
    """Helper to create a valid ActionRequest for quarantine testing."""
    if delegation_chain is None:
        delegation_chain = [AgentId.ORCHESTRATOR_01, source_agent]
    return ActionRequest(
        request_id=f"req-{uuid.uuid4().hex[:8]}",
        timestamp=datetime.now(timezone.utc),
        source_agent=source_agent,
        target_agent=target_agent,
        task_id="task-quarantine-001",
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
# TEST A: Quarantine Active Agent
# ============================================================================

def test_a_quarantine_active_agent():
    """
    TEST A — Quarantine active agent
    Initial:
        research-01 = ACTIVE

    Call:
        quarantine_agent("research-01")

    Expected:
        research-01 = QUARANTINED
    """
    identity_service = IdentityService()
    quarantine_service = QuarantineService(identity_service)

    # Verify initial state
    agent = identity_service.get_agent(AgentId.RESEARCH_01)
    assert agent is not None
    assert agent.state == SecurityState.ACTIVE

    # Quarantine the agent
    quarantine_service.quarantine(AgentId.RESEARCH_01)

    # Verify state changed
    agent = identity_service.get_agent(AgentId.RESEARCH_01)
    assert agent is not None
    assert agent.state == SecurityState.QUARANTINED


# ============================================================================
# TEST B: Identity Remains Valid
# ============================================================================

def test_b_identity_remains_valid():
    """
    TEST B — Identity remains valid
    After quarantine:
        get_agent("research-01")
    must still return a valid AgentIdentity.

    Expected:
        agent_id = research-01
        state = QUARANTINED
    """
    identity_service = IdentityService()
    quarantine_service = QuarantineService(identity_service)

    # Quarantine the agent
    quarantine_service.quarantine(AgentId.RESEARCH_01)

    # Get agent identity
    agent = identity_service.get_agent(AgentId.RESEARCH_01)

    # Verify identity is still valid
    assert agent is not None
    assert agent.agent_id == AgentId.RESEARCH_01
    assert agent.state == SecurityState.QUARANTINED


# ============================================================================
# TEST C: Unknown Agent
# ============================================================================

def test_c_unknown_agent():
    """
    TEST C — Unknown agent
    Attempt:
        quarantine_agent("unknown-agent")

    Expected:
    - no new identity
    - existing registry unchanged
    - deterministic failure/result
    """
    identity_service = IdentityService()
    quarantine_service = QuarantineService(identity_service)

    # Count agents before
    agents_before = identity_service.list_agents()
    count_before = len(agents_before)

    # Attempt to quarantine unknown agent
    with pytest.raises(KeyError):
        quarantine_service.quarantine("unknown-agent")

    # Verify no new identity was created
    agents_after = identity_service.list_agents()
    count_after = len(agents_after)
    assert count_before == count_after


# ============================================================================
# TEST D: Idempotent Quarantine
# ============================================================================

def test_d_idempotent_quarantine():
    """
    TEST D — Idempotent quarantine
    Call:
        quarantine_agent("research-01")
        quarantine_agent("research-01")

    Expected:
        research-01 = QUARANTINED

    It must never return to ACTIVE.
    """
    identity_service = IdentityService()
    quarantine_service = QuarantineService(identity_service)

    # First quarantine
    quarantine_service.quarantine(AgentId.RESEARCH_01)

    # Second quarantine (idempotent)
    quarantine_service.quarantine(AgentId.RESEARCH_01)

    # Verify state is still QUARANTINED
    agent = identity_service.get_agent(AgentId.RESEARCH_01)
    assert agent is not None
    assert agent.state == SecurityState.QUARANTINED


# ============================================================================
# TEST E: Previously Allowed Action Becomes Denied
# ============================================================================

def test_e_previously_allowed_action_becomes_denied():
    """
    TEST E — Previously allowed action becomes denied
    Before quarantine:
        research-01
        action = research.search
        resource = research-data
        capability = research.search

    Expected:
        ALLOW

    Then quarantine research-01.

    Repeat the exact same request.

    Expected:
        DENY
        AGENT_QUARANTINED

    This is a critical test.
    """
    identity_service = IdentityService()

    # Request #1: Before quarantine
    request1 = _make_action_request(
        source_agent=AgentId.RESEARCH_01,
        action=ActionName.RESEARCH_SEARCH,
        resource=ResourceName.RESEARCH_DATA,
        capability=CapabilityName.RESEARCH_SEARCH,
    )
    result1 = authorize(request1, identity_service=identity_service)

    # Should be ALLOW
    assert result1.decision == AuthorizationDecision.ALLOW

    # Quarantine research-01
    quarantine_service = QuarantineService(identity_service)
    quarantine_service.quarantine(AgentId.RESEARCH_01)

    # Request #2: After quarantine (same request)
    request2 = _make_action_request(
        source_agent=AgentId.RESEARCH_01,
        action=ActionName.RESEARCH_SEARCH,
        resource=ResourceName.RESEARCH_DATA,
        capability=CapabilityName.RESEARCH_SEARCH,
    )
    result2 = authorize(request2, identity_service=identity_service)

    # Should be DENY with AGENT_QUARANTINED
    assert result2.decision == AuthorizationDecision.DENY
    assert ReasonCode.AGENT_QUARANTINED in result2.reason_codes


# ============================================================================
# TEST F: Quarantine Blocks Multiple Actions
# ============================================================================

def test_f_quarantine_blocks_multiple_actions():
    """
    TEST F — Quarantine blocks multiple actions
    After quarantine, test at least:
        research.search
        research.read

    Both must return:
        DENY
        AGENT_QUARANTINED

    The implementation must not only block one specific action.
    """
    identity_service = IdentityService()
    quarantine_service = QuarantineService(identity_service)

    # Quarantine research-01
    quarantine_service.quarantine(AgentId.RESEARCH_01)

    # Test research.search
    request1 = _make_action_request(
        source_agent=AgentId.RESEARCH_01,
        action=ActionName.RESEARCH_SEARCH,
        resource=ResourceName.RESEARCH_DATA,
        capability=CapabilityName.RESEARCH_SEARCH,
    )
    result1 = authorize(request1, identity_service=identity_service)
    assert result1.decision == AuthorizationDecision.DENY
    assert ReasonCode.AGENT_QUARANTINED in result1.reason_codes

    # Test research.read
    request2 = _make_action_request(
        source_agent=AgentId.RESEARCH_01,
        action=ActionName.RESEARCH_READ,
        resource=ResourceName.RESEARCH_DATA,
        capability=CapabilityName.RESEARCH_SEARCH,
    )
    result2 = authorize(request2, identity_service=identity_service)
    assert result2.decision == AuthorizationDecision.DENY
    assert ReasonCode.AGENT_QUARANTINED in result2.reason_codes


# ============================================================================
# TEST G: Quarantine Blocks Even Valid Cedar Authorization
# ============================================================================

def test_g_quarantine_blocks_even_valid_cedar_authorization():
    """
    TEST G — Quarantine blocks even valid Cedar authorization
    Use an action/resource pair that Cedar normally permits.

    Example:
        research.search
        research-data

    Before quarantine:
        Cedar = ALLOW

    After quarantine:
        final decision = DENY
        reason_codes includes AGENT_QUARANTINED

    Cedar must NOT override quarantine.
    """
    identity_service = IdentityService()

    # Verify Cedar normally allows this request
    request = _make_action_request(
        source_agent=AgentId.RESEARCH_01,
        action=ActionName.RESEARCH_SEARCH,
        resource=ResourceName.RESEARCH_DATA,
        capability=CapabilityName.RESEARCH_SEARCH,
    )
    result_before = authorize(request, identity_service=identity_service)
    assert result_before.decision == AuthorizationDecision.ALLOW

    # Quarantine research-01
    quarantine_service = QuarantineService(identity_service)
    quarantine_service.quarantine(AgentId.RESEARCH_01)

    # Same request after quarantine
    result_after = authorize(request, identity_service=identity_service)
    assert result_after.decision == AuthorizationDecision.DENY
    assert ReasonCode.AGENT_QUARANTINED in result_after.reason_codes


# ============================================================================
# TEST H: Quarantine Short-Circuits Pipeline
# ============================================================================

def test_h_quarantine_short_circuits_pipeline():
    """
    TEST H — Quarantine short-circuits pipeline
    For a quarantined agent verify:
        identity = PASS
        agent_state = FAIL
        capability = NOT_EVALUATED
        provenance = NOT_EVALUATED
        cedar = NOT_EVALUATED

    Use the project's existing check representation.
    Do not execute unnecessary authorization checks after quarantine.
    """
    identity_service = IdentityService()
    quarantine_service = QuarantineService(identity_service)

    # Quarantine research-01
    quarantine_service.quarantine(AgentId.RESEARCH_01)

    # Make a request
    request = _make_action_request(
        source_agent=AgentId.RESEARCH_01,
        action=ActionName.RESEARCH_SEARCH,
        resource=ResourceName.RESEARCH_DATA,
        capability=CapabilityName.RESEARCH_SEARCH,
    )
    result = authorize(request, identity_service=identity_service)

    # Verify pipeline short-circuited
    assert result.decision == AuthorizationDecision.DENY
    assert result.checks.identity == CheckStatus.PASS
    assert result.checks.agent_state == CheckStatus.FAIL
    assert result.checks.capability == CheckStatus.NOT_EVALUATED
    assert result.checks.provenance == CheckStatus.NOT_EVALUATED
    assert result.checks.cedar == CheckStatus.NOT_EVALUATED
    assert result.checks.deterministic_rules == CheckStatus.NOT_EVALUATED


# ============================================================================
# TEST I: Risk Score Does Not Override Quarantine
# ============================================================================

def test_i_risk_score_does_not_override_quarantine():
    """
    TEST I — Risk score does not override quarantine
    Create a quarantined request with:
        risk_score = 0

    Expected:
        DENY
        AGENT_QUARANTINED

    Do not allow low risk to bypass quarantine.
    """
    identity_service = IdentityService()
    quarantine_service = QuarantineService(identity_service)

    # Quarantine research-01
    quarantine_service.quarantine(AgentId.RESEARCH_01)

    # Make a request
    request = _make_action_request(
        source_agent=AgentId.RESEARCH_01,
        action=ActionName.RESEARCH_SEARCH,
        resource=ResourceName.RESEARCH_DATA,
        capability=CapabilityName.RESEARCH_SEARCH,
    )
    result = authorize(request, identity_service=identity_service)

    # Verify DENY despite any risk score
    assert result.decision == AuthorizationDecision.DENY
    assert ReasonCode.AGENT_QUARANTINED in result.reason_codes


# ============================================================================
# TEST J: Decision Invariance
# ============================================================================

def test_j_decision_invariance():
    """
    TEST J — Decision invariance
    Verify:
        quarantine_agent()
    does not directly modify an already-created Decision object.

    Quarantine changes agent state.
    Authorization evaluates that state on subsequent requests.
    """
    identity_service = IdentityService()

    # Create a decision BEFORE quarantine
    request = _make_action_request(
        source_agent=AgentId.RESEARCH_01,
        action=ActionName.RESEARCH_SEARCH,
        resource=ResourceName.RESEARCH_DATA,
        capability=CapabilityName.RESEARCH_SEARCH,
    )
    result_before = authorize(request, identity_service=identity_service)

    # Store original decision
    original_decision = result_before.decision
    original_reason_codes = list(result_before.reason_codes)

    # Quarantine research-01
    quarantine_service = QuarantineService(identity_service)
    quarantine_service.quarantine(AgentId.RESEARCH_01)

    # Verify the original result object is unchanged
    assert result_before.decision == original_decision
    assert result_before.reason_codes == original_reason_codes

    # Verify NEW request gets DENIED
    result_after = authorize(request, identity_service=identity_service)
    assert result_after.decision == AuthorizationDecision.DENY
    assert ReasonCode.AGENT_QUARANTINED in result_after.reason_codes


# ============================================================================
# TEST K: End-to-End Demo Test
# ============================================================================

def test_k_end_to_end_demo():
    """
    TEST K — End-to-end demo test

    Scenario:
    1. research-01 is ACTIVE
    2. research-01 sends valid research.search request
    3. Request is ALLOWED
    4. security layer quarantines research-01
    5. research-01 sends the SAME valid research.search request again
    6. Request is DENIED

    Expected final sequence:
        REQUEST #1
        ALLOW

        QUARANTINE
        research-01 -> QUARANTINED

        REQUEST #2
        DENY
        AGENT_QUARANTINED

    This is the primary Phase 17 demo test.
    """
    identity_service = IdentityService()

    # STEP 1: Verify research-01 is ACTIVE
    agent = identity_service.get_agent(AgentId.RESEARCH_01)
    assert agent is not None
    assert agent.state == SecurityState.ACTIVE
    print("\n✓ STEP 1: research-01 is ACTIVE")

    # STEP 2: Send valid research request
    request = _make_action_request(
        source_agent=AgentId.RESEARCH_01,
        action=ActionName.RESEARCH_SEARCH,
        resource=ResourceName.RESEARCH_DATA,
        capability=CapabilityName.RESEARCH_SEARCH,
    )
    result1 = authorize(request, identity_service=identity_service)

    # STEP 3: Verify ALLOW
    assert result1.decision == AuthorizationDecision.ALLOW
    print("✓ STEP 2-3: Request #1 → ALLOW")

    # STEP 4: Quarantine research-01
    quarantine_service = QuarantineService(identity_service)
    quarantine_service.quarantine(AgentId.RESEARCH_01)

    # Verify quarantine state
    agent = identity_service.get_agent(AgentId.RESEARCH_01)
    assert agent is not None
    assert agent.state == SecurityState.QUARANTINED
    print("✓ STEP 4: research-01 → QUARANTINED")

    # STEP 5: Send the same request again
    request2 = _make_action_request(
        source_agent=AgentId.RESEARCH_01,
        action=ActionName.RESEARCH_SEARCH,
        resource=ResourceName.RESEARCH_DATA,
        capability=CapabilityName.RESEARCH_SEARCH,
    )
    result2 = authorize(request2, identity_service=identity_service)

    # STEP 6: Verify DENY with AGENT_QUARANTINED
    assert result2.decision == AuthorizationDecision.DENY
    assert ReasonCode.AGENT_QUARANTINED in result2.reason_codes
    print("✓ STEP 5-6: Request #2 → DENY (AGENT_QUARANTINED)")

    print("\n✓ End-to-end demo completed successfully!")


# ============================================================================
# TEST L: Manual Demo Test (for display purposes)
# ============================================================================

def test_l_manual_demo_test():
    """
    TEST L — Manual demo test
    Run a simple manual demonstration with clear before/after output.
    """
    identity_service = IdentityService()

    print("\n" + "="*60)
    print("PHASE 17 QUARANTINE DEMO")
    print("="*60)

    # STEP 1: Before quarantine
    request = _make_action_request(
        source_agent=AgentId.RESEARCH_01,
        action=ActionName.RESEARCH_SEARCH,
        resource=ResourceName.RESEARCH_DATA,
        capability=CapabilityName.RESEARCH_SEARCH,
    )
    result1 = authorize(request, identity_service=identity_service)

    print(f"\nREQUEST #1 (Before Quarantine):")
    print(f"  Agent: research-01")
    print(f"  Action: research.search")
    print(f"  Resource: research-data")
    print(f"  Decision: {result1.decision.value}")
    print(f"  Risk Score: {result1.risk_score}")
    print(f"  Reason Codes: {[r.value for r in result1.reason_codes]}")

    # STEP 2: Quarantine
    quarantine_service = QuarantineService(identity_service)
    quarantine_service.quarantine(AgentId.RESEARCH_01)

    agent = identity_service.get_agent(AgentId.RESEARCH_01)
    print(f"\nQUARANTINE:")
    print(f"  Agent: research-01")
    print(f"  State: {agent.state.value}")

    # STEP 3: After quarantine
    request2 = _make_action_request(
        source_agent=AgentId.RESEARCH_01,
        action=ActionName.RESEARCH_SEARCH,
        resource=ResourceName.RESEARCH_DATA,
        capability=CapabilityName.RESEARCH_SEARCH,
    )
    result2 = authorize(request2, identity_service=identity_service)

    print(f"\nREQUEST #2 (After Quarantine):")
    print(f"  Agent: research-01")
    print(f"  Action: research.search")
    print(f"  Resource: research-data")
    print(f"  Decision: {result2.decision.value}")
    print(f"  Risk Score: {result2.risk_score}")
    print(f"  Reason Codes: {[r.value for r in result2.reason_codes]}")

    print("\n" + "="*60)
    print("DEMO COMPLETE")
    print("="*60 + "\n")

    # Verify the demo worked correctly
    assert result1.decision == AuthorizationDecision.ALLOW
    assert result2.decision == AuthorizationDecision.DENY
    assert ReasonCode.AGENT_QUARANTINED in result2.reason_codes
