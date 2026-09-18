"""
Unit tests for deterministic security rules.
"""

from datetime import datetime, timezone
import pytest

from shield.detection.rules import (
    check_authority_mismatch,
    check_capability_mismatch,
    check_privilege_escalation,
    check_provenance_anomaly,
    check_suspicious_behavior,
)
from shield.gateway.models import (
    ActionName,
    ActionRequest,
    CapabilityName,
    ReasonCode,
    ResourceName,
)
from shield.identity.models import AgentId
from shield.provenance.models import Provenance


def _make_request(
    source_agent: AgentId = AgentId.RESEARCH_01,
    action: ActionName = ActionName.RESEARCH_SEARCH,
    resource: ResourceName = ResourceName.RESEARCH_DATA,
    capability: CapabilityName = CapabilityName.RESEARCH_SEARCH,
    claimed_authority: AgentId | None = None,
    task_origin: AgentId | None = None,
    delegation_chain: list[AgentId] | None = None,
) -> ActionRequest:
    """Helper to build an ActionRequest for detection testing."""
    if claimed_authority is None:
        claimed_authority = source_agent
    if task_origin is None:
        task_origin = source_agent
    if delegation_chain is None:
        delegation_chain = [source_agent]

    return ActionRequest(
        request_id=f"test-rule-{source_agent.value}-{action.value}",
        timestamp=datetime.now(timezone.utc),
        source_agent=source_agent,
        target_agent=source_agent,
        task_id="task-rules-test",
        action=action,
        resource=resource,
        claimed_authority=claimed_authority,
        capability=capability,
        provenance=Provenance(
            task_origin=task_origin,
            delegation_chain=delegation_chain,
        ),
    )


# ============================================================================
# CAPABILITY_MISMATCH Tests
# ============================================================================

def test_capability_mismatch_false_when_aligned():
    """Matching action and capability does not trigger CAPABILITY_MISMATCH."""
    req = _make_request(
        action=ActionName.RESEARCH_SEARCH,
        capability=CapabilityName.RESEARCH_SEARCH,
    )
    assert check_capability_mismatch(req) is False


def test_capability_mismatch_true_when_mismatched():
    """Declared capability differing from required action capability triggers signal."""
    # research.search capability for deployment.deploy action
    req = _make_request(
        action=ActionName.DEPLOYMENT_DEPLOY,
        capability=CapabilityName.RESEARCH_SEARCH,
    )
    assert check_capability_mismatch(req) is True

    # research.search capability for research.read action
    req2 = _make_request(
        action=ActionName.RESEARCH_READ,
        capability=CapabilityName.RESEARCH_SEARCH,
    )
    assert check_capability_mismatch(req2) is True


# ============================================================================
# AUTHORITY_MISMATCH Tests
# ============================================================================

def test_authority_mismatch_false_when_consistent():
    """Consistent authority matches self or delegator."""
    # Self-delegated
    req_self = _make_request(
        source_agent=AgentId.RESEARCH_01,
        claimed_authority=AgentId.RESEARCH_01,
        task_origin=AgentId.RESEARCH_01,
        delegation_chain=[AgentId.RESEARCH_01],
    )
    assert check_authority_mismatch(req_self) is False

    # Delegated: orchestrator-01 -> research-01
    req_del = _make_request(
        source_agent=AgentId.RESEARCH_01,
        claimed_authority=AgentId.ORCHESTRATOR_01,
        task_origin=AgentId.ORCHESTRATOR_01,
        delegation_chain=[AgentId.ORCHESTRATOR_01, AgentId.RESEARCH_01],
    )
    assert check_authority_mismatch(req_del) is False


def test_authority_mismatch_true_when_inconsistent():
    """Inconsistent claimed authority triggers AUTHORITY_MISMATCH."""
    # Self chain but claims orchestrator authority
    req = _make_request(
        source_agent=AgentId.RESEARCH_01,
        claimed_authority=AgentId.ORCHESTRATOR_01,
        task_origin=AgentId.RESEARCH_01,
        delegation_chain=[AgentId.RESEARCH_01],
    )
    assert check_authority_mismatch(req) is True

    # Delegated chain orchestrator -> research, but claims deployment authority
    req2 = _make_request(
        source_agent=AgentId.RESEARCH_01,
        claimed_authority=AgentId.DEPLOYMENT_01,
        task_origin=AgentId.ORCHESTRATOR_01,
        delegation_chain=[AgentId.ORCHESTRATOR_01, AgentId.RESEARCH_01],
    )
    assert check_authority_mismatch(req2) is True


# ============================================================================
# PROVENANCE_ANOMALY Tests
# ============================================================================

def test_provenance_anomaly_false_when_valid():
    """Valid provenance chain does not trigger PROVENANCE_ANOMALY."""
    req = _make_request(
        source_agent=AgentId.RESEARCH_01,
        claimed_authority=AgentId.RESEARCH_01,
        task_origin=AgentId.RESEARCH_01,
        delegation_chain=[AgentId.RESEARCH_01],
    )
    assert check_provenance_anomaly(req) is False


def test_provenance_anomaly_true_on_impossible_delegation():
    """Impossible delegation step triggers PROVENANCE_ANOMALY."""
    # coding-01 -> research-01 is not an allowed delegation
    req = _make_request(
        source_agent=AgentId.RESEARCH_01,
        claimed_authority=AgentId.CODING_01,
        task_origin=AgentId.CODING_01,
        delegation_chain=[AgentId.CODING_01, AgentId.RESEARCH_01],
    )
    assert check_provenance_anomaly(req) is True


def test_provenance_anomaly_true_on_loop():
    """Delegation loop triggers PROVENANCE_ANOMALY."""
    req = _make_request(
        source_agent=AgentId.RESEARCH_01,
        claimed_authority=AgentId.ORCHESTRATOR_01,
        task_origin=AgentId.RESEARCH_01,
        delegation_chain=[AgentId.RESEARCH_01, AgentId.ORCHESTRATOR_01, AgentId.RESEARCH_01],
    )
    assert check_provenance_anomaly(req) is True


def test_provenance_anomaly_true_when_chain_does_not_end_at_source():
    """Chain terminating at a different agent triggers PROVENANCE_ANOMALY."""
    req = _make_request(
        source_agent=AgentId.RESEARCH_01,
        claimed_authority=AgentId.RESEARCH_01,
        task_origin=AgentId.ORCHESTRATOR_01,
        delegation_chain=[AgentId.ORCHESTRATOR_01],
    )
    assert check_provenance_anomaly(req) is True


# ============================================================================
# PRIVILEGE_ESCALATION Tests
# ============================================================================

def test_privilege_escalation_canonical_targets():
    """
    Verify exact requirements from Section 2:
    - research-01 attempting deployment.deploy
    - research-01 attempting deployment.production
    - coding-01 attempting deployment.production
    - verification-01 attempting deployment.production
    """
    # research-01 attempting deployment.deploy
    req1 = _make_request(
        source_agent=AgentId.RESEARCH_01,
        action=ActionName.DEPLOYMENT_DEPLOY,
        resource=ResourceName.PRODUCTION_ENVIRONMENT,
        capability=CapabilityName.DEPLOYMENT_PRODUCTION,
    )
    assert check_privilege_escalation(req1) is True

    # coding-01 attempting deployment.deploy (requires deployment.production)
    req2 = _make_request(
        source_agent=AgentId.CODING_01,
        action=ActionName.DEPLOYMENT_DEPLOY,
        resource=ResourceName.PRODUCTION_ENVIRONMENT,
        capability=CapabilityName.DEPLOYMENT_PRODUCTION,
    )
    assert check_privilege_escalation(req2) is True

    # verification-01 attempting deployment.deploy
    req3 = _make_request(
        source_agent=AgentId.VERIFICATION_01,
        action=ActionName.DEPLOYMENT_DEPLOY,
        resource=ResourceName.PRODUCTION_ENVIRONMENT,
        capability=CapabilityName.DEPLOYMENT_PRODUCTION,
    )
    assert check_privilege_escalation(req3) is True


def test_privilege_escalation_false_for_authorized_operations():
    """Normal operations within assigned role do not trigger PRIVILEGE_ESCALATION."""
    # research-01 performing research.search
    req_res = _make_request(
        source_agent=AgentId.RESEARCH_01,
        action=ActionName.RESEARCH_SEARCH,
        resource=ResourceName.RESEARCH_DATA,
        capability=CapabilityName.RESEARCH_SEARCH,
    )
    assert check_privilege_escalation(req_res) is False

    # coding-01 performing coding.write
    req_code = _make_request(
        source_agent=AgentId.CODING_01,
        action=ActionName.CODING_WRITE,
        resource=ResourceName.WORKSPACE,
        capability=CapabilityName.CODING_WRITE,
    )
    assert check_privilege_escalation(req_code) is False

    # deployment-01 performing deployment.deploy
    req_dep = _make_request(
        source_agent=AgentId.DEPLOYMENT_01,
        action=ActionName.DEPLOYMENT_DEPLOY,
        resource=ResourceName.PRODUCTION_ENVIRONMENT,
        capability=CapabilityName.DEPLOYMENT_PRODUCTION,
    )
    assert check_privilege_escalation(req_dep) is False


# ============================================================================
# SUSPICIOUS_BEHAVIOR Tests
# ============================================================================

def test_suspicious_behavior_compound_conditions():
    """Verify compound high-risk violations trigger SUSPICIOUS_BEHAVIOR."""
    # 1. PRIVILEGE_ESCALATION + CAPABILITY_MISMATCH
    req1 = _make_request(
        source_agent=AgentId.RESEARCH_01,
        action=ActionName.DEPLOYMENT_DEPLOY,
        resource=ResourceName.PRODUCTION_ENVIRONMENT,
        capability=CapabilityName.RESEARCH_SEARCH,
    )
    # Check explicitly with triggered set
    triggered1 = {ReasonCode.PRIVILEGE_ESCALATION, ReasonCode.CAPABILITY_MISMATCH}
    assert check_suspicious_behavior(req1, triggered_codes=triggered1) is True

    # 2. PRIVILEGE_ESCALATION + AUTHORITY_MISMATCH
    triggered2 = {ReasonCode.PRIVILEGE_ESCALATION, ReasonCode.AUTHORITY_MISMATCH}
    assert check_suspicious_behavior(req1, triggered_codes=triggered2) is True

    # 3. PRIVILEGE_ESCALATION + PROVENANCE_ANOMALY
    triggered3 = {ReasonCode.PRIVILEGE_ESCALATION, ReasonCode.PROVENANCE_ANOMALY}
    assert check_suspicious_behavior(req1, triggered_codes=triggered3) is True

    # 4. Valid request with no violations -> False
    req_valid = _make_request(
        source_agent=AgentId.RESEARCH_01,
        action=ActionName.RESEARCH_SEARCH,
        capability=CapabilityName.RESEARCH_SEARCH,
    )
    assert check_suspicious_behavior(req_valid, triggered_codes=set()) is False

    # 5. Single violation alone (e.g. only PRIVILEGE_ESCALATION) -> False
    assert check_suspicious_behavior(req1, triggered_codes={ReasonCode.PRIVILEGE_ESCALATION}) is False
