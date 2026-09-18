"""
End-to-end anomaly and detection orchestration tests.
Implements the required test matrix A-J and Section 9 integration test.
"""

from datetime import datetime, timezone
import pytest

from shield.authorization.pipeline import authorize
from shield.detection.anomaly import AnomalyDetector, detect
from shield.gateway.models import (
    ActionName,
    ActionRequest,
    AuthorizationDecision,
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
        request_id=f"test-det-{source_agent.value}-{action.value}",
        timestamp=datetime.now(timezone.utc),
        source_agent=source_agent,
        target_agent=source_agent,
        task_id="task-anomaly-test",
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
# TEST A: No violation
# ============================================================================

def test_a_no_violation():
    """
    Valid research request:
    research-01, action = research.search, resource = research-data,
    capability = research.search, valid provenance.

    Expected:
    - no capability mismatch
    - no authority mismatch
    - no provenance anomaly
    - no privilege escalation
    - no suspicious behavior
    - risk = 0
    """
    request = _make_request(
        source_agent=AgentId.RESEARCH_01,
        action=ActionName.RESEARCH_SEARCH,
        resource=ResourceName.RESEARCH_DATA,
        capability=CapabilityName.RESEARCH_SEARCH,
    )

    result = detect(request)

    assert result.has_signal(ReasonCode.CAPABILITY_MISMATCH) is False
    assert result.has_signal(ReasonCode.AUTHORITY_MISMATCH) is False
    assert result.has_signal(ReasonCode.PROVENANCE_ANOMALY) is False
    assert result.has_signal(ReasonCode.PRIVILEGE_ESCALATION) is False
    assert result.has_signal(ReasonCode.SUSPICIOUS_BEHAVIOR) is False
    assert len(result.signals) == 0
    assert result.risk_score == 0


# ============================================================================
# TEST B: Capability mismatch
# ============================================================================

def test_b_capability_mismatch():
    """
    research-01
    capability = research.search
    action = deployment.deploy
    resource = production-environment

    Expected:
    CAPABILITY_MISMATCH triggered
    risk includes +30
    """
    request = _make_request(
        source_agent=AgentId.RESEARCH_01,
        action=ActionName.DEPLOYMENT_DEPLOY,
        resource=ResourceName.PRODUCTION_ENVIRONMENT,
        capability=CapabilityName.RESEARCH_SEARCH,
    )

    result = detect(request)

    assert result.has_signal(ReasonCode.CAPABILITY_MISMATCH) is True
    cap_signal = result.get_signal(ReasonCode.CAPABILITY_MISMATCH)
    assert cap_signal is not None
    assert cap_signal.weight == 30
    assert result.risk_score >= 30


# ============================================================================
# TEST C: Authority mismatch
# ============================================================================

def test_c_authority_mismatch():
    """
    Construct a request with inconsistent claimed_authority and provenance.
    research-01 self-chain claiming orchestrator-01 authority.

    Expected:
    AUTHORITY_MISMATCH triggered
    +25
    """
    request = _make_request(
        source_agent=AgentId.RESEARCH_01,
        action=ActionName.RESEARCH_SEARCH,
        resource=ResourceName.RESEARCH_DATA,
        capability=CapabilityName.RESEARCH_SEARCH,
        claimed_authority=AgentId.ORCHESTRATOR_01,
        delegation_chain=[AgentId.RESEARCH_01],
    )

    result = detect(request)

    assert result.has_signal(ReasonCode.AUTHORITY_MISMATCH) is True
    auth_signal = result.get_signal(ReasonCode.AUTHORITY_MISMATCH)
    assert auth_signal is not None
    assert auth_signal.weight == 25
    assert result.risk_score == 25


# ============================================================================
# TEST D: Provenance anomaly
# ============================================================================

def test_d_provenance_anomaly():
    """
    Construct an invalid delegation chain (e.g. impossible delegation coding -> research).

    Expected:
    PROVENANCE_ANOMALY triggered
    +20
    """
    request = _make_request(
        source_agent=AgentId.RESEARCH_01,
        action=ActionName.RESEARCH_SEARCH,
        resource=ResourceName.RESEARCH_DATA,
        capability=CapabilityName.RESEARCH_SEARCH,
        claimed_authority=AgentId.CODING_01,
        task_origin=AgentId.CODING_01,
        delegation_chain=[AgentId.CODING_01, AgentId.RESEARCH_01],
    )

    result = detect(request)

    assert result.has_signal(ReasonCode.PROVENANCE_ANOMALY) is True
    prov_signal = result.get_signal(ReasonCode.PROVENANCE_ANOMALY)
    assert prov_signal is not None
    assert prov_signal.weight == 20
    assert result.risk_score == 20


# ============================================================================
# TEST E: Privilege escalation
# ============================================================================

def test_e_privilege_escalation():
    """
    research-01 requests deployment.deploy against production-environment.

    Expected:
    PRIVILEGE_ESCALATION triggered
    +15
    """
    # Presenting matching capability token to isolate privilege escalation
    request = _make_request(
        source_agent=AgentId.RESEARCH_01,
        action=ActionName.DEPLOYMENT_DEPLOY,
        resource=ResourceName.PRODUCTION_ENVIRONMENT,
        capability=CapabilityName.DEPLOYMENT_PRODUCTION,
    )

    result = detect(request)

    assert result.has_signal(ReasonCode.PRIVILEGE_ESCALATION) is True
    priv_signal = result.get_signal(ReasonCode.PRIVILEGE_ESCALATION)
    assert priv_signal is not None
    assert priv_signal.weight == 15
    assert result.risk_score == 15


# ============================================================================
# TEST F: Suspicious behavior
# ============================================================================

def test_f_suspicious_behavior():
    """
    Construct the deterministic combination required by the SUSPICIOUS_BEHAVIOR rule.
    (PRIVILEGE_ESCALATION + another violation, e.g., AUTHORITY_MISMATCH).

    Expected:
    SUSPICIOUS_BEHAVIOR triggered
    +10
    """
    # research-01 attempting deployment.deploy (priv escalation +15)
    # presenting deployment.production token (no cap mismatch)
    # claiming orchestrator-01 authority on self chain (auth mismatch +25)
    # Compound rule triggers SUSPICIOUS_BEHAVIOR (+10)
    request = _make_request(
        source_agent=AgentId.RESEARCH_01,
        action=ActionName.DEPLOYMENT_DEPLOY,
        resource=ResourceName.PRODUCTION_ENVIRONMENT,
        capability=CapabilityName.DEPLOYMENT_PRODUCTION,
        claimed_authority=AgentId.ORCHESTRATOR_01,
        delegation_chain=[AgentId.RESEARCH_01],
    )

    result = detect(request)

    assert result.has_signal(ReasonCode.SUSPICIOUS_BEHAVIOR) is True
    susp_signal = result.get_signal(ReasonCode.SUSPICIOUS_BEHAVIOR)
    assert susp_signal is not None
    assert susp_signal.weight == 10

    # Risk score: 15 (priv esc) + 25 (auth mismatch) + 10 (suspicious) = 50
    assert result.risk_score == 50


# ============================================================================
# TEST G: Score composition
# ============================================================================

def test_g_score_composition():
    """
    Test exact score composition:
    CAPABILITY_MISMATCH + AUTHORITY_MISMATCH => 30 + 25 = 55
    CAPABILITY_MISMATCH + AUTHORITY_MISMATCH + PROVENANCE_ANOMALY => 75
    All five signals => 30 + 25 + 20 + 15 + 10 = 100
    """
    # 1. Request with CAPABILITY_MISMATCH + AUTHORITY_MISMATCH (no priv escalation)
    # research-01 requesting research.read (not priv esc) with capability research.search (cap mismatch +30)
    # and claiming orchestrator authority on self chain (auth mismatch +25)
    req_55 = _make_request(
        source_agent=AgentId.RESEARCH_01,
        action=ActionName.RESEARCH_READ,
        resource=ResourceName.RESEARCH_DATA,
        capability=CapabilityName.RESEARCH_SEARCH,
        claimed_authority=AgentId.ORCHESTRATOR_01,
        delegation_chain=[AgentId.RESEARCH_01],
    )
    res_55 = detect(req_55)
    assert res_55.has_signal(ReasonCode.CAPABILITY_MISMATCH) is True
    assert res_55.has_signal(ReasonCode.AUTHORITY_MISMATCH) is True
    assert res_55.has_signal(ReasonCode.PROVENANCE_ANOMALY) is False
    assert res_55.has_signal(ReasonCode.PRIVILEGE_ESCALATION) is False
    assert res_55.has_signal(ReasonCode.SUSPICIOUS_BEHAVIOR) is False
    assert res_55.risk_score == 55

    # 2. Request with CAPABILITY_MISMATCH + AUTHORITY_MISMATCH + PROVENANCE_ANOMALY => 75
    # Add impossible delegation chain coding -> research, claimed authority orchestrator
    req_75 = _make_request(
        source_agent=AgentId.RESEARCH_01,
        action=ActionName.RESEARCH_READ,
        resource=ResourceName.RESEARCH_DATA,
        capability=CapabilityName.RESEARCH_SEARCH,
        claimed_authority=AgentId.ORCHESTRATOR_01,
        task_origin=AgentId.CODING_01,
        delegation_chain=[AgentId.CODING_01, AgentId.RESEARCH_01],
    )
    res_75 = detect(req_75)
    assert res_75.has_signal(ReasonCode.CAPABILITY_MISMATCH) is True
    assert res_75.has_signal(ReasonCode.AUTHORITY_MISMATCH) is True
    assert res_75.has_signal(ReasonCode.PROVENANCE_ANOMALY) is True
    assert res_75.has_signal(ReasonCode.PRIVILEGE_ESCALATION) is False
    assert res_75.has_signal(ReasonCode.SUSPICIOUS_BEHAVIOR) is False
    assert res_75.risk_score == 75

    # 3. Canonical full attack with all five signals => 100
    # research-01 attempting deployment.deploy (+30 cap mismatch, +15 priv esc)
    # with impossible delegation (+20 prov anomaly)
    # and mismatched claimed authority (+25 auth mismatch)
    # triggering compound suspicious behavior (+10)
    req_100 = _make_request(
        source_agent=AgentId.RESEARCH_01,
        action=ActionName.DEPLOYMENT_DEPLOY,
        resource=ResourceName.PRODUCTION_ENVIRONMENT,
        capability=CapabilityName.RESEARCH_SEARCH,
        claimed_authority=AgentId.ORCHESTRATOR_01,
        task_origin=AgentId.CODING_01,
        delegation_chain=[AgentId.CODING_01, AgentId.RESEARCH_01],
    )
    res_100 = detect(req_100)
    assert res_100.has_signal(ReasonCode.CAPABILITY_MISMATCH) is True
    assert res_100.has_signal(ReasonCode.AUTHORITY_MISMATCH) is True
    assert res_100.has_signal(ReasonCode.PROVENANCE_ANOMALY) is True
    assert res_100.has_signal(ReasonCode.PRIVILEGE_ESCALATION) is True
    assert res_100.has_signal(ReasonCode.SUSPICIOUS_BEHAVIOR) is True
    assert len(res_100.signals) == 5
    assert res_100.risk_score == 100


# ============================================================================
# TEST H: No hardcoded 94
# ============================================================================

def test_h_no_hardcoded_attack_score():
    """
    Do NOT assert that the canonical attack always equals 94.
    Assert that the score equals the sum of the triggered signals.
    """
    req = _make_request(
        source_agent=AgentId.RESEARCH_01,
        action=ActionName.DEPLOYMENT_DEPLOY,
        resource=ResourceName.PRODUCTION_ENVIRONMENT,
        capability=CapabilityName.RESEARCH_SEARCH,
        claimed_authority=AgentId.ORCHESTRATOR_01,
        task_origin=AgentId.CODING_01,
        delegation_chain=[AgentId.CODING_01, AgentId.RESEARCH_01],
    )
    result = detect(req)
    expected_sum = sum(s.weight for s in result.signals)
    assert result.risk_score == expected_sum
    assert result.risk_score != 94
    assert result.risk_score == 100


# ============================================================================
# TEST I: Score bounds
# ============================================================================

def test_i_score_bounds():
    """
    Test score bounds:
    - no signals -> 0
    - all five -> 100
    - score never exceeds 100
    """
    # 0 for valid
    valid_req = _make_request()
    res_valid = detect(valid_req)
    assert res_valid.risk_score == 0

    # Max 100 for all five
    attack_req = _make_request(
        source_agent=AgentId.RESEARCH_01,
        action=ActionName.DEPLOYMENT_DEPLOY,
        resource=ResourceName.PRODUCTION_ENVIRONMENT,
        capability=CapabilityName.RESEARCH_SEARCH,
        claimed_authority=AgentId.ORCHESTRATOR_01,
        task_origin=AgentId.CODING_01,
        delegation_chain=[AgentId.CODING_01, AgentId.RESEARCH_01],
    )
    res_attack = detect(attack_req)
    assert res_attack.risk_score == 100
    assert res_attack.risk_score <= 100


# ============================================================================
# TEST J: Determinism
# ============================================================================

def test_j_determinism():
    """
    Run detection twice against the same ActionRequest.
    Expected: identical signals, identical explanations, identical risk score.
    """
    req = _make_request(
        source_agent=AgentId.RESEARCH_01,
        action=ActionName.DEPLOYMENT_DEPLOY,
        resource=ResourceName.PRODUCTION_ENVIRONMENT,
        capability=CapabilityName.RESEARCH_SEARCH,
        claimed_authority=AgentId.ORCHESTRATOR_01,
        delegation_chain=[AgentId.RESEARCH_01],
    )

    result_1 = detect(req)
    result_2 = detect(req)

    assert result_1.risk_score == result_2.risk_score
    assert len(result_1.signals) == len(result_2.signals)
    for s1, s2 in zip(result_1.signals, result_2.signals):
        assert s1.code == s2.code
        assert s1.weight == s2.weight
        assert s1.triggered == s2.triggered
        assert s1.explanation == s2.explanation
    assert result_1.explanations == result_2.explanations


# ============================================================================
# SECTION 9 INTEGRATION TEST: Detection does NOT override Authorization
# ============================================================================

def test_section_9_detection_does_not_override_authorization():
    """
    Verify detection does NOT override authorization.
    Create a request that Cedar denies. Run detection.
    Even if detection returns a low score, detection must not produce an ALLOW.
    Authorization remains authoritative (DENY).
    """
    # Create request that Cedar denies:
    # research-01 attempting deployment.deploy with valid provenance and capability token
    req = _make_request(
        source_agent=AgentId.RESEARCH_01,
        action=ActionName.DEPLOYMENT_DEPLOY,
        resource=ResourceName.PRODUCTION_ENVIRONMENT,
        capability=CapabilityName.RESEARCH_SEARCH,
    )

    # 1. Evaluate detection
    detection_result = detect(req)
    assert isinstance(detection_result.risk_score, int)

    # 2. Evaluate authorization pipeline
    auth_result = authorize(req)

    # 3. Cedar / pipeline must DENY the request
    assert auth_result.decision == AuthorizationDecision.DENY
    assert auth_result.checks.cedar is False
    assert ReasonCode.POLICY_DENIED in auth_result.reason_codes

    # 4. Detection score does not dictate authorization verdict
    assert auth_result.decision != AuthorizationDecision.ALLOW


def test_anomaly_detector_class_wrapper():
    """Verify AnomalyDetector class provides the same deterministic detection."""
    detector = AnomalyDetector()
    req = _make_request()
    res = detector.detect(req)
    assert res.risk_score == 0
    assert len(res.signals) == 0
