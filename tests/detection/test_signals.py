"""
Unit tests for detection signals, models, weights, and deterministic risk calculation.
"""

import pytest

from shield.detection.signals import (
    SIGNAL_EXPLANATIONS,
    SIGNAL_WEIGHTS,
    DetectionResult,
    DetectionSignal,
    SignalType,
    ThreatSignal,
    calculate_risk,
)
from shield.gateway.models import ReasonCode


def test_signal_weights_exact_values():
    """Verify exact canonical signal weights."""
    assert SIGNAL_WEIGHTS[ReasonCode.CAPABILITY_MISMATCH] == 30
    assert SIGNAL_WEIGHTS[ReasonCode.AUTHORITY_MISMATCH] == 25
    assert SIGNAL_WEIGHTS[ReasonCode.PROVENANCE_ANOMALY] == 20
    assert SIGNAL_WEIGHTS[ReasonCode.PRIVILEGE_ESCALATION] == 15
    assert SIGNAL_WEIGHTS[ReasonCode.SUSPICIOUS_BEHAVIOR] == 10

    # Total of all five signals must equal exactly 100
    assert sum(SIGNAL_WEIGHTS.values()) == 100


def test_signal_explanations_defined():
    """Verify that human-readable explanations exist for each signal."""
    for code in SIGNAL_WEIGHTS:
        assert code in SIGNAL_EXPLANATIONS
        assert len(SIGNAL_EXPLANATIONS[code]) > 0
        assert isinstance(SIGNAL_EXPLANATIONS[code], str)


def test_detection_signal_model():
    """Verify DetectionSignal model instantiates and validates correctly."""
    sig = DetectionSignal(
        code=ReasonCode.CAPABILITY_MISMATCH,
        weight=30,
        triggered=True,
        explanation="Capability mismatch detected",
    )
    assert sig.code == ReasonCode.CAPABILITY_MISMATCH
    assert sig.weight == 30
    assert sig.triggered is True
    assert sig.explanation == "Capability mismatch detected"

    # ThreatSignal is an alias
    assert ThreatSignal is DetectionSignal
    assert SignalType is ReasonCode


def test_calculate_risk_no_signals():
    """Empty signals list produces a risk score of 0."""
    assert calculate_risk([]) == 0


def test_calculate_risk_single_signal():
    """Single triggered signal produces its exact weight."""
    sig = DetectionSignal(
        code=ReasonCode.CAPABILITY_MISMATCH,
        weight=30,
        triggered=True,
        explanation=SIGNAL_EXPLANATIONS[ReasonCode.CAPABILITY_MISMATCH],
    )
    assert calculate_risk([sig]) == 30
    assert calculate_risk([ReasonCode.CAPABILITY_MISMATCH]) == 30
    assert calculate_risk(["CAPABILITY_MISMATCH"]) == 30


def test_calculate_risk_composition():
    """Test additive score composition matching Section 4 / Section 8.G."""
    # CAPABILITY_MISMATCH: 30
    sig_cap = DetectionSignal(
        code=ReasonCode.CAPABILITY_MISMATCH,
        weight=30,
        triggered=True,
        explanation="Cap mismatch",
    )
    # AUTHORITY_MISMATCH: 25
    sig_auth = DetectionSignal(
        code=ReasonCode.AUTHORITY_MISMATCH,
        weight=25,
        triggered=True,
        explanation="Auth mismatch",
    )
    # PROVENANCE_ANOMALY: 20
    sig_prov = DetectionSignal(
        code=ReasonCode.PROVENANCE_ANOMALY,
        weight=20,
        triggered=True,
        explanation="Prov anomaly",
    )
    # PRIVILEGE_ESCALATION: 15
    sig_priv = DetectionSignal(
        code=ReasonCode.PRIVILEGE_ESCALATION,
        weight=15,
        triggered=True,
        explanation="Priv escalation",
    )
    # SUSPICIOUS_BEHAVIOR: 10
    sig_susp = DetectionSignal(
        code=ReasonCode.SUSPICIOUS_BEHAVIOR,
        weight=10,
        triggered=True,
        explanation="Suspicious behavior",
    )

    # 1. CAPABILITY_MISMATCH + AUTHORITY_MISMATCH = 30 + 25 = 55
    score_55 = calculate_risk([sig_cap, sig_auth])
    assert score_55 == 55

    # 2. CAPABILITY_MISMATCH + AUTHORITY_MISMATCH + PROVENANCE_ANOMALY = 30 + 25 + 20 = 75
    score_75 = calculate_risk([sig_cap, sig_auth, sig_prov])
    assert score_75 == 75

    # 3. All five signals = 30 + 25 + 20 + 15 + 10 = 100
    score_100 = calculate_risk([sig_cap, sig_auth, sig_prov, sig_priv, sig_susp])
    assert score_100 == 100


def test_calculate_risk_untriggered_signals_do_not_contribute():
    """Signals marked as triggered=False must not contribute to the score."""
    sig1 = DetectionSignal(
        code=ReasonCode.CAPABILITY_MISMATCH,
        weight=30,
        triggered=True,
        explanation="Triggered",
    )
    sig2 = DetectionSignal(
        code=ReasonCode.AUTHORITY_MISMATCH,
        weight=25,
        triggered=False,
        explanation="Not triggered",
    )
    assert calculate_risk([sig1, sig2]) == 30


def test_calculate_risk_no_duplicate_counting():
    """Passing duplicate signal codes must not double count."""
    sig1 = DetectionSignal(code=ReasonCode.CAPABILITY_MISMATCH, weight=30, triggered=True, explanation="First")
    sig2 = DetectionSignal(code=ReasonCode.CAPABILITY_MISMATCH, weight=30, triggered=True, explanation="Duplicate")
    assert calculate_risk([sig1, sig2]) == 30
    assert calculate_risk([ReasonCode.CAPABILITY_MISMATCH, ReasonCode.CAPABILITY_MISMATCH]) == 30


def test_calculate_risk_bounds():
    """Risk score is always bounded between 0 and 100."""
    assert calculate_risk([]) == 0
    all_codes = list(SIGNAL_WEIGHTS.keys())
    assert calculate_risk(all_codes) == 100


def test_no_hardcoded_attack_score():
    """Confirm score is strictly computed from signal sum, not a hardcoded number like 94."""
    # If only 4 signals are present (e.g. sum = 85 or 90)
    signals = [
        ReasonCode.CAPABILITY_MISMATCH,  # 30
        ReasonCode.AUTHORITY_MISMATCH,   # 25
        ReasonCode.PROVENANCE_ANOMALY,   # 20
        ReasonCode.PRIVILEGE_ESCALATION, # 15
    ]
    expected_sum = 30 + 25 + 20 + 15  # 90
    assert calculate_risk(signals) == expected_sum
    assert calculate_risk(signals) != 94


def test_detection_result_model():
    """Verify DetectionResult model structure and helper methods."""
    sig = DetectionSignal(
        code=ReasonCode.CAPABILITY_MISMATCH,
        weight=30,
        triggered=True,
        explanation=SIGNAL_EXPLANATIONS[ReasonCode.CAPABILITY_MISMATCH],
    )
    result = DetectionResult(
        request_id="req-123",
        risk_score=30,
        signals=[sig],
        all_signals=[sig],
        explanations=[sig.explanation],
    )
    assert result.request_id == "req-123"
    assert result.risk_score == 30
    assert result.has_signal(ReasonCode.CAPABILITY_MISMATCH) is True
    assert result.has_signal("CAPABILITY_MISMATCH") is True
    assert result.has_signal(ReasonCode.AUTHORITY_MISMATCH) is False
    assert result.get_signal(ReasonCode.CAPABILITY_MISMATCH) == sig
    assert result.get_signal(ReasonCode.AUTHORITY_MISMATCH) is None
