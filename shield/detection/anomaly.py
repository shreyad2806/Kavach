"""
Anomaly and Threat Detection Orchestration — Kavach Phase 11.

Deterministically coordinates the evaluation of the five security signals,
calculates the aggregate risk score, and produces an explainable DetectionResult.

Contains NO LLM calls, NO ML models, NO network requests, and NO state mutation.
"""

from shield.detection.rules import (
    check_authority_mismatch,
    check_capability_mismatch,
    check_privilege_escalation,
    check_provenance_anomaly,
    check_suspicious_behavior,
)
from shield.detection.signals import (
    SIGNAL_EXPLANATIONS,
    SIGNAL_WEIGHTS,
    DetectionResult,
    DetectionSignal,
    calculate_risk,
)
from shield.gateway.models import ActionRequest, ReasonCode


def detect(request: ActionRequest) -> DetectionResult:
    """
    Deterministically evaluate an ActionRequest for security signals and compute risk score.

    Evaluation steps:
      1. Evaluates each of the four primary deterministic rules:
         - CAPABILITY_MISMATCH
         - AUTHORITY_MISMATCH
         - PROVENANCE_ANOMALY
         - PRIVILEGE_ESCALATION
      2. Evaluates the compound SUSPICIOUS_BEHAVIOR rule based on triggered primary signals.
      3. Constructs structured DetectionSignal objects for all five signals.
      4. Collects triggered signals and human-readable explanations.
      5. Calculates the bounded risk score via calculate_risk().
      6. Returns a structured DetectionResult.

    Parameters:
        request: The ActionRequest to evaluate.

    Returns:
        DetectionResult containing risk score, triggered signals, and explanations.
    """
    # 1. Primary rule evaluations
    cap_mismatch = check_capability_mismatch(request)
    auth_mismatch = check_authority_mismatch(request)
    prov_anomaly = check_provenance_anomaly(request)
    priv_escalation = check_privilege_escalation(request)

    triggered_codes: set[ReasonCode] = set()
    if cap_mismatch:
        triggered_codes.add(ReasonCode.CAPABILITY_MISMATCH)
    if auth_mismatch:
        triggered_codes.add(ReasonCode.AUTHORITY_MISMATCH)
    if prov_anomaly:
        triggered_codes.add(ReasonCode.PROVENANCE_ANOMALY)
    if priv_escalation:
        triggered_codes.add(ReasonCode.PRIVILEGE_ESCALATION)

    # 2. Compound rule evaluation
    suspicious = check_suspicious_behavior(request, triggered_codes=triggered_codes)
    if suspicious:
        triggered_codes.add(ReasonCode.SUSPICIOUS_BEHAVIOR)

    # 3. Build signals in canonical order
    canonical_order = [
        (ReasonCode.CAPABILITY_MISMATCH, cap_mismatch),
        (ReasonCode.AUTHORITY_MISMATCH, auth_mismatch),
        (ReasonCode.PROVENANCE_ANOMALY, prov_anomaly),
        (ReasonCode.PRIVILEGE_ESCALATION, priv_escalation),
        (ReasonCode.SUSPICIOUS_BEHAVIOR, suspicious),
    ]

    all_signals: list[DetectionSignal] = []
    triggered_signals: list[DetectionSignal] = []
    explanations: list[str] = []

    for code, is_triggered in canonical_order:
        signal = DetectionSignal(
            code=code,
            weight=SIGNAL_WEIGHTS[code],
            triggered=is_triggered,
            explanation=SIGNAL_EXPLANATIONS[code],
        )
        all_signals.append(signal)
        if is_triggered:
            triggered_signals.append(signal)
            explanations.append(signal.explanation)

    # 4. Calculate deterministic risk score
    risk_score = calculate_risk(triggered_signals)

    return DetectionResult(
        request_id=request.request_id,
        risk_score=risk_score,
        signals=triggered_signals,
        all_signals=all_signals,
        explanations=explanations,
    )


class AnomalyDetector:
    """
    Deterministic anomaly detector interface for Kavach.
    """

    def detect(self, request: ActionRequest) -> DetectionResult:
        """Evaluate security signals for the given ActionRequest."""
        return detect(request)
