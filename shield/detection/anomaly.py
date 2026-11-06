"""
Context-aware deterministic anomaly orchestration for Kavach Shield.

This module consumes a typed ActionRequest and observable request metadata.
It makes no network calls and cannot mutate identity/policy state. The result
is advisory telemetry; authorization remains exclusively in authorize().
"""
from shield.detection.rules import (
    check_authority_mismatch,
    check_capability_mismatch,
    check_delegation_depth,
    check_environment_context,
    check_privilege_escalation,
    check_provenance_anomaly,
    check_sensitive_resource_mismatch,
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


# Contextual rules use existing reason codes so event and API contracts remain
# backward-compatible. Their explanations identify the concrete sub-condition.
_CONTEXT_EXPLANATIONS = {
    "SENSITIVE_RESOURCE_MISMATCH": "The action is not an expected operation for the sensitivity of the target resource.",
    "DELEGATION_DEPTH_EXCEEDED": "The delegation chain exceeds the currently supported trust boundary.",
    "UNSAFE_ENVIRONMENT_CONTEXT": "Environment metadata combines production with debug or an untrusted trust label.",
}


def _evaluate(request: ActionRequest) -> list[tuple[ReasonCode, bool, str]]:
    checks = [
        (ReasonCode.CAPABILITY_MISMATCH, check_capability_mismatch(request)),
        (ReasonCode.AUTHORITY_MISMATCH, check_authority_mismatch(request)),
        (ReasonCode.PROVENANCE_ANOMALY, check_provenance_anomaly(request)),
        (ReasonCode.PRIVILEGE_ESCALATION, check_privilege_escalation(request)),
    ]
    primary = {code for code, fired in checks if fired}
    suspicious = check_suspicious_behavior(request, primary)

    # Fold additional contextual violations into the existing compound
    # signal's explanation while retaining distinct, inspectable findings.
    contextual = []
    if check_sensitive_resource_mismatch(request):
        contextual.append(("resource", _CONTEXT_EXPLANATIONS["SENSITIVE_RESOURCE_MISMATCH"]))
    if check_delegation_depth(request):
        contextual.append(("delegation", _CONTEXT_EXPLANATIONS["DELEGATION_DEPTH_EXCEEDED"]))
    if check_environment_context(request):
        contextual.append(("environment", _CONTEXT_EXPLANATIONS["UNSAFE_ENVIRONMENT_CONTEXT"]))

    return [
        (code, fired, SIGNAL_EXPLANATIONS[code])
        for code, fired in checks
    ] + [
        (
            ReasonCode.SUSPICIOUS_BEHAVIOR,
            suspicious or bool(contextual),
            (
                SIGNAL_EXPLANATIONS[ReasonCode.SUSPICIOUS_BEHAVIOR]
                if suspicious else "; ".join(message for _, message in contextual)
            ),
        )
    ]


def detect(request: ActionRequest) -> DetectionResult:
    """Return deterministic signals and a bounded, advisory risk score."""
    evaluated = _evaluate(request)
    all_signals = [
        DetectionSignal(
            code=code,
            weight=SIGNAL_WEIGHTS[code],
            triggered=fired,
            explanation=explanation,
        )
        for code, fired, explanation in evaluated
    ]
    triggered = [signal for signal in all_signals if signal.triggered]
    explanations = [signal.explanation for signal in triggered]
    return DetectionResult(
        request_id=request.request_id,
        risk_score=calculate_risk(triggered),
        signals=triggered,
        all_signals=all_signals,
        explanations=explanations,
    )


class AnomalyDetector:
    """Small dependency-free facade used by the authorization pipeline."""

    def detect(self, request: ActionRequest) -> DetectionResult:
        return detect(request)
