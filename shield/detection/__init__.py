from shield.detection.anomaly import AnomalyDetector, detect
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
    SignalType,
    ThreatSignal,
    calculate_risk,
)

__all__ = [
    "AnomalyDetector",
    "detect",
    "calculate_risk",
    "DetectionSignal",
    "ThreatSignal",
    "DetectionResult",
    "SignalType",
    "SIGNAL_WEIGHTS",
    "SIGNAL_EXPLANATIONS",
    "check_capability_mismatch",
    "check_authority_mismatch",
    "check_provenance_anomaly",
    "check_privilege_escalation",
    "check_suspicious_behavior",
]
