"""
Detection Rules — deterministic mapping from authorization reason codes to threat signals.
"""

from kavach.detection.signals import SignalType, ThreatSignal, SIGNAL_MAP
from kavach.gateway.models import AuthorizationResult, ReasonCode
from kavach.identity.models import SecurityState


_REASON_TO_SIGNAL: dict[ReasonCode, SignalType] = {
    ReasonCode.PRIVILEGE_ESCALATION: SignalType.PRIVILEGE_ESCALATION,
    ReasonCode.CAPABILITY_MISMATCH: SignalType.CAPABILITY_ABUSE,
    ReasonCode.PROVENANCE_ANOMALY: SignalType.PROVENANCE_ANOMALY,
    ReasonCode.AGENT_QUARANTINED: SignalType.QUARANTINE_BYPASS,
    ReasonCode.AUTHORITY_MISMATCH: SignalType.LATERAL_MOVEMENT,
}


def detect(result: AuthorizationResult) -> list[ThreatSignal]:
    """Return threat signals triggered by the authorization result."""
    triggered: list[ThreatSignal] = []
    seen: set[SignalType] = set()

    for reason in result.reason_codes:
        signal_type = _REASON_TO_SIGNAL.get(reason)
        if signal_type and signal_type not in seen:
            seen.add(signal_type)
            triggered.append(SIGNAL_MAP[signal_type])

    return triggered
