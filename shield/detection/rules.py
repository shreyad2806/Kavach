"""
Detection Rules — deterministic mapping from authorization reason codes to threat signals.
"""

from shield.gateway.models import AuthorizationResult, ReasonCode
from shield.identity.models import SecurityState


_REASON_TO_SIGNAL: dict[ReasonCode, str] = {
    ReasonCode.PRIVILEGE_ESCALATION: "PRIVILEGE_ESCALATION",
    ReasonCode.CAPABILITY_MISMATCH: "CAPABILITY_ABUSE",
    ReasonCode.PROVENANCE_ANOMALY: "PROVENANCE_ANOMALY",
    ReasonCode.AGENT_QUARANTINED: "QUARANTINE_BYPASS",
    ReasonCode.AUTHORITY_MISMATCH: "LATERAL_MOVEMENT",
}


def detect(result: AuthorizationResult) -> list[str]:
    """Return threat signal names triggered by the authorization result."""
    triggered: list[str] = []
    seen: set[str] = set()

    for reason in result.reason_codes:
        signal_name = _REASON_TO_SIGNAL.get(reason)
        if signal_name and signal_name not in seen:
            seen.add(signal_name)
            triggered.append(signal_name)

    return triggered
