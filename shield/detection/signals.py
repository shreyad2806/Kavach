"""
Security signal catalogue and bounded deterministic risk scoring.

Weights are risk contributions, not authorization authority. All signals are
deduplicated before scoring and a score never changes ALLOW/DENY.
"""
from typing import Iterable

from pydantic import BaseModel, ConfigDict, Field

from shield.gateway.models import ReasonCode


SIGNAL_WEIGHTS: dict[ReasonCode, int] = {
    ReasonCode.CAPABILITY_MISMATCH: 28,
    ReasonCode.AUTHORITY_MISMATCH: 24,
    ReasonCode.PROVENANCE_ANOMALY: 24,
    ReasonCode.PRIVILEGE_ESCALATION: 24,
    ReasonCode.SUSPICIOUS_BEHAVIOR: 14,
    ReasonCode.POLICY_DENIED: 20,
    ReasonCode.AGENT_QUARANTINED: 35,
    ReasonCode.IDENTITY_FAILURE: 40,
}

SIGNAL_EXPLANATIONS: dict[ReasonCode, str] = {
    ReasonCode.CAPABILITY_MISMATCH: "The presented capability does not match the requested action.",
    ReasonCode.AUTHORITY_MISMATCH: "The claimed authority does not match the request's delegation lineage.",
    ReasonCode.PROVENANCE_ANOMALY: "The delegation lineage is malformed or contains an unsupported delegation edge.",
    ReasonCode.PRIVILEGE_ESCALATION: "The requesting agent is attempting an action outside its assigned role boundary.",
    ReasonCode.SUSPICIOUS_BEHAVIOR: "Multiple independent security invariants were violated in one request.",
    ReasonCode.POLICY_DENIED: "The active Cedar policy denied this request.",
    ReasonCode.AGENT_QUARANTINED: "The requesting agent is already in a quarantined state.",
    ReasonCode.IDENTITY_FAILURE: "The requesting agent is not present in the trusted identity registry.",
}

# SignalType remains as a compatibility alias for existing imports.
SignalType = ReasonCode
ThreatSignal = None


class DetectionSignal(BaseModel):
    model_config = ConfigDict(extra="forbid")

    code: ReasonCode
    weight: int = Field(ge=0, le=100)
    triggered: bool = True
    explanation: str = Field(min_length=1)


def calculate_risk(signals: Iterable[DetectionSignal | ReasonCode | str]) -> int:
    total = 0
    seen: set[ReasonCode] = set()
    for item in signals:
        if isinstance(item, DetectionSignal):
            if not item.triggered:
                continue
            code, weight = item.code, item.weight
        else:
            try:
                code = item if isinstance(item, ReasonCode) else ReasonCode(item)
            except (ValueError, TypeError):
                continue
            weight = SIGNAL_WEIGHTS.get(code, 0)
        if code not in seen:
            seen.add(code)
            total += weight
    return min(100, max(0, total))


class DetectionResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    request_id: str = Field(min_length=1)
    risk_score: int = Field(ge=0, le=100)
    signals: list[DetectionSignal] = Field(default_factory=list)
    all_signals: list[DetectionSignal] = Field(default_factory=list)
    explanations: list[str] = Field(default_factory=list)

    def has_signal(self, code: ReasonCode | str) -> bool:
        target = code.value if isinstance(code, ReasonCode) else code
        return any(s.code.value == target and s.triggered for s in self.signals)

    def get_signal(self, code: ReasonCode | str) -> DetectionSignal | None:
        target = code.value if isinstance(code, ReasonCode) else code
        return next((s for s in self.signals if s.code.value == target), None)
