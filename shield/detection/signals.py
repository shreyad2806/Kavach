"""
Security Signals — stable deterministic weights and explainable risk output.

The weights are intentionally compatible with the original Kavach score model.
Contextual findings are folded into SUSPICIOUS_BEHAVIOR so existing clients and
ReasonCode enums remain backward-compatible.
"""
from typing import Iterable

from pydantic import BaseModel, ConfigDict, Field

from shield.gateway.models import ReasonCode

SIGNAL_WEIGHTS: dict[ReasonCode, int] = {
    ReasonCode.CAPABILITY_MISMATCH: 30,
    ReasonCode.AUTHORITY_MISMATCH: 25,
    ReasonCode.PROVENANCE_ANOMALY: 20,
    ReasonCode.PRIVILEGE_ESCALATION: 15,
    ReasonCode.SUSPICIOUS_BEHAVIOR: 10,
    # Additional existing authorization reasons, used in early-return paths.
    ReasonCode.IDENTITY_FAILURE: 40,
    ReasonCode.AGENT_QUARANTINED: 35,
    ReasonCode.POLICY_DENIED: 20,
}

SIGNAL_EXPLANATIONS: dict[ReasonCode, str] = {
    ReasonCode.CAPABILITY_MISMATCH: "Declared capability does not match the capability required by the requested action.",
    ReasonCode.AUTHORITY_MISMATCH: "Claimed authority conflicts with the validated delegation chain or source identity.",
    ReasonCode.PROVENANCE_ANOMALY: "Provenance violates delegation chain integrity or supported delegation relationships.",
    ReasonCode.PRIVILEGE_ESCALATION: "The requested action exceeds the requesting agent's assigned role boundary.",
    ReasonCode.SUSPICIOUS_BEHAVIOR: "A contextual or compound security invariant was violated by this request.",
    ReasonCode.IDENTITY_FAILURE: "The requesting agent is not registered in the trusted identity registry.",
    ReasonCode.AGENT_QUARANTINED: "The requesting agent is quarantined and cannot perform protected operations.",
    ReasonCode.POLICY_DENIED: "The active Cedar authorization policy denied this operation.",
}

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
    return max(0, min(100, total))


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
