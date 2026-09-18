"""
Security Signals — deterministic signal models and risk scoring for Kavach Phase 11.

Defines the five canonical security signals, their fixed weights, human-readable
explanations, signal representation model, and risk score calculation.
"""

from typing import Iterable
from pydantic import BaseModel, ConfigDict, Field

from shield.gateway.models import ReasonCode

# Canonical signal weights — maximum possible score = 100
SIGNAL_WEIGHTS: dict[ReasonCode, int] = {
    ReasonCode.CAPABILITY_MISMATCH: 30,
    ReasonCode.AUTHORITY_MISMATCH: 25,
    ReasonCode.PROVENANCE_ANOMALY: 20,
    ReasonCode.PRIVILEGE_ESCALATION: 15,
    ReasonCode.SUSPICIOUS_BEHAVIOR: 10,
}

# Human-readable explanations for why each signal fired
SIGNAL_EXPLANATIONS: dict[ReasonCode, str] = {
    ReasonCode.CAPABILITY_MISMATCH: (
        "Declared capability does not match the capability required by the requested action"
    ),
    ReasonCode.AUTHORITY_MISMATCH: (
        "Claimed authority conflicts with the validated delegation chain or source identity"
    ),
    ReasonCode.PROVENANCE_ANOMALY: (
        "Provenance violates delegation chain integrity rules"
    ),
    ReasonCode.PRIVILEGE_ESCALATION: (
        "Requested action represents a privilege increase relative to the agent's assigned capabilities/role"
    ),
    ReasonCode.SUSPICIOUS_BEHAVIOR: (
        "High-risk compound security violation detected across multiple security dimensions"
    ),
}

# SignalType alias for backwards compatibility
SignalType = ReasonCode


class DetectionSignal(BaseModel):
    """
    Structured representation of an observable detection signal.
    """
    model_config = ConfigDict(extra="forbid")

    code: ReasonCode = Field(
        ...,
        description="Stable identifier of the security signal, reusing ReasonCode."
    )
    weight: int = Field(
        ...,
        ge=0,
        le=100,
        description="Fixed risk weight associated with this signal."
    )
    triggered: bool = Field(
        default=True,
        description="Whether this signal fired during evaluation."
    )
    explanation: str = Field(
        ...,
        min_length=1,
        description="Human-readable explanation of why this signal fired or was evaluated."
    )


# ThreatSignal alias for backwards compatibility
ThreatSignal = DetectionSignal


def calculate_risk(signals: Iterable[DetectionSignal | ReasonCode | str]) -> int:
    """
    Deterministically calculate the aggregate risk score from a collection of signals.

    Rules:
      - Starts at 0.
      - Adds the fixed weight of each unique triggered signal.
      - Bounded strictly between 0 and 100 (clamped).
      - Purely deterministic, no randomness, no LLM/ML, no hardcoding.

    Parameters:
        signals: Iterable of DetectionSignal objects, ReasonCode enums, or string names.

    Returns:
        Integer risk score between 0 and 100.
    """
    total = 0
    seen_codes: set[ReasonCode] = set()

    for item in signals:
        if isinstance(item, DetectionSignal):
            if not item.triggered:
                continue
            code = item.code
            weight = item.weight
        elif isinstance(item, ReasonCode):
            code = item
            weight = SIGNAL_WEIGHTS.get(code, 0)
        elif isinstance(item, str):
            try:
                code = ReasonCode(item)
                weight = SIGNAL_WEIGHTS.get(code, 0)
            except ValueError:
                continue
        else:
            continue

        if code not in seen_codes:
            seen_codes.add(code)
            total += weight

    return max(0, min(100, total))


class DetectionResult(BaseModel):
    """
    Detection result contract exposing risk score, triggered signals, and explanations.
    """
    model_config = ConfigDict(extra="forbid")

    request_id: str = Field(
        ...,
        min_length=1,
        description="Identifier of the evaluated request."
    )
    risk_score: int = Field(
        ...,
        ge=0,
        le=100,
        description="Calculated deterministic risk score (0-100)."
    )
    signals: list[DetectionSignal] = Field(
        default_factory=list,
        description="List of triggered security signals that contributed to the score."
    )
    all_signals: list[DetectionSignal] = Field(
        default_factory=list,
        description="All five evaluated security signals with their triggered status."
    )
    explanations: list[str] = Field(
        default_factory=list,
        description="Human-readable explanations for all triggered signals."
    )

    def has_signal(self, code: ReasonCode | str) -> bool:
        """Return True if the specified signal code was triggered."""
        target = code.value if isinstance(code, ReasonCode) else code
        return any(s.code.value == target and s.triggered for s in self.signals)

    def get_signal(self, code: ReasonCode | str) -> DetectionSignal | None:
        """Return the DetectionSignal for the given code if present in signals."""
        target = code.value if isinstance(code, ReasonCode) else code
        for s in self.signals:
            if s.code.value == target:
                return s
        return None
