from datetime import datetime
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class VerdictDecision(str, Enum):
    APPROVED = "APPROVED"
    BLOCKED = "BLOCKED"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"


class ScanVerdict(BaseModel):
    """
    Final deterministic verdict for a scanned artifact.
    Produced by the verdict engine from aggregated findings and sandbox signals.
    The LLM never sets this — it only reads it to produce a human-readable explanation.
    """
    model_config = ConfigDict(extra="forbid")

    artifact_id: str = Field(..., min_length=1, description="Artifact this verdict applies to.")
    decision: VerdictDecision = Field(..., description="Final pipeline decision.")
    risk_level: RiskLevel = Field(..., description="Overall risk classification.")
    risk_score: int = Field(..., ge=0, le=100, description="Aggregate risk score (0–100).")
    finding_counts: dict[str, int] = Field(
        default_factory=dict,
        description="Count of findings per severity level, e.g. {'CRITICAL': 1, 'HIGH': 3}.",
    )
    blocked_reasons: list[str] = Field(
        default_factory=list,
        description="Human-readable reasons why the artifact was blocked or flagged.",
    )
    scanner_verdicts: dict[str, str] = Field(
        default_factory=dict,
        description="Per-scanner summary, e.g. {'bandit': 'HIGH', 'pip_audit': 'MEDIUM'}.",
    )
    sha256: str = Field(..., min_length=1, description="SHA-256 of the artifact that was scanned.")
    timestamp: datetime = Field(..., description="UTC timestamp when the verdict was produced.")
