from datetime import datetime
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field


class FindingSeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class ScannerType(str, Enum):
    BANDIT = "bandit"
    SEMGREP = "semgrep"
    PIP_AUDIT = "pip_audit"
    GITLEAKS = "gitleaks"
    SANDBOX = "sandbox"


class ScanFinding(BaseModel):
    """
    A single security finding produced by one scanner tool.
    Deterministic output — no LLM involvement at this layer.
    """
    model_config = ConfigDict(extra="forbid")

    artifact_id: str = Field(..., min_length=1, description="Artifact this finding belongs to.")
    scanner: ScannerType = Field(..., description="Scanner tool that produced this finding.")
    severity: FindingSeverity = Field(..., description="Severity classification of the finding.")
    title: str = Field(..., min_length=1, description="Short finding title.")
    description: str = Field(..., min_length=1, description="Detailed description of the finding.")
    location: str | None = Field(default=None, description="File path or package name where the issue was found.")
    rule_id: str | None = Field(default=None, description="Rule or check identifier from the scanner tool.")
    cve_id: str | None = Field(default=None, description="CVE identifier if applicable (pip-audit findings).")
    raw: dict = Field(default_factory=dict, description="Raw scanner output for this finding.")
    timestamp: datetime = Field(..., description="UTC timestamp when this finding was recorded.")
