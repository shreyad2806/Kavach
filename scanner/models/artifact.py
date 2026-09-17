from datetime import datetime
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field


class ArtifactType(str, Enum):
    PYTHON_PACKAGE = "python_package"
    GITHUB_REPO = "github_repo"
    GENERIC_FILE = "generic_file"


class ArtifactStatus(str, Enum):
    QUEUED = "QUEUED"
    DOWNLOADING = "DOWNLOADING"
    SCANNING = "SCANNING"
    SANDBOXING = "SANDBOXING"
    APPROVED = "APPROVED"
    BLOCKED = "BLOCKED"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"
    FAILED = "FAILED"


class ArtifactRequest(BaseModel):
    """
    Inbound request to scan an external artifact.
    Submitted by an agent or operator via the artifact gateway.
    """
    model_config = ConfigDict(extra="forbid")

    artifact_type: ArtifactType = Field(..., description="Type of artifact being submitted.")
    source_url: str = Field(..., min_length=1, description="External URL to download the artifact from.")
    requested_by: str = Field(..., min_length=1, description="Agent ID or operator identity submitting the request.")


class ArtifactRecord(BaseModel):
    """
    Persisted artifact record created when a scan request is accepted.
    Tracks the full lifecycle from quarantine through verdict.
    """
    model_config = ConfigDict(extra="forbid")

    artifact_id: str = Field(..., min_length=1, description="Unique artifact identifier (art-<uuid>).")
    artifact_type: ArtifactType = Field(..., description="Type of artifact.")
    source_url: str = Field(..., min_length=1, description="Original external source URL.")
    requested_by: str = Field(..., min_length=1, description="Requesting agent or operator.")
    status: ArtifactStatus = Field(default=ArtifactStatus.QUEUED, description="Current pipeline status.")
    sha256: str | None = Field(default=None, description="SHA-256 hash of the downloaded artifact.")
    quarantine_key: str | None = Field(default=None, description="S3 key in quarantine bucket.")
    approved_key: str | None = Field(default=None, description="S3 key in approved bucket, set after approval.")
    created_at: datetime = Field(..., description="UTC timestamp when the record was created.")
    updated_at: datetime = Field(..., description="UTC timestamp of the last status update.")
    # Inter-run comparison fields
    previous_sha256: str | None = Field(default=None, description="SHA-256 of the previously scanned version, if any.")
    previous_verdict: str | None = Field(default=None, description="Verdict decision from the previous scan, if any.")
    scan_count: int = Field(default=1, description="How many times this source_url has been scanned.")
