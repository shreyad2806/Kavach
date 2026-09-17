"""
S3 key path construction for quarantine and approved artifact storage.
All path logic lives here so nothing else hardcodes bucket structure.
"""

from urllib.parse import urlparse

QUARANTINE_PREFIX = "quarantine"
APPROVED_PREFIX = "approved"


def quarantine_key(artifact_id: str, filename: str) -> str:
    return f"{QUARANTINE_PREFIX}/{artifact_id}/{filename}"


def approved_key(artifact_id: str, filename: str) -> str:
    return f"{APPROVED_PREFIX}/{artifact_id}/{filename}"


def filename_from_url(source_url: str) -> str:
    """Extract a safe filename from a source URL."""
    path = urlparse(source_url).path.rstrip("/")
    name = path.split("/")[-1] if path else ""
    return name if name else "artifact"
