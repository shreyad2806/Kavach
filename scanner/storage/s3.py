"""
S3 storage operations for the scanner pipeline.

Quarantine bucket  — artifacts land here first, inaccessible to agents.
Approved bucket    — artifacts move here only after a clean verdict.

Reads SCANNER_BUCKET and AWS region from environment.
For local dev, point AWS_ENDPOINT_URL at LocalStack.
"""

import hashlib
import os

import boto3

from scanner.storage.paths import approved_key, quarantine_key, filename_from_url


def _s3():
    endpoint = os.environ.get("AWS_ENDPOINT_URL")
    return boto3.client("s3", endpoint_url=endpoint)


def _bucket() -> str:
    return os.environ["SCANNER_BUCKET"]


def compute_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def upload_to_quarantine(artifact_id: str, source_url: str, data: bytes) -> tuple[str, str]:
    """
    Upload raw artifact bytes to the quarantine prefix.
    Returns (s3_key, sha256).
    Agents have no access to this prefix.
    """
    filename = filename_from_url(source_url)
    key = quarantine_key(artifact_id, filename)
    sha256 = compute_sha256(data)

    _s3().put_object(
        Bucket=_bucket(),
        Key=key,
        Body=data,
        Metadata={"sha256": sha256, "artifact_id": artifact_id},
        ServerSideEncryption="AES256",
    )
    return key, sha256


def promote_to_approved(artifact_id: str, source_url: str) -> str:
    """
    Copy the artifact from quarantine to the approved prefix.
    Called only after a clean verdict — agents can access approved/ only.
    Returns the approved S3 key.
    """
    filename = filename_from_url(source_url)
    src_key = quarantine_key(artifact_id, filename)
    dst_key = approved_key(artifact_id, filename)

    _s3().copy_object(
        Bucket=_bucket(),
        CopySource={"Bucket": _bucket(), "Key": src_key},
        Key=dst_key,
        ServerSideEncryption="AES256",
    )
    return dst_key


def download_from_quarantine(artifact_id: str, source_url: str) -> bytes:
    """Read artifact bytes from quarantine (scanner use only)."""
    filename = filename_from_url(source_url)
    key = quarantine_key(artifact_id, filename)
    response = _s3().get_object(Bucket=_bucket(), Key=key)
    return response["Body"].read()


def generate_approved_presigned_url(artifact_id: str, source_url: str, expires_in: int = 3600) -> str:
    """
    Generate a time-limited pre-signed URL for an approved artifact.
    Agents receive this URL — they never get direct bucket access.
    """
    filename = filename_from_url(source_url)
    key = approved_key(artifact_id, filename)
    return _s3().generate_presigned_url(
        "get_object",
        Params={"Bucket": _bucket(), "Key": key},
        ExpiresIn=expires_in,
    )
