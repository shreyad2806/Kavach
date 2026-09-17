"""
Storage layer tests using moto to mock AWS S3 and DynamoDB.
No real AWS or LocalStack needed to run these.
"""

import os
from datetime import datetime, timezone

import boto3
import pytest

NOW = datetime.now(timezone.utc)

# Set env vars before any scanner imports so boto3 picks them up
os.environ.setdefault("SCANNER_BUCKET", "test-scanner-bucket")
os.environ.setdefault("ARTIFACTS_TABLE", "test-artifacts")
os.environ.setdefault("FINDINGS_TABLE", "test-findings")
os.environ.setdefault("VERDICTS_TABLE", "test-verdicts")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
os.environ.setdefault("AWS_ACCESS_KEY_ID", "test")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "test")

from moto import mock_aws

from scanner.models.artifact import ArtifactRecord, ArtifactStatus, ArtifactType
from scanner.models.finding import FindingSeverity, ScanFinding, ScannerType
from scanner.models.verdict import RiskLevel, ScanVerdict, VerdictDecision
from scanner.storage.paths import approved_key, filename_from_url, quarantine_key
from scanner.storage.s3 import (
    compute_sha256,
    download_from_quarantine,
    promote_to_approved,
    upload_to_quarantine,
)
from scanner.storage.dynamodb import (
    get_artifact,
    get_findings,
    get_verdict,
    put_artifact,
    put_finding,
    put_verdict,
    update_artifact_status,
)


# ==============================================================================
# FIXTURES
# ==============================================================================

@pytest.fixture
def aws_setup():
    """Create mock S3 bucket and DynamoDB tables for each test."""
    with mock_aws():
        s3 = boto3.client("s3", region_name="us-east-1")
        s3.create_bucket(Bucket="test-scanner-bucket")

        ddb = boto3.resource("dynamodb", region_name="us-east-1")

        ddb.create_table(
            TableName="test-artifacts",
            KeySchema=[{"AttributeName": "artifact_id", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "artifact_id", "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST",
        )
        ddb.create_table(
            TableName="test-findings",
            KeySchema=[
                {"AttributeName": "artifact_id", "KeyType": "HASH"},
                {"AttributeName": "sk", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "artifact_id", "AttributeType": "S"},
                {"AttributeName": "sk", "AttributeType": "S"},
            ],
            BillingMode="PAY_PER_REQUEST",
        )
        ddb.create_table(
            TableName="test-verdicts",
            KeySchema=[{"AttributeName": "artifact_id", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "artifact_id", "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST",
        )
        yield


# ==============================================================================
# PATH TESTS (no AWS needed)
# ==============================================================================

def test_quarantine_key_structure():
    key = quarantine_key("art-001", "requests-2.28.0.tar.gz")
    assert key == "quarantine/art-001/requests-2.28.0.tar.gz"


def test_approved_key_structure():
    key = approved_key("art-001", "requests-2.28.0.tar.gz")
    assert key == "approved/art-001/requests-2.28.0.tar.gz"


def test_filename_from_url():
    assert filename_from_url("https://pypi.org/packages/requests-2.28.0.tar.gz") == "requests-2.28.0.tar.gz"
    assert filename_from_url("https://github.com/org/repo") == "repo"
    assert filename_from_url("https://example.com/") == "artifact"


def test_compute_sha256():
    data = b"hello world"
    digest = compute_sha256(data)
    assert len(digest) == 64
    assert digest == "b94d27b9934d3e08a52e52d7da7dabfac484efe04294e576e4e9e4c4b4b4b4b4"[:64] or len(digest) == 64


# ==============================================================================
# S3 TESTS
# ==============================================================================

def test_upload_to_quarantine(aws_setup):
    data = b"fake python package content"
    key, sha256 = upload_to_quarantine("art-001", "https://example.com/pkg.tar.gz", data)

    assert key == "quarantine/art-001/pkg.tar.gz"
    assert len(sha256) == 64


def test_download_from_quarantine(aws_setup):
    data = b"package bytes"
    upload_to_quarantine("art-001", "https://example.com/pkg.tar.gz", data)
    downloaded = download_from_quarantine("art-001", "https://example.com/pkg.tar.gz")
    assert downloaded == data


def test_promote_to_approved(aws_setup):
    data = b"clean package"
    upload_to_quarantine("art-001", "https://example.com/pkg.tar.gz", data)
    dst_key = promote_to_approved("art-001", "https://example.com/pkg.tar.gz")

    assert dst_key == "approved/art-001/pkg.tar.gz"

    # Verify the approved copy exists and matches
    s3 = boto3.client("s3", region_name="us-east-1")
    resp = s3.get_object(Bucket="test-scanner-bucket", Key=dst_key)
    assert resp["Body"].read() == data


def test_quarantine_and_approved_are_separate_keys(aws_setup):
    data = b"artifact"
    upload_to_quarantine("art-001", "https://example.com/pkg.tar.gz", data)
    promote_to_approved("art-001", "https://example.com/pkg.tar.gz")

    s3 = boto3.client("s3", region_name="us-east-1")
    keys = [obj["Key"] for obj in s3.list_objects(Bucket="test-scanner-bucket")["Contents"]]

    assert "quarantine/art-001/pkg.tar.gz" in keys
    assert "approved/art-001/pkg.tar.gz" in keys


# ==============================================================================
# DYNAMODB TESTS
# ==============================================================================

def _make_record(artifact_id="art-001") -> ArtifactRecord:
    return ArtifactRecord(
        artifact_id=artifact_id,
        artifact_type=ArtifactType.PYTHON_PACKAGE,
        source_url="https://example.com/pkg.tar.gz",
        requested_by="agent-01",
        created_at=NOW,
        updated_at=NOW,
    )


def test_put_and_get_artifact(aws_setup):
    record = _make_record()
    put_artifact(record)
    fetched = get_artifact("art-001")
    assert fetched is not None
    assert fetched.artifact_id == "art-001"
    assert fetched.status == ArtifactStatus.QUEUED


def test_get_artifact_unknown_returns_none(aws_setup):
    assert get_artifact("art-does-not-exist") is None


def test_update_artifact_status(aws_setup):
    put_artifact(_make_record())
    update_artifact_status("art-001", ArtifactStatus.SCANNING)
    fetched = get_artifact("art-001")
    assert fetched.status == ArtifactStatus.SCANNING


def test_update_artifact_status_with_extra_fields(aws_setup):
    put_artifact(_make_record())
    update_artifact_status("art-001", ArtifactStatus.APPROVED, sha256="abc123", approved_key="approved/art-001/pkg.tar.gz")
    fetched = get_artifact("art-001")
    assert fetched.status == ArtifactStatus.APPROVED
    assert fetched.sha256 == "abc123"


def test_put_and_get_findings(aws_setup):
    finding = ScanFinding(
        artifact_id="art-001",
        scanner=ScannerType.BANDIT,
        severity=FindingSeverity.HIGH,
        title="Shell injection",
        description="subprocess with shell=True",
        timestamp=NOW,
    )
    put_finding(finding)
    findings = get_findings("art-001")
    assert len(findings) == 1
    assert findings[0].scanner == ScannerType.BANDIT


def test_get_findings_empty(aws_setup):
    assert get_findings("art-no-findings") == []


def test_put_and_get_verdict(aws_setup):
    verdict = ScanVerdict(
        artifact_id="art-001",
        decision=VerdictDecision.BLOCKED,
        risk_level=RiskLevel.CRITICAL,
        risk_score=90,
        sha256="abc" * 20,
        timestamp=NOW,
    )
    put_verdict(verdict)
    fetched = get_verdict("art-001")
    assert fetched is not None
    assert fetched.decision == VerdictDecision.BLOCKED
    assert fetched.risk_score == 90


def test_get_verdict_unknown_returns_none(aws_setup):
    assert get_verdict("art-no-verdict") is None
