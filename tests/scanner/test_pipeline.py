"""
Pipeline handler tests.
All AWS calls mocked via moto. Scanners and sandbox mocked via unittest.mock.
"""

import json
import os
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import boto3
import pytest

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
from scanner.models.sandbox import SandboxReport
from scanner.models.verdict import RiskLevel, VerdictDecision
from scanner.pipeline.handler import handler
from scanner.storage.dynamodb import get_artifact, get_findings, get_verdict, put_artifact
from scanner.storage.s3 import upload_to_quarantine

NOW = datetime.now(timezone.utc)


# ==============================================================================
# FIXTURES
# ==============================================================================

@pytest.fixture
def aws_setup():
    with mock_aws():
        boto3.client("s3", region_name="us-east-1").create_bucket(Bucket="test-scanner-bucket")
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


def _seed_artifact(artifact_id: str = "art-001") -> ArtifactRecord:
    record = ArtifactRecord(
        artifact_id=artifact_id,
        artifact_type=ArtifactType.PYTHON_PACKAGE,
        source_url="https://example.com/pkg.tar.gz",
        requested_by="agent-01",
        status=ArtifactStatus.QUEUED,
        sha256="abc" * 20,
        quarantine_key="quarantine/art-001/pkg.tar.gz",
        created_at=NOW,
        updated_at=NOW,
    )
    put_artifact(record)
    return record


def _empty_findings() -> list:
    return []


def _one_high_finding(artifact_id: str = "art-001") -> list[ScanFinding]:
    return [ScanFinding(
        artifact_id=artifact_id,
        scanner=ScannerType.BANDIT,
        severity=FindingSeverity.HIGH,
        title="Shell injection",
        description="subprocess with shell=True",
        timestamp=NOW,
    )]


def _clean_sandbox_report(artifact_id: str = "art-001") -> SandboxReport:
    return SandboxReport(
        artifact_id=artifact_id,
        executed=True,
        exit_code=0,
        events=[],
        suspicious_event_count=0,
        timestamp=NOW,
    )


# ==============================================================================
# MISSING / INVALID INPUT
# ==============================================================================

def test_missing_stage_returns_error(aws_setup):
    resp = handler({"artifact_id": "art-001"}, None)
    assert resp["status"] == "ERROR"
    assert "stage" in resp["error"]


def test_missing_artifact_id_returns_error(aws_setup):
    resp = handler({"stage": "static_scan"}, None)
    assert resp["status"] == "ERROR"


def test_unknown_artifact_returns_error(aws_setup):
    resp = handler({"stage": "static_scan", "artifact_id": "art-unknown", "scanner": "bandit"}, None)
    assert resp["status"] == "ERROR"
    assert "not found" in resp["error"]


def test_unknown_scanner_returns_error(aws_setup):
    _seed_artifact()
    resp = handler({"stage": "static_scan", "artifact_id": "art-001", "scanner": "trivy"}, None)
    assert resp["status"] == "ERROR"
    assert "Unknown scanner" in resp["error"]


def test_unknown_stage_returns_error(aws_setup):
    _seed_artifact()
    resp = handler({"stage": "magic_scan", "artifact_id": "art-001"}, None)
    assert resp["status"] == "ERROR"


# ==============================================================================
# STATIC SCAN STAGE
# ==============================================================================

def test_static_scan_bandit_success(aws_setup):
    _seed_artifact()
    upload_to_quarantine("art-001", "https://example.com/pkg.tar.gz", b"print('hello')")

    with patch("scanner.pipeline.handler.BanditScanner.scan", return_value=_one_high_finding()):
        resp = handler({"stage": "static_scan", "artifact_id": "art-001", "scanner": "bandit"}, None)

    assert resp["status"] == "OK"
    assert resp["scanner"] == "bandit"
    assert resp["finding_count"] == 1


def test_static_scan_stores_findings_in_dynamodb(aws_setup):
    _seed_artifact()
    upload_to_quarantine("art-001", "https://example.com/pkg.tar.gz", b"code")

    with patch("scanner.pipeline.handler.BanditScanner.scan", return_value=_one_high_finding()):
        handler({"stage": "static_scan", "artifact_id": "art-001", "scanner": "bandit"}, None)

    findings = get_findings("art-001")
    assert len(findings) == 1
    assert findings[0].scanner == ScannerType.BANDIT


def test_static_scan_no_findings_is_ok(aws_setup):
    _seed_artifact()
    upload_to_quarantine("art-001", "https://example.com/pkg.tar.gz", b"code")

    with patch("scanner.pipeline.handler.GitleaksScanner.scan", return_value=[]):
        resp = handler({"stage": "static_scan", "artifact_id": "art-001", "scanner": "gitleaks"}, None)

    assert resp["status"] == "OK"
    assert resp["finding_count"] == 0


def test_static_scan_updates_status_to_scanning(aws_setup):
    _seed_artifact()
    upload_to_quarantine("art-001", "https://example.com/pkg.tar.gz", b"code")

    with patch("scanner.pipeline.handler.SemgrepScanner.scan", return_value=[]):
        handler({"stage": "static_scan", "artifact_id": "art-001", "scanner": "semgrep"}, None)

    record = get_artifact("art-001")
    assert record.status == ArtifactStatus.SCANNING


# ==============================================================================
# SANDBOX STAGE
# ==============================================================================

def test_sandbox_stage_success(aws_setup):
    _seed_artifact()
    upload_to_quarantine("art-001", "https://example.com/pkg.tar.gz", b"print('hello')")

    with patch("scanner.pipeline.handler.sandbox_run", return_value=_clean_sandbox_report()):
        resp = handler({"stage": "sandbox", "artifact_id": "art-001"}, None)

    assert resp["status"] == "OK"
    assert resp["executed"] is True
    assert resp["suspicious_event_count"] == 0


def test_sandbox_stage_updates_status(aws_setup):
    _seed_artifact()
    upload_to_quarantine("art-001", "https://example.com/pkg.tar.gz", b"code")

    with patch("scanner.pipeline.handler.sandbox_run", return_value=_clean_sandbox_report()):
        handler({"stage": "sandbox", "artifact_id": "art-001"}, None)

    record = get_artifact("art-001")
    assert record.status == ArtifactStatus.SANDBOXING


# ==============================================================================
# VERDICT STAGE
# ==============================================================================

def test_verdict_stage_approved(aws_setup):
    _seed_artifact()
    upload_to_quarantine("art-001", "https://example.com/pkg.tar.gz", b"clean code")

    resp = handler({"stage": "verdict", "artifact_id": "art-001"}, None)

    assert resp["status"] == "OK"
    assert resp["decision"] == "APPROVED"
    record = get_artifact("art-001")
    assert record.status == ArtifactStatus.APPROVED
    assert record.approved_key is not None
    assert record.approved_key.startswith("approved/")


def test_verdict_stage_blocked_on_critical_finding(aws_setup):
    _seed_artifact()
    upload_to_quarantine("art-001", "https://example.com/pkg.tar.gz", b"malicious")

    # Pre-seed a CRITICAL gitleaks finding
    from scanner.storage.dynamodb import put_finding
    put_finding(ScanFinding(
        artifact_id="art-001",
        scanner=ScannerType.GITLEAKS,
        severity=FindingSeverity.CRITICAL,
        title="AWS key found",
        description="Hardcoded AWS secret",
        timestamp=NOW,
    ))

    resp = handler({"stage": "verdict", "artifact_id": "art-001"}, None)

    assert resp["status"] == "OK"
    assert resp["decision"] == "BLOCKED"
    record = get_artifact("art-001")
    assert record.status == ArtifactStatus.BLOCKED
    assert record.approved_key is None


def test_verdict_stage_stores_verdict(aws_setup):
    _seed_artifact()
    upload_to_quarantine("art-001", "https://example.com/pkg.tar.gz", b"code")

    handler({"stage": "verdict", "artifact_id": "art-001"}, None)

    verdict = get_verdict("art-001")
    assert verdict is not None
    assert verdict.artifact_id == "art-001"
    assert verdict.decision in (VerdictDecision.APPROVED, VerdictDecision.BLOCKED, VerdictDecision.REVIEW_REQUIRED)


def test_blocked_artifact_never_promoted_to_approved(aws_setup):
    _seed_artifact()
    upload_to_quarantine("art-001", "https://example.com/pkg.tar.gz", b"malicious")

    from scanner.storage.dynamodb import put_finding
    put_finding(ScanFinding(
        artifact_id="art-001",
        scanner=ScannerType.GITLEAKS,
        severity=FindingSeverity.CRITICAL,
        title="Secret",
        description="Leaked key",
        timestamp=NOW,
    ))

    handler({"stage": "verdict", "artifact_id": "art-001"}, None)

    # Approved prefix must be empty
    s3 = boto3.client("s3", region_name="us-east-1")
    objects = s3.list_objects(Bucket="test-scanner-bucket").get("Contents", [])
    approved_keys = [o["Key"] for o in objects if o["Key"].startswith("approved/")]
    assert approved_keys == []
