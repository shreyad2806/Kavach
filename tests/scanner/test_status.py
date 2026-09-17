"""
Tests for the artifact status endpoint (GET /artifacts/{id}).
"""

import json
import os
from datetime import datetime, timezone
from unittest.mock import patch

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

from scanner.gateway.status import handler
from scanner.models.artifact import ArtifactRecord, ArtifactStatus, ArtifactType
from scanner.models.finding import FindingSeverity, ScanFinding, ScannerType
from scanner.models.verdict import RiskLevel, ScanVerdict, VerdictDecision
from scanner.storage.dynamodb import put_artifact, put_finding, put_verdict

NOW = datetime.now(timezone.utc)


@pytest.fixture
def aws_setup():
    with mock_aws():
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        ddb.create_table(
            TableName="test-artifacts",
            KeySchema=[{"AttributeName": "artifact_id", "KeyType": "HASH"}],
            AttributeDefinitions=[
                {"AttributeName": "artifact_id", "AttributeType": "S"},
                {"AttributeName": "source_url", "AttributeType": "S"},
                {"AttributeName": "created_at", "AttributeType": "S"},
            ],
            GlobalSecondaryIndexes=[{
                "IndexName": "SourceUrlIndex",
                "KeySchema": [
                    {"AttributeName": "source_url", "KeyType": "HASH"},
                    {"AttributeName": "created_at", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            }],
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


def _seed_artifact(artifact_id="art-001", status=ArtifactStatus.QUEUED):
    record = ArtifactRecord(
        artifact_id=artifact_id,
        artifact_type=ArtifactType.PYTHON_PACKAGE,
        source_url="https://example.com/pkg.tar.gz",
        requested_by="agent-01",
        status=status,
        sha256="abc" * 20,
        quarantine_key="quarantine/art-001/pkg.tar.gz",
        created_at=NOW,
        updated_at=NOW,
    )
    put_artifact(record)
    return record


def _event(artifact_id: str) -> dict:
    return {"pathParameters": {"artifact_id": artifact_id}}


def test_status_returns_404_for_unknown_artifact(aws_setup):
    resp = handler(_event("art-unknown"), None)
    assert resp["statusCode"] == 404
    assert "not found" in json.loads(resp["body"])["error"]


def test_status_returns_400_for_missing_id(aws_setup):
    resp = handler({}, None)
    assert resp["statusCode"] == 400


def test_status_queued_artifact(aws_setup):
    _seed_artifact()
    resp = handler(_event("art-001"), None)
    assert resp["statusCode"] == 200
    body = json.loads(resp["body"])
    assert body["artifact_id"] == "art-001"
    assert body["status"] == "QUEUED"
    assert body["total_findings"] == 0
    assert "verdict" not in body


def test_status_includes_finding_counts(aws_setup):
    _seed_artifact()
    put_finding(ScanFinding(
        artifact_id="art-001", scanner=ScannerType.BANDIT,
        severity=FindingSeverity.HIGH, title="Issue", description="desc", timestamp=NOW,
    ))
    put_finding(ScanFinding(
        artifact_id="art-001", scanner=ScannerType.GITLEAKS,
        severity=FindingSeverity.CRITICAL, title="Secret", description="desc", timestamp=NOW,
    ))
    resp = handler(_event("art-001"), None)
    body = json.loads(resp["body"])
    assert body["total_findings"] == 2
    assert body["finding_counts"]["HIGH"] == 1
    assert body["finding_counts"]["CRITICAL"] == 1


def test_status_includes_verdict_when_complete(aws_setup):
    _seed_artifact(status=ArtifactStatus.APPROVED)
    verdict = ScanVerdict(
        artifact_id="art-001",
        decision=VerdictDecision.APPROVED,
        risk_level=RiskLevel.LOW,
        risk_score=5,
        sha256="abc" * 20,
        timestamp=NOW,
    )
    put_verdict(verdict)
    resp = handler(_event("art-001"), None)
    body = json.loads(resp["body"])
    assert body["verdict"]["decision"] == "APPROVED"
    assert body["verdict"]["risk_score"] == 5


def test_status_includes_agent_report(aws_setup):
    _seed_artifact(status=ArtifactStatus.APPROVED)
    verdict = ScanVerdict(
        artifact_id="art-001",
        decision=VerdictDecision.APPROVED,
        risk_level=RiskLevel.LOW,
        risk_score=0,
        sha256="abc" * 20,
        timestamp=NOW,
    )
    put_verdict(verdict, agent_report="This artifact is clean.")
    resp = handler(_event("art-001"), None)
    body = json.loads(resp["body"])
    assert body["agent_report"] == "This artifact is clean."


def test_status_direct_invocation_without_path_params(aws_setup):
    _seed_artifact()
    resp = handler({"artifact_id": "art-001"}, None)
    assert resp["statusCode"] == 200
    assert json.loads(resp["body"])["artifact_id"] == "art-001"
