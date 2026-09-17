"""
Tests for the artifact gateway handler and downloader.
Uses moto for AWS mocks and unittest.mock to stub HTTP downloads.
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
os.environ.setdefault("PIPELINE_STATE_MACHINE_ARN", "arn:aws:states:us-east-1:123:stateMachine:test")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
os.environ.setdefault("AWS_ACCESS_KEY_ID", "test")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "test")

from moto import mock_aws

from scanner.gateway.downloader import (
    ArtifactTooLargeError,
    DownloadError,
    MAX_SIZE_BYTES,
    fetch,
)
from scanner.gateway.handler import handler
from scanner.models.artifact import ArtifactStatus
from scanner.storage.dynamodb import get_artifact


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


def _event(body: dict) -> dict:
    return {"body": json.dumps(body)}


VALID_BODY = {
    "artifact_type": "python_package",
    "source_url": "https://example.com/pkg.tar.gz",
    "requested_by": "agent-01",
}

FAKE_ARTIFACT_BYTES = b"fake package content"


# ==============================================================================
# DOWNLOADER TESTS
# ==============================================================================

def test_fetch_success():
    mock_resp = MagicMock()
    mock_resp.read.return_value = FAKE_ARTIFACT_BYTES
    mock_resp.headers.get.return_value = None
    mock_resp.__enter__ = lambda s: s
    mock_resp.__exit__ = MagicMock(return_value=False)

    with patch("urllib.request.urlopen", return_value=mock_resp):
        data = fetch("https://example.com/pkg.tar.gz")
    assert data == FAKE_ARTIFACT_BYTES


def test_fetch_too_large_via_content_length():
    mock_resp = MagicMock()
    mock_resp.headers.get.return_value = str(MAX_SIZE_BYTES + 1)
    mock_resp.__enter__ = lambda s: s
    mock_resp.__exit__ = MagicMock(return_value=False)

    with patch("urllib.request.urlopen", return_value=mock_resp):
        with pytest.raises(ArtifactTooLargeError):
            fetch("https://example.com/huge.tar.gz")


def test_fetch_too_large_via_body():
    mock_resp = MagicMock()
    mock_resp.headers.get.return_value = None
    mock_resp.read.return_value = b"x" * (MAX_SIZE_BYTES + 1)
    mock_resp.__enter__ = lambda s: s
    mock_resp.__exit__ = MagicMock(return_value=False)

    with patch("urllib.request.urlopen", return_value=mock_resp):
        with pytest.raises(ArtifactTooLargeError):
            fetch("https://example.com/huge.tar.gz")


def test_fetch_network_error():
    from urllib.error import URLError
    with patch("urllib.request.urlopen", side_effect=URLError("connection refused")):
        with pytest.raises(DownloadError):
            fetch("https://unreachable.example.com/pkg.tar.gz")


# ==============================================================================
# HANDLER TESTS
# ==============================================================================

def test_handler_success(aws_setup):
    with patch("scanner.gateway.handler.fetch", return_value=FAKE_ARTIFACT_BYTES), \
         patch("scanner.gateway.handler._start_pipeline"):
        resp = handler(_event(VALID_BODY), None)

    assert resp["statusCode"] == 201
    body = json.loads(resp["body"])
    assert body["status"] == "QUEUED"
    assert body["artifact_id"].startswith("art-")
    assert len(body["sha256"]) == 64


def test_handler_creates_artifact_record(aws_setup):
    with patch("scanner.gateway.handler.fetch", return_value=FAKE_ARTIFACT_BYTES), \
         patch("scanner.gateway.handler._start_pipeline"):
        resp = handler(_event(VALID_BODY), None)

    artifact_id = json.loads(resp["body"])["artifact_id"]
    record = get_artifact(artifact_id)
    assert record is not None
    assert record.status == ArtifactStatus.QUEUED
    assert record.sha256 is not None
    assert record.quarantine_key is not None
    assert record.quarantine_key.startswith("quarantine/")


def test_handler_invalid_artifact_type(aws_setup):
    body = {**VALID_BODY, "artifact_type": "docker_image"}
    resp = handler(_event(body), None)
    assert resp["statusCode"] == 400
    assert "Invalid request" in json.loads(resp["body"])["error"]


def test_handler_missing_field(aws_setup):
    body = {"artifact_type": "python_package", "source_url": "https://example.com/pkg.tar.gz"}
    resp = handler(_event(body), None)
    assert resp["statusCode"] == 400


def test_handler_empty_body(aws_setup):
    resp = handler({"body": "{}"}, None)
    assert resp["statusCode"] == 400


def test_handler_download_failure_marks_failed(aws_setup):
    with patch("scanner.gateway.handler.fetch", side_effect=DownloadError("timeout")):
        resp = handler(_event(VALID_BODY), None)

    assert resp["statusCode"] == 502
    assert "timeout" in json.loads(resp["body"])["error"]


def test_handler_artifact_too_large_marks_failed(aws_setup):
    with patch("scanner.gateway.handler.fetch", side_effect=ArtifactTooLargeError("too big")):
        resp = handler(_event(VALID_BODY), None)

    assert resp["statusCode"] == 400
    assert "too big" in json.loads(resp["body"])["error"]


def test_handler_quarantine_key_never_in_approved_prefix(aws_setup):
    with patch("scanner.gateway.handler.fetch", return_value=FAKE_ARTIFACT_BYTES), \
         patch("scanner.gateway.handler._start_pipeline"):
        resp = handler(_event(VALID_BODY), None)

    artifact_id = json.loads(resp["body"])["artifact_id"]
    record = get_artifact(artifact_id)
    assert record.quarantine_key.startswith("quarantine/")
    assert record.approved_key is None


def test_handler_sha256_is_deterministic(aws_setup):
    """Same bytes must always produce the same hash."""
    with patch("scanner.gateway.handler.fetch", return_value=FAKE_ARTIFACT_BYTES), \
         patch("scanner.gateway.handler._start_pipeline"):
        r1 = handler(_event(VALID_BODY), None)
    with patch("scanner.gateway.handler.fetch", return_value=FAKE_ARTIFACT_BYTES), \
         patch("scanner.gateway.handler._start_pipeline"):
        r2 = handler(_event(VALID_BODY), None)

    sha1 = json.loads(r1["body"])["sha256"]
    sha2 = json.loads(r2["body"])["sha256"]
    assert sha1 == sha2


def test_handler_first_scan_has_no_previous_fields(aws_setup):
    with patch("scanner.gateway.handler.fetch", return_value=FAKE_ARTIFACT_BYTES), \
         patch("scanner.gateway.handler._start_pipeline"):
        resp = handler(_event(VALID_BODY), None)

    artifact_id = json.loads(resp["body"])["artifact_id"]
    record = get_artifact(artifact_id)
    assert record.scan_count == 1
    assert record.previous_sha256 is None
    assert record.previous_verdict is None


def test_handler_second_scan_populates_inter_run_fields(aws_setup):
    with patch("scanner.gateway.handler.fetch", return_value=FAKE_ARTIFACT_BYTES), \
         patch("scanner.gateway.handler._start_pipeline"):
        r1 = handler(_event(VALID_BODY), None)

    # Second scan of the same URL
    with patch("scanner.gateway.handler.fetch", return_value=FAKE_ARTIFACT_BYTES), \
         patch("scanner.gateway.handler._start_pipeline"):
        r2 = handler(_event(VALID_BODY), None)

    id2 = json.loads(r2["body"])["artifact_id"]
    record2 = get_artifact(id2)
    sha1 = json.loads(r1["body"])["sha256"]

    assert record2.scan_count == 2
    assert record2.previous_sha256 == sha1


# ==============================================================================
# SSRF PROTECTION TESTS
# ==============================================================================

from scanner.gateway.downloader import SSRFBlockedError, _check_ssrf


def test_ssrf_blocks_localhost():
    with pytest.raises(SSRFBlockedError):
        _check_ssrf("http://localhost/evil")


def test_ssrf_blocks_loopback_ip():
    with pytest.raises(SSRFBlockedError):
        _check_ssrf("http://127.0.0.1/secret")


def test_ssrf_blocks_aws_metadata():
    with pytest.raises(SSRFBlockedError):
        _check_ssrf("http://169.254.169.254/latest/meta-data/")


def test_ssrf_blocks_private_10_range():
    with pytest.raises(SSRFBlockedError):
        _check_ssrf("http://10.0.0.1/internal")


def test_ssrf_blocks_private_172_range():
    with pytest.raises(SSRFBlockedError):
        _check_ssrf("http://172.16.0.1/internal")


def test_ssrf_blocks_private_192_range():
    with pytest.raises(SSRFBlockedError):
        _check_ssrf("http://192.168.1.1/internal")


def test_ssrf_handler_returns_400_on_blocked_url(aws_setup):
    with patch("scanner.gateway.handler.fetch", side_effect=SSRFBlockedError("SSRF blocked")):
        resp = handler(_event(VALID_BODY), None)
    assert resp["statusCode"] == 400
    assert "SSRF" in json.loads(resp["body"])["error"]


def test_ssrf_no_hostname_raises_download_error():
    from scanner.gateway.downloader import DownloadError
    with pytest.raises(DownloadError):
        _check_ssrf("http:///no-host")
