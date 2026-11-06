"""
Scanner agent tests.
Strands Agent and Bedrock are mocked — no real AWS calls.
Tool functions are tested directly against mocked DynamoDB via moto.
"""

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
from scanner.models.verdict import RiskLevel, ScanVerdict, VerdictDecision
from scanner.storage.dynamodb import put_artifact, put_finding, put_verdict

NOW = datetime.now(timezone.utc)


# ==============================================================================
# FIXTURES
# ==============================================================================

@pytest.fixture
def aws_setup():
    with mock_aws():
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


def _seed(artifact_id: str = "art-001"):
    put_artifact(ArtifactRecord(
        artifact_id=artifact_id,
        artifact_type=ArtifactType.PYTHON_PACKAGE,
        source_url="https://example.com/pkg.tar.gz",
        requested_by="agent-01",
        status=ArtifactStatus.BLOCKED,
        sha256="abc" * 20,
        quarantine_key="quarantine/art-001/pkg.tar.gz",
        created_at=NOW,
        updated_at=NOW,
    ))
    put_finding(ScanFinding(
        artifact_id=artifact_id,
        scanner=ScannerType.GITLEAKS,
        severity=FindingSeverity.CRITICAL,
        title="AWS secret key detected",
        description="Hardcoded AWS_SECRET_ACCESS_KEY found in config.py",
        location="config.py:10",
        rule_id="aws-access-token",
        timestamp=NOW,
    ))
    put_verdict(ScanVerdict(
        artifact_id=artifact_id,
        decision=VerdictDecision.BLOCKED,
        risk_level=RiskLevel.CRITICAL,
        risk_score=95,
        finding_counts={"CRITICAL": 1},
        blocked_reasons=["Secret detected by gitleaks: AWS secret key detected"],
        scanner_verdicts={"gitleaks": "CRITICAL"},
        sha256="abc" * 20,
        timestamp=NOW,
    ))


# ==============================================================================
# TOOL TESTS — tested directly, no agent needed
# ==============================================================================

def test_get_artifact_info_known(aws_setup):
    _seed()
    from scanner.agent.tools import get_artifact_info
    info = get_artifact_info("art-001")
    assert info["artifact_id"] == "art-001"
    assert info["status"] == "BLOCKED"
    assert info["sha256"] is not None


def test_get_artifact_info_unknown(aws_setup):
    from scanner.agent.tools import get_artifact_info
    info = get_artifact_info("art-unknown")
    assert "error" in info


def test_get_scan_findings_returns_structured_data(aws_setup):
    _seed()
    from scanner.agent.tools import get_scan_findings
    result = get_scan_findings("art-001")
    assert result["total"] == 1
    assert result["findings"][0]["severity"] == "CRITICAL"
    assert result["findings"][0]["scanner"] == "gitleaks"


def test_get_scan_findings_empty(aws_setup):
    _seed()
    from scanner.agent.tools import get_scan_findings
    result = get_scan_findings("art-no-findings")
    assert result["total"] == 0
    assert result["findings"] == []


def test_get_scan_verdict_returns_decision(aws_setup):
    _seed()
    from scanner.agent.tools import get_scan_verdict
    result = get_scan_verdict("art-001")
    assert result["decision"] == "BLOCKED"
    assert result["risk_score"] == 95
    assert len(result["blocked_reasons"]) == 1


def test_get_scan_verdict_unknown(aws_setup):
    from scanner.agent.tools import get_scan_verdict
    result = get_scan_verdict("art-no-verdict")
    assert "error" in result


def test_tools_are_read_only(aws_setup):
    """Tools must not expose any write operations."""
    import scanner.agent.tools as tools_module
    import inspect
    # Verify no write functions are exported
    exported = [name for name in dir(tools_module) if not name.startswith("_")]
    write_names = [n for n in exported if any(w in n for w in ("put", "update", "delete", "write", "create"))]
    assert write_names == [], f"Write operations found in agent tools: {write_names}"


# ==============================================================================
# AGENT INTEGRATION TEST — Strands mocked
# ==============================================================================

def test_explain_scan_calls_agent_and_returns_string(aws_setup):
    _seed()

    mock_agent_instance = MagicMock()
    mock_agent_instance.return_value = "This artifact was BLOCKED due to a hardcoded AWS secret key."

    with patch("scanner.agent.scanner_agent.Agent", return_value=mock_agent_instance):
        with patch("scanner.agent.scanner_agent.BedrockModel"):
            from scanner.agent.scanner_agent import explain_scan
            report = explain_scan("art-001")

    assert isinstance(report, str)
    assert len(report) > 0


def test_explain_scan_prompt_contains_artifact_id(aws_setup):
    _seed()

    mock_agent_instance = MagicMock()
    mock_agent_instance.return_value = "Report for art-001"

    with patch("scanner.agent.scanner_agent.Agent", return_value=mock_agent_instance):
        with patch("scanner.agent.scanner_agent.BedrockModel"):
            from scanner.agent.scanner_agent import explain_scan
            explain_scan("art-001")

    call_args = mock_agent_instance.call_args[0][0]
    assert "art-001" in call_args


def test_system_prompt_contains_untrusted_data_rule():
    from scanner.agent.prompts import SYSTEM_PROMPT
    assert "untrusted" in SYSTEM_PROMPT.lower()
    assert "never" in SYSTEM_PROMPT.lower()


def test_system_prompt_forbids_verdict_modification():
    from scanner.agent.prompts import SYSTEM_PROMPT
    assert "cannot" in SYSTEM_PROMPT.lower() or "must never" in SYSTEM_PROMPT.lower()
