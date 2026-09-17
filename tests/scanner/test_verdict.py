"""
Verdict engine and scorer tests.
Fully deterministic — no mocking needed.
"""

from datetime import datetime, timezone

import pytest

from scanner.models.finding import FindingSeverity, ScanFinding, ScannerType
from scanner.models.sandbox import SandboxEvent, SandboxEventType, SandboxReport
from scanner.models.verdict import RiskLevel, VerdictDecision
from scanner.verdict.engine import evaluate
from scanner.verdict.scorer import combined_score, score_findings, score_sandbox

NOW = datetime.now(timezone.utc)


def _finding(scanner: ScannerType, severity: FindingSeverity, title: str = "test") -> ScanFinding:
    return ScanFinding(
        artifact_id="art-001",
        scanner=scanner,
        severity=severity,
        title=title,
        description="test finding",
        timestamp=NOW,
    )


def _sandbox_event(event_type: SandboxEventType, suspicious: bool = True) -> SandboxEvent:
    return SandboxEvent(
        artifact_id="art-001",
        event_type=event_type,
        detail="test detail",
        suspicious=suspicious,
        timestamp=NOW,
    )


def _report(events: list[SandboxEvent], executed: bool = True) -> SandboxReport:
    return SandboxReport(
        artifact_id="art-001",
        executed=executed,
        events=events,
        suspicious_event_count=sum(1 for e in events if e.suspicious),
        timestamp=NOW,
    )


# ==============================================================================
# SCORER TESTS
# ==============================================================================

def test_score_findings_empty():
    assert score_findings([]) == 0


def test_score_findings_single_high():
    findings = [_finding(ScannerType.BANDIT, FindingSeverity.HIGH)]
    assert score_findings(findings) == 20


def test_score_findings_critical_gitleaks_gets_bonus():
    findings = [_finding(ScannerType.GITLEAKS, FindingSeverity.CRITICAL)]
    # CRITICAL(40) + GITLEAKS_BONUS(15) = 55
    assert score_findings(findings) == 55


def test_score_findings_capped_at_100():
    findings = [_finding(ScannerType.GITLEAKS, FindingSeverity.CRITICAL)] * 10
    assert score_findings(findings) == 100


def test_score_sandbox_no_report():
    assert score_sandbox(None) == 0


def test_score_sandbox_not_executed():
    report = _report([], executed=False)
    assert score_sandbox(report) == 0


def test_score_sandbox_non_suspicious_events_ignored():
    events = [_sandbox_event(SandboxEventType.FILE_READ, suspicious=False)]
    assert score_sandbox(_report(events)) == 0


def test_score_sandbox_shell_execution():
    events = [_sandbox_event(SandboxEventType.SHELL_EXECUTION)]
    assert score_sandbox(_report(events)) == 30


def test_score_sandbox_secret_access():
    events = [_sandbox_event(SandboxEventType.SECRET_ACCESS)]
    assert score_sandbox(_report(events)) == 35


def test_combined_score_no_sandbox():
    findings = [_finding(ScannerType.BANDIT, FindingSeverity.HIGH)]
    score = combined_score(findings, None)
    assert score > 0


# ==============================================================================
# VERDICT ENGINE TESTS
# ==============================================================================

def test_verdict_clean_artifact():
    verdict = evaluate("art-001", "abc" * 20, findings=[], report=None)
    assert verdict.decision == VerdictDecision.APPROVED
    assert verdict.risk_level == RiskLevel.LOW
    assert verdict.risk_score == 0


def test_verdict_low_findings_approved():
    findings = [_finding(ScannerType.BANDIT, FindingSeverity.LOW)] * 2
    verdict = evaluate("art-001", "abc" * 20, findings=findings)
    assert verdict.decision == VerdictDecision.APPROVED


def test_verdict_medium_findings_approved_with_counts():
    findings = [_finding(ScannerType.BANDIT, FindingSeverity.MEDIUM)] * 3
    verdict = evaluate("art-001", "abc" * 20, findings=findings)
    assert verdict.decision == VerdictDecision.APPROVED
    assert verdict.finding_counts.get("MEDIUM") == 3


def test_verdict_high_score_review_required():
    # Multiple HIGH findings should push into REVIEW_REQUIRED
    findings = [_finding(ScannerType.BANDIT, FindingSeverity.HIGH)] * 4
    verdict = evaluate("art-001", "abc" * 20, findings=findings)
    assert verdict.decision in (VerdictDecision.REVIEW_REQUIRED, VerdictDecision.BLOCKED)


def test_verdict_gitleaks_critical_hard_blocks():
    findings = [_finding(ScannerType.GITLEAKS, FindingSeverity.CRITICAL, "AWS key found")]
    verdict = evaluate("art-001", "abc" * 20, findings=findings)
    assert verdict.decision == VerdictDecision.BLOCKED
    assert verdict.risk_level == RiskLevel.CRITICAL
    assert len(verdict.blocked_reasons) >= 1
    assert any("gitleaks" in r for r in verdict.blocked_reasons)


def test_verdict_pip_audit_critical_hard_blocks():
    findings = [_finding(ScannerType.PIP_AUDIT, FindingSeverity.CRITICAL, "CVE-2023-1234")]
    verdict = evaluate("art-001", "abc" * 20, findings=findings)
    assert verdict.decision == VerdictDecision.BLOCKED
    assert any("CVE" in r or "dependency" in r for r in verdict.blocked_reasons)


def test_verdict_sandbox_shell_execution_hard_blocks():
    events = [_sandbox_event(SandboxEventType.SHELL_EXECUTION)]
    verdict = evaluate("art-001", "abc" * 20, findings=[], report=_report(events))
    assert verdict.decision == VerdictDecision.BLOCKED
    assert any("shell" in r.lower() for r in verdict.blocked_reasons)


def test_verdict_sandbox_secret_access_hard_blocks():
    events = [_sandbox_event(SandboxEventType.SECRET_ACCESS)]
    verdict = evaluate("art-001", "abc" * 20, findings=[], report=_report(events))
    assert verdict.decision == VerdictDecision.BLOCKED


def test_verdict_scanner_verdicts_populated():
    findings = [
        _finding(ScannerType.BANDIT, FindingSeverity.HIGH),
        _finding(ScannerType.BANDIT, FindingSeverity.MEDIUM),
        _finding(ScannerType.SEMGREP, FindingSeverity.LOW),
    ]
    verdict = evaluate("art-001", "abc" * 20, findings=findings)
    assert verdict.scanner_verdicts.get("bandit") == "HIGH"
    assert verdict.scanner_verdicts.get("semgrep") == "LOW"


def test_verdict_sha256_preserved():
    sha = "a" * 64
    verdict = evaluate("art-001", sha, findings=[])
    assert verdict.sha256 == sha


def test_verdict_risk_score_in_range():
    findings = [_finding(ScannerType.BANDIT, FindingSeverity.HIGH)] * 3
    verdict = evaluate("art-001", "abc" * 20, findings=findings)
    assert 0 <= verdict.risk_score <= 100
