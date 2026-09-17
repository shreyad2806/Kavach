"""
Verdict engine — applies deterministic thresholds to produce a final ScanVerdict.
The LLM reads this verdict but never produces or modifies it.

Thresholds:
  0–20   LOW      → APPROVED
  21–50  MEDIUM   → APPROVED  (with warnings recorded)
  51–79  HIGH     → REVIEW_REQUIRED
  80–100 CRITICAL → BLOCKED

Hard overrides (score-independent):
  - Any CRITICAL finding from gitleaks → BLOCKED immediately
  - Any CRITICAL CVE from pip-audit    → BLOCKED immediately
  - Sandbox SECRET_ACCESS or SHELL_EXECUTION → BLOCKED immediately
"""

from datetime import datetime, timezone

from scanner.logger import get_logger
from scanner.models.finding import FindingSeverity, ScanFinding, ScannerType
from scanner.models.sandbox import SandboxEventType, SandboxReport
from scanner.models.verdict import RiskLevel, ScanVerdict, VerdictDecision
from scanner.verdict.scorer import combined_score, score_findings, score_sandbox

log = get_logger(__name__)


def _risk_level(score: int) -> RiskLevel:
    if score <= 20:
        return RiskLevel.LOW
    if score <= 50:
        return RiskLevel.MEDIUM
    if score <= 79:
        return RiskLevel.HIGH
    return RiskLevel.CRITICAL


def _hard_block_reasons(
    findings: list[ScanFinding],
    report: SandboxReport | None,
) -> list[str]:
    """Return non-empty list of reasons if the artifact must be hard-blocked regardless of score."""
    reasons = []

    for f in findings:
        if f.scanner == ScannerType.GITLEAKS and f.severity == FindingSeverity.CRITICAL:
            reasons.append(f"Secret detected by gitleaks: {f.title}")
        if f.scanner == ScannerType.PIP_AUDIT and f.severity == FindingSeverity.CRITICAL:
            reasons.append(f"Critical CVE in dependency: {f.title}")

    if report and report.executed:
        for event in report.events:
            if event.suspicious and event.event_type == SandboxEventType.SECRET_ACCESS:
                reasons.append(f"Sandbox: secret/credential access detected ({event.detail})")
            if event.suspicious and event.event_type == SandboxEventType.SHELL_EXECUTION:
                reasons.append(f"Sandbox: shell execution detected ({event.detail})")
            if event.suspicious and event.event_type == SandboxEventType.PRIVILEGE_ESCALATION:
                reasons.append(f"Sandbox: privilege escalation attempt ({event.detail})")

    return reasons


def _finding_counts(findings: list[ScanFinding]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
    return counts


def _scanner_verdicts(findings: list[ScanFinding]) -> dict[str, str]:
    """Highest severity seen per scanner."""
    order = [FindingSeverity.CRITICAL, FindingSeverity.HIGH, FindingSeverity.MEDIUM, FindingSeverity.LOW, FindingSeverity.INFO]
    worst: dict[str, FindingSeverity] = {}
    for f in findings:
        current = worst.get(f.scanner.value)
        if current is None or order.index(f.severity) < order.index(current):
            worst[f.scanner.value] = f.severity
    return {k: v.value for k, v in worst.items()}


def evaluate(
    artifact_id: str,
    sha256: str,
    findings: list[ScanFinding],
    report: SandboxReport | None = None,
    previous_sha256: str | None = None,
    scan_count: int = 1,
) -> ScanVerdict:
    # Inject a finding if the artifact hash changed since the last scan
    if previous_sha256 and sha256 and sha256 != previous_sha256:
        log.warning(
            "artifact hash changed since last scan",
            extra={"artifact_id": artifact_id, "previous_sha256": previous_sha256, "new_sha256": sha256},
        )
        findings = list(findings) + [ScanFinding(
            artifact_id=artifact_id,
            scanner=ScannerType.SEMGREP,  # closest generic scanner type
            severity=FindingSeverity.HIGH,
            title="Artifact hash changed since last scan",
            description=(
                f"SHA-256 changed from {previous_sha256[:16]}... to {sha256[:16]}... "
                f"(scan #{scan_count}). Verify the source has not been tampered with."
            ),
            timestamp=datetime.now(timezone.utc),
        )]

    score = combined_score(findings, report)
    risk = _risk_level(score)
    hard_blocks = _hard_block_reasons(findings, report)

    if hard_blocks:
        log.critical("hard block triggered", extra={"artifact_id": artifact_id, "reasons": hard_blocks})
        decision = VerdictDecision.BLOCKED
        risk = RiskLevel.CRITICAL
        score = max(score, 80)
    elif risk == RiskLevel.CRITICAL:
        decision = VerdictDecision.BLOCKED
    elif risk == RiskLevel.HIGH:
        decision = VerdictDecision.REVIEW_REQUIRED
    else:
        decision = VerdictDecision.APPROVED

    return ScanVerdict(
        artifact_id=artifact_id,
        decision=decision,
        risk_level=risk,
        risk_score=score,
        finding_counts=_finding_counts(findings),
        blocked_reasons=hard_blocks,
        scanner_verdicts=_scanner_verdicts(findings),
        sha256=sha256,
        timestamp=datetime.now(timezone.utc),
    )
