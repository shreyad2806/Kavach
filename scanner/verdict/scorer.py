"""
Risk scorer — maps findings and sandbox signals to a numeric risk score.
Fully deterministic. No LLM involved.

Weights are additive. Score is capped at 100.
"""

from scanner.models.finding import FindingSeverity, ScanFinding, ScannerType
from scanner.models.sandbox import SandboxEventType, SandboxReport

# Per-finding severity weights
_SEVERITY_WEIGHT: dict[FindingSeverity, int] = {
    FindingSeverity.CRITICAL: 40,
    FindingSeverity.HIGH: 20,
    FindingSeverity.MEDIUM: 10,
    FindingSeverity.LOW: 3,
    FindingSeverity.INFO: 0,
}

# Gitleaks findings are always secrets — extra weight on top of CRITICAL
_GITLEAKS_BONUS = 15

# Sandbox event weights (only suspicious events contribute)
_SANDBOX_EVENT_WEIGHT: dict[SandboxEventType, int] = {
    SandboxEventType.SECRET_ACCESS: 35,
    SandboxEventType.SHELL_EXECUTION: 30,
    SandboxEventType.PRIVILEGE_ESCALATION: 30,
    SandboxEventType.UNEXPECTED_DOWNLOAD: 25,
    SandboxEventType.NETWORK_CONNECT: 20,
    SandboxEventType.DNS_LOOKUP: 10,
    SandboxEventType.PROCESS_SPAWN: 15,
    SandboxEventType.FILE_WRITE: 5,
    SandboxEventType.FILE_DELETE: 10,
    SandboxEventType.ENV_READ: 10,
    SandboxEventType.FILE_READ: 0,
}


def score_findings(findings: list[ScanFinding]) -> int:
    total = 0
    for f in findings:
        weight = _SEVERITY_WEIGHT.get(f.severity, 0)
        if f.scanner == ScannerType.GITLEAKS and f.severity == FindingSeverity.CRITICAL:
            weight += _GITLEAKS_BONUS
        total += weight
    return min(total, 100)


def score_sandbox(report: SandboxReport | None) -> int:
    if report is None or not report.executed:
        return 0
    total = 0
    for event in report.events:
        if event.suspicious:
            total += _SANDBOX_EVENT_WEIGHT.get(event.event_type, 5)
    return min(total, 100)


def combined_score(findings: list[ScanFinding], report: SandboxReport | None) -> int:
    static = score_findings(findings)
    dynamic = score_sandbox(report)
    # Dynamic signals are weighted at 60% static + 40% dynamic, capped at 100
    return min(int(static * 0.6 + dynamic * 0.4) + max(static, dynamic) // 4, 100)
