"""
Bandit scanner wrapper — Python security static analysis.
Runs: bandit -r <path> -f json
Detects: subprocess abuse, eval/exec, hardcoded passwords, weak crypto, etc.
"""

import json
import subprocess

from scanner.logger import get_logger
from scanner.models.finding import FindingSeverity, ScanFinding, ScannerType
from scanner.scanners.base import BaseScanner

log = get_logger(__name__)

_SEVERITY_MAP = {
    "HIGH": FindingSeverity.HIGH,
    "MEDIUM": FindingSeverity.MEDIUM,
    "LOW": FindingSeverity.LOW,
}


class BanditScanner(BaseScanner):

    def scan(self, artifact_id: str, artifact_path: str) -> list[ScanFinding]:
        try:
            result = subprocess.run(
                ["bandit", "-r", artifact_path, "-f", "json", "-q"],
                capture_output=True,
                text=True,
                timeout=120,
            )
            # Bandit exits 1 when it finds issues — that is expected, not an error
            raw = json.loads(result.stdout)
        except subprocess.TimeoutExpired:
            log.warning("bandit timed out", extra={"artifact_id": artifact_id})
            return []
        except FileNotFoundError:
            log.error("bandit not installed")
            return []
        except json.JSONDecodeError as e:
            log.warning("bandit output parse failed", extra={"error": str(e)})
            return []

        findings = []
        for issue in raw.get("results", []):
            severity = _SEVERITY_MAP.get(issue.get("issue_severity", "").upper(), FindingSeverity.LOW)
            findings.append(ScanFinding(
                artifact_id=artifact_id,
                scanner=ScannerType.BANDIT,
                severity=severity,
                title=issue.get("issue_text", "Unknown issue"),
                description=f"{issue.get('issue_text', '')} — test: {issue.get('test_id', '')}",
                location=f"{issue.get('filename', '')}:{issue.get('line_number', '')}",
                rule_id=issue.get("test_id"),
                raw=issue,
                timestamp=self._now(),
            ))
        return findings
