"""
Semgrep scanner wrapper — pattern-based static analysis.
Runs: semgrep --config=auto <path> --json
Detects: supply-chain patterns, insecure deserialization, SSRF, injection, etc.
"""

import json
import subprocess

from scanner.models.finding import FindingSeverity, ScanFinding, ScannerType
from scanner.scanners.base import BaseScanner

_SEVERITY_MAP = {
    "ERROR": FindingSeverity.HIGH,
    "WARNING": FindingSeverity.MEDIUM,
    "INFO": FindingSeverity.INFO,
}


class SemgrepScanner(BaseScanner):

    def scan(self, artifact_id: str, artifact_path: str) -> list[ScanFinding]:
        try:
            result = subprocess.run(
                ["semgrep", "--config=auto", artifact_path, "--json", "--quiet"],
                capture_output=True,
                text=True,
                timeout=180,
            )
            raw = json.loads(result.stdout)
        except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError):
            return []

        findings = []
        for match in raw.get("results", []):
            severity_str = match.get("extra", {}).get("severity", "INFO").upper()
            severity = _SEVERITY_MAP.get(severity_str, FindingSeverity.INFO)
            rule_id = match.get("check_id", "")
            findings.append(ScanFinding(
                artifact_id=artifact_id,
                scanner=ScannerType.SEMGREP,
                severity=severity,
                title=rule_id.split(".")[-1] if rule_id else "semgrep finding",
                description=match.get("extra", {}).get("message", "No description"),
                location=f"{match.get('path', '')}:{match.get('start', {}).get('line', '')}",
                rule_id=rule_id,
                raw=match,
                timestamp=self._now(),
            ))
        return findings
