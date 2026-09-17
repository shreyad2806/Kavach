"""
pip-audit scanner wrapper — dependency vulnerability scanning.
Runs: pip-audit --path <path> -f json
Detects: known CVEs in declared dependencies via PyPI Advisory Database.
"""

import json
import subprocess

from scanner.models.finding import FindingSeverity, ScanFinding, ScannerType
from scanner.scanners.base import BaseScanner


def _severity_from_aliases(aliases: list[str]) -> FindingSeverity:
    """
    pip-audit doesn't provide a severity field directly.
    Treat any CVE as HIGH, GHSA advisories as MEDIUM.
    """
    for alias in aliases:
        if alias.startswith("CVE-"):
            return FindingSeverity.HIGH
    return FindingSeverity.MEDIUM


class PipAuditScanner(BaseScanner):

    def scan(self, artifact_id: str, artifact_path: str) -> list[ScanFinding]:
        try:
            result = subprocess.run(
                ["pip-audit", "--path", artifact_path, "-f", "json", "--no-deps"],
                capture_output=True,
                text=True,
                timeout=120,
            )
            raw = json.loads(result.stdout)
        except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError):
            return []

        findings = []
        for dep in raw.get("dependencies", []):
            for vuln in dep.get("vulns", []):
                aliases = vuln.get("aliases", [])
                cve_id = next((a for a in aliases if a.startswith("CVE-")), None)
                severity = _severity_from_aliases(aliases)
                findings.append(ScanFinding(
                    artifact_id=artifact_id,
                    scanner=ScannerType.PIP_AUDIT,
                    severity=severity,
                    title=f"{vuln.get('id', 'Unknown')} in {dep.get('name', '')} {dep.get('version', '')}",
                    description=vuln.get("description", "No description available."),
                    location=f"{dep.get('name', '')}=={dep.get('version', '')}",
                    rule_id=vuln.get("id"),
                    cve_id=cve_id,
                    raw=vuln,
                    timestamp=self._now(),
                ))
        return findings
