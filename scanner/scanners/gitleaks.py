"""
Gitleaks scanner wrapper — secret and credential detection.
Runs: gitleaks detect --source <path> --report-format json --report-path -
Detects: AWS keys, API tokens, private keys, passwords hardcoded in source.
"""

import json
import subprocess

from scanner.models.finding import FindingSeverity, ScanFinding, ScannerType
from scanner.scanners.base import BaseScanner


class GitleaksScanner(BaseScanner):

    def scan(self, artifact_id: str, artifact_path: str) -> list[ScanFinding]:
        try:
            result = subprocess.run(
                [
                    "gitleaks", "detect",
                    "--source", artifact_path,
                    "--report-format", "json",
                    "--report-path", "-",
                    "--no-git",
                ],
                capture_output=True,
                text=True,
                timeout=60,
            )
            # gitleaks exits 1 when secrets are found — expected, not an error
            stdout = result.stdout.strip()
            if not stdout:
                return []
            raw_list = json.loads(stdout)
        except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError):
            return []

        findings = []
        for leak in raw_list:
            findings.append(ScanFinding(
                artifact_id=artifact_id,
                scanner=ScannerType.GITLEAKS,
                # Secrets are always CRITICAL — a leaked credential is an immediate threat
                severity=FindingSeverity.CRITICAL,
                title=f"Secret detected: {leak.get('RuleID', 'unknown rule')}",
                description=f"Secret match found by rule '{leak.get('RuleID', '')}'. "
                            f"Description: {leak.get('Description', 'N/A')}",
                location=f"{leak.get('File', '')}:{leak.get('StartLine', '')}",
                rule_id=leak.get("RuleID"),
                raw=leak,
                timestamp=self._now(),
            ))
        return findings
