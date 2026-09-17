"""
Semgrep scanner wrapper — pattern-based static analysis.
Uses language-specific rulesets based on detected file types.
Detects: supply-chain patterns, insecure deserialization, SSRF, injection, etc.
"""

import json
import subprocess

from scanner.gateway.extractor import detect_languages
from scanner.logger import get_logger
from scanner.models.finding import FindingSeverity, ScanFinding, ScannerType
from scanner.scanners.base import BaseScanner

log = get_logger(__name__)

_SEVERITY_MAP = {
    "ERROR": FindingSeverity.HIGH,
    "WARNING": FindingSeverity.MEDIUM,
    "INFO": FindingSeverity.INFO,
}

# Semgrep registry configs per language
_LANGUAGE_CONFIGS = {
    "python": ["p/python", "p/secrets", "p/supply-chain"],
    "javascript": ["p/javascript", "p/secrets"],
    "typescript": ["p/typescript", "p/secrets"],
    "go": ["p/golang", "p/secrets"],
    "java": ["p/java", "p/secrets"],
    "ruby": ["p/ruby"],
    "shell": ["p/bash"],
}


class SemgrepScanner(BaseScanner):

    def scan(self, artifact_id: str, artifact_path: str) -> list[ScanFinding]:
        languages = detect_languages(artifact_path)

        # Build config list based on detected languages
        configs: list[str] = []
        for lang in languages:
            configs.extend(_LANGUAGE_CONFIGS.get(lang, []))

        # Deduplicate while preserving order
        seen: set[str] = set()
        unique_configs = [c for c in configs if not (c in seen or seen.add(c))]

        # Fall back to auto if no language matched
        if not unique_configs:
            unique_configs = ["auto"]

        cmd = ["semgrep"]
        for config in unique_configs:
            cmd += ["--config", config]
        cmd += [artifact_path, "--json", "--quiet"]

        log.info("semgrep scan started", extra={"artifact_id": artifact_id, "languages": list(languages), "configs": unique_configs})
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=180,
            )
            raw = json.loads(result.stdout)
        except subprocess.TimeoutExpired:
            log.warning("semgrep timed out", extra={"artifact_id": artifact_id})
            return []
        except FileNotFoundError:
            log.error("semgrep not installed")
            return []
        except json.JSONDecodeError as e:
            log.warning("semgrep output parse failed", extra={"error": str(e)})
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
