"""
Semgrep scanner wrapper — pattern-based static analysis.
Uses language-specific rulesets based on detected file types.
Detects: supply-chain patterns, insecure deserialization, SSRF, injection, etc.

Rule resolution order:
  1. SEMGREP_RULES_DIR env var — local files bundled into the Docker image at build time.
     This is the production path: no internet access needed at runtime.
  2. Registry configs (p/python etc.) — used in local dev when SEMGREP_RULES_DIR is not set.
"""

import json
import os
import subprocess
from pathlib import Path

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

# Registry config names per language (used when no local rules dir is set)
_LANGUAGE_REGISTRY_CONFIGS = {
    "python": ["p/python", "p/secrets", "p/supply-chain"],
    "javascript": ["p/javascript", "p/secrets"],
    "typescript": ["p/typescript", "p/secrets"],
    "go": ["p/golang", "p/secrets"],
    "java": ["p/java", "p/secrets"],
    "ruby": ["p/ruby"],
    "shell": ["p/bash"],
}

# Mapping from registry config name to local filename (set by Dockerfile)
_REGISTRY_TO_LOCAL = {
    "p/python": "python.yaml",
    "p/secrets": "secrets.yaml",
    "p/supply-chain": "supply-chain.yaml",
    "p/javascript": "javascript.yaml",
    "p/typescript": "typescript.yaml",
    "p/golang": "golang.yaml",
    "p/java": "java.yaml",
    "p/ruby": "ruby.yaml",
    "p/bash": "bash.yaml",
}


def _resolve_configs(registry_configs: list[str]) -> list[str]:
    """
    Resolve registry config names to local file paths if SEMGREP_RULES_DIR is set
    and the file exists. Falls back to the registry name for any missing file.
    """
    rules_dir = os.environ.get("SEMGREP_RULES_DIR", "")
    if not rules_dir:
        return registry_configs

    resolved = []
    for config in registry_configs:
        local_name = _REGISTRY_TO_LOCAL.get(config)
        if local_name:
            local_path = Path(rules_dir) / local_name
            if local_path.exists():
                resolved.append(str(local_path))
                continue
        # File not found locally — fall back to registry (requires internet)
        log.warning("semgrep local rule file missing, falling back to registry", extra={"config": config})
        resolved.append(config)
    return resolved


class SemgrepScanner(BaseScanner):

    def scan(self, artifact_id: str, artifact_path: str) -> list[ScanFinding]:
        languages = detect_languages(artifact_path)

        registry_configs: list[str] = []
        for lang in languages:
            registry_configs.extend(_LANGUAGE_REGISTRY_CONFIGS.get(lang, []))

        # Deduplicate while preserving order
        seen: set[str] = set()
        registry_configs = [c for c in registry_configs if not (c in seen or seen.add(c))]

        if not registry_configs:
            registry_configs = ["auto"]

        configs = _resolve_configs(registry_configs)

        cmd = ["semgrep"]
        for config in configs:
            cmd += ["--config", config]
        cmd += [artifact_path, "--json", "--quiet"]

        log.info("semgrep scan started", extra={"artifact_id": artifact_id, "languages": list(languages), "configs": configs})
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
