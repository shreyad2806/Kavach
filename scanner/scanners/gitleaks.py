"""
Gitleaks scanner wrapper — secret and credential detection.
Detects: AWS keys, API tokens, private keys, passwords hardcoded in source.

For GitHub URLs: clones the full repo so git history is scanned.
For plain files/archives: runs with --no-git on extracted contents.
"""

import json
import os
import subprocess
import tempfile

from scanner.logger import get_logger
from scanner.models.finding import FindingSeverity, ScanFinding, ScannerType
from scanner.scanners.base import BaseScanner

log = get_logger(__name__)


def _is_github_url(source_url: str) -> bool:
    return "github.com" in source_url and not source_url.endswith(
        (".tar.gz", ".zip", ".whl", ".tgz")
    )


def _clone_repo(source_url: str, dest_dir: str) -> bool:
    """Clone a GitHub repo into dest_dir. Returns True on success."""
    try:
        subprocess.run(
            ["git", "clone", "--depth=50", source_url, dest_dir],
            capture_output=True,
            timeout=120,
            check=True,
        )
        return True
    except subprocess.CalledProcessError as e:
        log.warning("git clone failed", extra={"source_url": source_url, "error": str(e)})
        return False
    except subprocess.TimeoutExpired:
        log.warning("git clone timed out", extra={"source_url": source_url})
        return False
    except FileNotFoundError:
        log.error("git not installed")
        return False


class GitleaksScanner(BaseScanner):

    def __init__(self, source_url: str = "") -> None:
        self._source_url = source_url

    def scan(self, artifact_id: str, artifact_path: str) -> list[ScanFinding]:
        if self._source_url and _is_github_url(self._source_url):
            return self._scan_with_history(artifact_id)
        return self._scan_no_git(artifact_id, artifact_path)

    def _scan_no_git(self, artifact_id: str, artifact_path: str) -> list[ScanFinding]:
        log.info("gitleaks scan (no-git)", extra={"artifact_id": artifact_id})
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
            stdout = result.stdout.strip()
            if not stdout:
                return []
            raw_list = json.loads(stdout)
        except subprocess.TimeoutExpired:
            log.warning("gitleaks timed out", extra={"artifact_id": artifact_id})
            return []
        except FileNotFoundError:
            log.error("gitleaks not installed")
            return []
        except json.JSONDecodeError as e:
            log.warning("gitleaks output parse failed", extra={"artifact_id": artifact_id, "error": str(e)})
            return []
        return self._parse(artifact_id, raw_list)

    def _scan_with_history(self, artifact_id: str) -> list[ScanFinding]:
        log.info("gitleaks scan (with git history)", extra={"artifact_id": artifact_id, "source_url": self._source_url})
        with tempfile.TemporaryDirectory() as tmpdir:
            clone_dir = os.path.join(tmpdir, "repo")
            if not _clone_repo(self._source_url, clone_dir):
                return []
            try:
                result = subprocess.run(
                    [
                        "gitleaks", "detect",
                        "--source", clone_dir,
                        "--report-format", "json",
                        "--report-path", "-",
                    ],
                    capture_output=True,
                    text=True,
                    timeout=120,
                )
                stdout = result.stdout.strip()
                if not stdout:
                    return []
                raw_list = json.loads(stdout)
            except subprocess.TimeoutExpired:
                log.warning("gitleaks (history) timed out", extra={"artifact_id": artifact_id})
                return []
            except FileNotFoundError:
                log.error("gitleaks not installed")
                return []
            except json.JSONDecodeError as e:
                log.warning("gitleaks (history) parse failed", extra={"artifact_id": artifact_id, "error": str(e)})
                return []
        return self._parse(artifact_id, raw_list)

    def _parse(self, artifact_id: str, raw_list: list) -> list[ScanFinding]:
        findings = []
        for leak in raw_list:
            findings.append(ScanFinding(
                artifact_id=artifact_id,
                scanner=ScannerType.GITLEAKS,
                severity=FindingSeverity.CRITICAL,
                title=f"Secret detected: {leak.get('RuleID', 'unknown rule')}",
                description=(
                    f"Secret match found by rule '{leak.get('RuleID', '')}'. "
                    f"Description: {leak.get('Description', 'N/A')}. "
                    f"Commit: {leak.get('Commit', 'N/A')}"
                ),
                location=f"{leak.get('File', '')}:{leak.get('StartLine', '')}",
                rule_id=leak.get("RuleID"),
                raw=leak,
                timestamp=self._now(),
            ))
        log.info("gitleaks complete", extra={"artifact_id": artifact_id, "finding_count": len(findings)})
        return findings
