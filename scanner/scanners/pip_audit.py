"""
pip-audit scanner wrapper — dependency vulnerability scanning.
Runs: pip-audit -r requirements.txt -f json
Detects: known CVEs in declared dependencies via PyPI Advisory Database.

If no requirements file is found, imports are extracted from .py files
and a temporary requirements.txt is generated for auditing.
"""

import ast
import json
import os
import subprocess
import tempfile
from pathlib import Path

from scanner.logger import get_logger
from scanner.models.finding import FindingSeverity, ScanFinding, ScannerType
from scanner.scanners.base import BaseScanner

log = get_logger(__name__)

# Third-party packages that are commonly imported but not stdlib
# Used to filter out stdlib modules from import extraction
_STDLIB = set([
    "os", "sys", "re", "json", "time", "datetime", "math", "random",
    "string", "io", "pathlib", "typing", "collections", "itertools",
    "functools", "operator", "copy", "abc", "enum", "dataclasses",
    "contextlib", "warnings", "logging", "traceback", "inspect",
    "threading", "multiprocessing", "subprocess", "socket", "ssl",
    "http", "urllib", "email", "html", "xml", "csv", "hashlib",
    "hmac", "secrets", "base64", "struct", "array", "queue",
    "tempfile", "shutil", "glob", "fnmatch", "stat", "platform",
    "argparse", "unittest", "ast", "dis", "gc", "weakref",
    "builtins", "__future__", "zipfile", "tarfile", "gzip",
])


def _severity_from_aliases(aliases: list[str]) -> FindingSeverity:
    for alias in aliases:
        if alias.startswith("CVE-"):
            return FindingSeverity.HIGH
    return FindingSeverity.MEDIUM


def _extract_imports(artifact_dir: str) -> set[str]:
    """Walk .py files and extract top-level imported package names."""
    imports: set[str] = set()
    for root, _, files in os.walk(artifact_dir):
        for fname in files:
            if not fname.endswith(".py"):
                continue
            try:
                source = Path(root, fname).read_text(encoding="utf-8", errors="ignore")
                tree = ast.parse(source)
                for node in ast.walk(tree):
                    if isinstance(node, ast.Import):
                        for alias in node.names:
                            pkg = alias.name.split(".")[0]
                            if pkg not in _STDLIB:
                                imports.add(pkg)
                    elif isinstance(node, ast.ImportFrom):
                        if node.module:
                            pkg = node.module.split(".")[0]
                            if pkg not in _STDLIB:
                                imports.add(pkg)
            except Exception:
                continue
    return imports


def _find_requirements_file(artifact_dir: str) -> str | None:
    """Return path to the first requirements file found, or None."""
    candidates = [
        "requirements.txt", "requirements-dev.txt",
        "requirements/base.txt", "requirements/prod.txt",
    ]
    base = Path(artifact_dir)
    if not base.exists():
        return None
    for candidate in candidates:
        p = base / candidate
        if p.exists():
            return str(p)
    # Also search subdirectories one level deep
    try:
        for child in base.iterdir():
            if child.is_dir():
                for candidate in candidates:
                    p = child / candidate
                    if p.exists():
                        return str(p)
    except OSError:
        pass
    return None


def _find_setup_py(artifact_dir: str) -> str | None:
    p = Path(artifact_dir) / "setup.py"
    return str(p) if p.exists() else None


class PipAuditScanner(BaseScanner):

    def scan(self, artifact_id: str, artifact_path: str) -> list[ScanFinding]:
        req_file = _find_requirements_file(artifact_path)
        setup_py = _find_setup_py(artifact_path)

        # Build the pip-audit command based on what's available
        if req_file:
            cmd = ["pip-audit", "-r", req_file, "-f", "json", "--no-deps"]
        elif setup_py or not Path(artifact_path).exists():
            # setup.py present, or path doesn't exist (e.g. in tests) — use --path
            cmd = ["pip-audit", "--path", artifact_path, "-f", "json", "--no-deps"]
        else:
            # Auto-generate requirements from imports
            imports = _extract_imports(artifact_path)
            if not imports:
                return []
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".txt", delete=False
            ) as tmp:
                tmp.write("\n".join(sorted(imports)))
                tmp_path = tmp.name
            cmd = ["pip-audit", "-r", tmp_path, "-f", "json", "--no-deps"]

        log.info("pip-audit scan started", extra={"artifact_id": artifact_id, "mode": "requirements" if req_file else ("setup_py" if setup_py else "import_extraction")})
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,
            )
            raw = json.loads(result.stdout)
        except subprocess.TimeoutExpired:
            log.warning("pip-audit timed out", extra={"artifact_id": artifact_id})
            return []
        except FileNotFoundError:
            log.error("pip-audit not installed")
            return []
        except json.JSONDecodeError as e:
            log.warning("pip-audit output parse failed", extra={"error": str(e)})
            return []
        finally:
            # Clean up temp file if created
            if "tmp_path" in locals():
                try:
                    os.unlink(tmp_path)
                except Exception:
                    pass

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
