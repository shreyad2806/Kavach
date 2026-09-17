"""
Static scanner tests.
subprocess.run is mocked throughout — no real tools need to be installed.
"""

import json
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

from scanner.models.finding import FindingSeverity, ScannerType
from scanner.scanners.bandit import BanditScanner
from scanner.scanners.gitleaks import GitleaksScanner
from scanner.scanners.pip_audit import PipAuditScanner
from scanner.scanners.semgrep import SemgrepScanner


def _mock_run(stdout: str, returncode: int = 0):
    m = MagicMock()
    m.stdout = stdout
    m.returncode = returncode
    return m


# ==============================================================================
# BANDIT
# ==============================================================================

BANDIT_OUTPUT = json.dumps({
    "results": [
        {
            "issue_text": "Use of subprocess with shell=True",
            "issue_severity": "HIGH",
            "test_id": "B602",
            "filename": "setup.py",
            "line_number": 42,
        },
        {
            "issue_text": "Hardcoded password string",
            "issue_severity": "MEDIUM",
            "test_id": "B105",
            "filename": "config.py",
            "line_number": 10,
        },
    ]
})


def test_bandit_parses_findings():
    with patch("subprocess.run", return_value=_mock_run(BANDIT_OUTPUT, returncode=1)):
        findings = BanditScanner().scan("art-001", "/tmp/artifact")

    assert len(findings) == 2
    assert findings[0].scanner == ScannerType.BANDIT
    assert findings[0].severity == FindingSeverity.HIGH
    assert findings[0].rule_id == "B602"
    assert "setup.py:42" in findings[0].location


def test_bandit_empty_results():
    with patch("subprocess.run", return_value=_mock_run(json.dumps({"results": []}))):
        findings = BanditScanner().scan("art-001", "/tmp/artifact")
    assert findings == []


def test_bandit_tool_not_found_returns_empty():
    with patch("subprocess.run", side_effect=FileNotFoundError):
        findings = BanditScanner().scan("art-001", "/tmp/artifact")
    assert findings == []


def test_bandit_timeout_returns_empty():
    import subprocess
    with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("bandit", 120)):
        findings = BanditScanner().scan("art-001", "/tmp/artifact")
    assert findings == []


def test_bandit_invalid_json_returns_empty():
    with patch("subprocess.run", return_value=_mock_run("not json")):
        findings = BanditScanner().scan("art-001", "/tmp/artifact")
    assert findings == []


# ==============================================================================
# SEMGREP
# ==============================================================================

SEMGREP_OUTPUT = json.dumps({
    "results": [
        {
            "check_id": "python.lang.security.audit.subprocess-shell-true",
            "path": "run.py",
            "start": {"line": 15},
            "extra": {
                "severity": "ERROR",
                "message": "Subprocess called with shell=True is a security risk.",
            },
        }
    ]
})


def test_semgrep_parses_findings():
    with patch("subprocess.run", return_value=_mock_run(SEMGREP_OUTPUT)):
        findings = SemgrepScanner().scan("art-001", "/tmp/artifact")

    assert len(findings) == 1
    assert findings[0].scanner == ScannerType.SEMGREP
    assert findings[0].severity == FindingSeverity.HIGH
    assert "run.py:15" in findings[0].location


def test_semgrep_empty_results():
    with patch("subprocess.run", return_value=_mock_run(json.dumps({"results": []}))):
        findings = SemgrepScanner().scan("art-001", "/tmp/artifact")
    assert findings == []


def test_semgrep_tool_not_found_returns_empty():
    with patch("subprocess.run", side_effect=FileNotFoundError):
        findings = SemgrepScanner().scan("art-001", "/tmp/artifact")
    assert findings == []


# ==============================================================================
# PIP-AUDIT
# ==============================================================================

PIP_AUDIT_OUTPUT = json.dumps({
    "dependencies": [
        {
            "name": "requests",
            "version": "2.28.0",
            "vulns": [
                {
                    "id": "GHSA-j8r2-6x86-q33q",
                    "aliases": ["CVE-2023-32681"],
                    "description": "Requests forwards proxy-authorization headers to destination servers.",
                }
            ],
        },
        {
            "name": "urllib3",
            "version": "1.26.5",
            "vulns": [],
        },
    ]
})


def test_pip_audit_parses_findings():
    with patch("subprocess.run", return_value=_mock_run(PIP_AUDIT_OUTPUT)):
        findings = PipAuditScanner().scan("art-001", "/tmp/artifact")

    assert len(findings) == 1
    assert findings[0].scanner == ScannerType.PIP_AUDIT
    assert findings[0].severity == FindingSeverity.HIGH
    assert findings[0].cve_id == "CVE-2023-32681"
    assert "requests==2.28.0" in findings[0].location


def test_pip_audit_no_vulns():
    output = json.dumps({"dependencies": [{"name": "boto3", "version": "1.26.0", "vulns": []}]})
    with patch("subprocess.run", return_value=_mock_run(output)):
        findings = PipAuditScanner().scan("art-001", "/tmp/artifact")
    assert findings == []


def test_pip_audit_ghsa_only_is_medium():
    output = json.dumps({
        "dependencies": [{
            "name": "flask",
            "version": "2.0.0",
            "vulns": [{
                "id": "GHSA-abc-def-ghij",
                "aliases": ["GHSA-abc-def-ghij"],
                "description": "Some advisory",
            }]
        }]
    })
    with patch("subprocess.run", return_value=_mock_run(output)):
        findings = PipAuditScanner().scan("art-001", "/tmp/artifact")
    assert findings[0].severity == FindingSeverity.MEDIUM
    assert findings[0].cve_id is None


def test_pip_audit_tool_not_found_returns_empty():
    with patch("subprocess.run", side_effect=FileNotFoundError):
        findings = PipAuditScanner().scan("art-001", "/tmp/artifact")
    assert findings == []


# ==============================================================================
# GITLEAKS
# ==============================================================================

GITLEAKS_OUTPUT = json.dumps([
    {
        "RuleID": "aws-access-token",
        "Description": "AWS Access Token",
        "File": "config.py",
        "StartLine": 5,
        "Match": "AKIAIOSFODNN7EXAMPLE",
    }
])


def test_gitleaks_parses_findings():
    with patch("subprocess.run", return_value=_mock_run(GITLEAKS_OUTPUT, returncode=1)):
        findings = GitleaksScanner().scan("art-001", "/tmp/artifact")

    assert len(findings) == 1
    assert findings[0].scanner == ScannerType.GITLEAKS
    assert findings[0].severity == FindingSeverity.CRITICAL
    assert findings[0].rule_id == "aws-access-token"
    assert "config.py:5" in findings[0].location


def test_gitleaks_no_secrets():
    with patch("subprocess.run", return_value=_mock_run("", returncode=0)):
        findings = GitleaksScanner().scan("art-001", "/tmp/artifact")
    assert findings == []


def test_gitleaks_tool_not_found_returns_empty():
    with patch("subprocess.run", side_effect=FileNotFoundError):
        findings = GitleaksScanner().scan("art-001", "/tmp/artifact")
    assert findings == []


def test_gitleaks_always_critical_severity():
    with patch("subprocess.run", return_value=_mock_run(GITLEAKS_OUTPUT, returncode=1)):
        findings = GitleaksScanner().scan("art-001", "/tmp/artifact")
    for f in findings:
        assert f.severity == FindingSeverity.CRITICAL


@pytest.mark.parametrize("url", [
    "https://github.com/org/repo",
    "https://gitlab.com/org/repo",
    "https://bitbucket.org/org/repo",
])
def test_gitleaks_git_repo_urls_use_history(url):
    from scanner.scanners.gitleaks import _is_git_repo_url
    assert _is_git_repo_url(url) is True


@pytest.mark.parametrize("url", [
    "https://github.com/org/repo/archive/main.tar.gz",
    "https://files.example.com/package.whl",
    "https://example.com/pkg.zip",
])
def test_gitleaks_archive_urls_use_no_git(url):
    from scanner.scanners.gitleaks import _is_git_repo_url
    assert _is_git_repo_url(url) is False


# ==============================================================================
# CROSS-SCANNER: all scanners return ScanFinding with correct artifact_id
# ==============================================================================

@pytest.mark.parametrize("scanner_cls,output,returncode", [
    (BanditScanner, BANDIT_OUTPUT, 1),
    (SemgrepScanner, SEMGREP_OUTPUT, 0),
    (PipAuditScanner, PIP_AUDIT_OUTPUT, 0),
    (GitleaksScanner, GITLEAKS_OUTPUT, 1),
])
def test_all_scanners_set_artifact_id(scanner_cls, output, returncode):
    with patch("subprocess.run", return_value=_mock_run(output, returncode)):
        findings = scanner_cls().scan("art-xyz", "/tmp/artifact")
    assert len(findings) >= 1
    for f in findings:
        assert f.artifact_id == "art-xyz"


# ==============================================================================
# SEMGREP LOCAL RULE RESOLUTION
# ==============================================================================

def test_semgrep_uses_registry_when_no_rules_dir():
    from scanner.scanners.semgrep import _resolve_configs
    import os
    with patch.dict(os.environ, {}, clear=False):
        os.environ.pop("SEMGREP_RULES_DIR", None)
        result = _resolve_configs(["p/python", "p/secrets"])
    assert result == ["p/python", "p/secrets"]


def test_semgrep_uses_local_files_when_rules_dir_set(tmp_path):
    from scanner.scanners.semgrep import _resolve_configs
    import os
    # Create fake rule files
    (tmp_path / "python.yaml").write_text("rules: []")
    (tmp_path / "secrets.yaml").write_text("rules: []")
    with patch.dict(os.environ, {"SEMGREP_RULES_DIR": str(tmp_path)}):
        result = _resolve_configs(["p/python", "p/secrets"])
    assert all(str(tmp_path) in r for r in result)
    assert all(r.endswith(".yaml") for r in result)


def test_semgrep_falls_back_to_registry_for_missing_local_file(tmp_path):
    from scanner.scanners.semgrep import _resolve_configs
    import os
    # Only python.yaml exists, secrets.yaml does not
    (tmp_path / "python.yaml").write_text("rules: []")
    with patch.dict(os.environ, {"SEMGREP_RULES_DIR": str(tmp_path)}):
        result = _resolve_configs(["p/python", "p/secrets"])
    assert str(tmp_path) in result[0]   # python resolved locally
    assert result[1] == "p/secrets"     # secrets fell back to registry
