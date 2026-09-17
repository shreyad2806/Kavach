"""
Fargate sandbox entrypoint.

This script runs INSIDE the isolated Fargate container.
It:
  1. Downloads the artifact from S3 quarantine
  2. Executes it under strace to capture syscall-level behavior
  3. Parses the strace output through the signal observer
  4. Writes the SandboxReport to DynamoDB
  5. Exits

Environment variables (injected by the pipeline Lambda via task overrides):
  ARTIFACT_ID           — artifact to sandbox
  SCANNER_BUCKET        — S3 bucket name
  ARTIFACTS_TABLE       — DynamoDB artifacts table
  SANDBOX_RESULTS_TABLE — DynamoDB table to write the report to
"""

import json
import os
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

import boto3

# ---------------------------------------------------------------------------
# Inline signal matching (no scanner package import — container is minimal)
# ---------------------------------------------------------------------------
import re
from dataclasses import dataclass
from enum import Enum


class SandboxEventType(str, Enum):
    NETWORK_CONNECT = "NETWORK_CONNECT"
    DNS_LOOKUP = "DNS_LOOKUP"
    UNEXPECTED_DOWNLOAD = "UNEXPECTED_DOWNLOAD"
    FILE_READ = "FILE_READ"
    FILE_WRITE = "FILE_WRITE"
    FILE_DELETE = "FILE_DELETE"
    PROCESS_SPAWN = "PROCESS_SPAWN"
    SHELL_EXECUTION = "SHELL_EXECUTION"
    SECRET_ACCESS = "SECRET_ACCESS"
    ENV_READ = "ENV_READ"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"


@dataclass(frozen=True)
class Signal:
    pattern: re.Pattern
    event_type: SandboxEventType
    suspicious: bool


_SECRET_PATHS = (
    r"/etc/passwd", r"/etc/shadow", r"/etc/hosts",
    r"\.aws/credentials", r"\.ssh/", r"/proc/",
    r"AWS_SECRET", r"AWS_ACCESS_KEY", r"api_key", r"private_key",
)

SIGNALS: list[Signal] = [
    Signal(re.compile(r"connect\(.*\d+\.\d+\.\d+\.\d+", re.I), SandboxEventType.NETWORK_CONNECT, True),
    Signal(re.compile(r"(urllib|requests|http\.client|socket).*connect", re.I), SandboxEventType.NETWORK_CONNECT, True),
    Signal(re.compile(r"dns|gethostbyname|getaddrinfo", re.I), SandboxEventType.DNS_LOOKUP, False),
    Signal(re.compile(r"(wget|curl|urllib\.request|requests\.get|download)", re.I), SandboxEventType.UNEXPECTED_DOWNLOAD, True),
    Signal(re.compile("|".join(_SECRET_PATHS), re.I), SandboxEventType.SECRET_ACCESS, True),
    Signal(re.compile(r"os\.environ|getenv|environ\[", re.I), SandboxEventType.ENV_READ, False),
    Signal(re.compile(r"(subprocess|os\.system|os\.popen|shell=True|/bin/sh|/bin/bash)", re.I), SandboxEventType.SHELL_EXECUTION, True),
    Signal(re.compile(r"(Popen|exec|execve|fork\(\))", re.I), SandboxEventType.PROCESS_SPAWN, True),
    Signal(re.compile(r"(setuid|setgid|chmod\s*777|sudo|privilege)", re.I), SandboxEventType.PRIVILEGE_ESCALATION, True),
    Signal(re.compile(r"open\(.*['\"]w['\"]|write\(|\.write\(", re.I), SandboxEventType.FILE_WRITE, False),
    Signal(re.compile(r"(os\.remove|os\.unlink|shutil\.rmtree|unlink\()", re.I), SandboxEventType.FILE_DELETE, True),
    Signal(re.compile(r"open\(.*['\"]r['\"]|\.read\(|readlines\(", re.I), SandboxEventType.FILE_READ, False),
]


def observe(artifact_id: str, output: str) -> list[dict]:
    events = []
    now = datetime.now(timezone.utc).isoformat()
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        for signal in SIGNALS:
            if signal.pattern.search(line):
                events.append({
                    "artifact_id": artifact_id,
                    "event_type": signal.event_type.value,
                    "detail": line[:300],
                    "suspicious": signal.suspicious,
                    "timestamp": now,
                })
                break
    return events


# ---------------------------------------------------------------------------
# Main sandbox logic
# ---------------------------------------------------------------------------

def _s3():
    return boto3.client("s3")


def _ddb():
    return boto3.resource("dynamodb")


def _find_entrypoint(path: Path) -> str | None:
    for candidate in ("setup.py", "main.py", "app.py", "__main__.py"):
        if (path / candidate).exists():
            return candidate
    py_files = list(path.glob("*.py"))
    return py_files[0].name if py_files else None


def main():
    artifact_id = os.environ["ARTIFACT_ID"]
    bucket = os.environ["SCANNER_BUCKET"]
    results_table = os.environ["SANDBOX_RESULTS_TABLE"]
    now = datetime.now(timezone.utc).isoformat()

    # Derive the quarantine S3 key
    # source_url is stored in the artifact record — we reconstruct the key directly
    quarantine_key = f"quarantine/{artifact_id}/artifact"

    with tempfile.TemporaryDirectory() as tmpdir:
        artifact_dir = Path(tmpdir) / "artifact"
        artifact_dir.mkdir()
        local_file = artifact_dir / "artifact.py"

        # Download from quarantine
        try:
            _s3().download_file(bucket, quarantine_key, str(local_file))
        except Exception as e:
            _write_report(results_table, {
                "artifact_id": artifact_id,
                "executed": False,
                "exit_code": None,
                "events": [],
                "suspicious_event_count": 0,
                "execution_error": f"Failed to download artifact: {e}",
                "duration_seconds": None,
                "timestamp": now,
            })
            return

        entrypoint = _find_entrypoint(artifact_dir)
        if not entrypoint:
            _write_report(results_table, {
                "artifact_id": artifact_id,
                "executed": False,
                "exit_code": None,
                "events": [],
                "suspicious_event_count": 0,
                "execution_error": "No Python entrypoint found",
                "duration_seconds": None,
                "timestamp": now,
            })
            return

        started = time.monotonic()
        try:
            # Run under strace to capture syscall-level behavior
            result = subprocess.run(
                [
                    "strace", "-f", "-e",
                    "trace=network,file,process",
                    "-s", "200",
                    "python", str(artifact_dir / entrypoint),
                ],
                capture_output=True,
                text=True,
                timeout=30,
                cwd=tmpdir,
            )
            output = result.stdout + "\n" + result.stderr
            exit_code = result.returncode
            executed = True
            error = None
        except subprocess.TimeoutExpired:
            output = ""
            exit_code = None
            executed = True
            error = "Execution timed out after 30s"
        except Exception as e:
            output = ""
            exit_code = None
            executed = False
            error = str(e)

        duration = round(time.monotonic() - started, 2)
        events = observe(artifact_id, output)
        suspicious_count = sum(1 for e in events if e["suspicious"])

        _write_report(results_table, {
            "artifact_id": artifact_id,
            "executed": executed,
            "exit_code": exit_code,
            "events": events,
            "suspicious_event_count": suspicious_count,
            "execution_error": error,
            "duration_seconds": duration,
            "timestamp": now,
        })


def _write_report(table_name: str, report: dict) -> None:
    table = _ddb().Table(table_name)
    # DynamoDB can't store None — strip null values
    clean = {k: v for k, v in report.items() if v is not None}
    # events list contains dicts — DynamoDB handles these natively
    table.put_item(Item=clean)


if __name__ == "__main__":
    main()
