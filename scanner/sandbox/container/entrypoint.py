"""
Fargate sandbox entrypoint — multi-language execution.

Supports:
  Python  — executed under strace
  Shell   — executed under strace (bash/sh scripts)
  Binary  — static inspection only (strings + file command), no execution
  Other   — static inspection only

Environment variables:
  ARTIFACT_ID           — artifact to sandbox
  SCANNER_BUCKET        — S3 bucket name
  SANDBOX_RESULTS_TABLE — DynamoDB table to write the report to
"""

import json
import os
import re
import subprocess
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path

import boto3


# ---------------------------------------------------------------------------
# Signal definitions (inline — container has no scanner package)
# ---------------------------------------------------------------------------

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
    # Strace-specific syscall patterns
    Signal(re.compile(r"connect\(.*AF_INET", re.I), SandboxEventType.NETWORK_CONNECT, True),
    Signal(re.compile(r"execve\(", re.I), SandboxEventType.PROCESS_SPAWN, True),
    Signal(re.compile(r"openat\(.*O_WRONLY|openat\(.*O_RDWR", re.I), SandboxEventType.FILE_WRITE, False),
    Signal(re.compile(r"unlinkat?\(", re.I), SandboxEventType.FILE_DELETE, True),
    Signal(re.compile(r"setuid|setgid|setreuid|setregid", re.I), SandboxEventType.PRIVILEGE_ESCALATION, True),
    # Node.js-specific patterns
    Signal(re.compile(r"(require\(['"]child_process['"]|spawn|execSync|execFile)", re.I), SandboxEventType.SHELL_EXECUTION, True),
    Signal(re.compile(r"(https?|axios|fetch|node-fetch|got)\.(get|post|request)", re.I), SandboxEventType.NETWORK_CONNECT, True),
    Signal(re.compile(r"(fs\.writeFile|fs\.appendFile|createWriteStream)", re.I), SandboxEventType.FILE_WRITE, False),
    Signal(re.compile(r"(fs\.unlink|rimraf)", re.I), SandboxEventType.FILE_DELETE, True),
    Signal(re.compile(r"process\.env", re.I), SandboxEventType.ENV_READ, False),
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
# File type detection
# ---------------------------------------------------------------------------

def _detect_type(artifact_dir: Path) -> tuple[str, Path | None]:
    """
    Returns (file_type, entrypoint_path).
    file_type: 'python' | 'shell' | 'binary' | 'unknown'
    """
    # Python
    for candidate in ("setup.py", "main.py", "app.py", "__main__.py"):
        p = artifact_dir / candidate
        if p.exists():
            return "python", p
    py_files = list(artifact_dir.rglob("*.py"))
    if py_files:
        return "python", py_files[0]

    # JavaScript / TypeScript
    for candidate in ("index.js", "main.js", "app.js", "index.ts", "main.ts"):
        p = artifact_dir / candidate
        if p.exists():
            return "javascript", p
    js_files = list(artifact_dir.rglob("*.js"))
    if js_files:
        return "javascript", js_files[0]

    # Shell scripts
    for ext in ("*.sh", "*.bash"):
        sh_files = list(artifact_dir.rglob(ext))
        if sh_files:
            return "shell", sh_files[0]

    # Binary / ELF
    for f in artifact_dir.rglob("*"):
        if f.is_file() and not f.suffix:
            try:
                magic = f.read_bytes()[:4]
                if magic[:4] == b"\x7fELF":
                    return "binary", f
            except Exception:
                pass

    return "unknown", None


# ---------------------------------------------------------------------------
# Execution strategies
# ---------------------------------------------------------------------------

def _run_node(entrypoint: Path, tmpdir: str) -> tuple[str, int | None, bool, str | None]:
    try:
        result = subprocess.run(
            ["strace", "-f", "-e", "trace=network,file,process", "-s", "200",
             "node", str(entrypoint)],
            capture_output=True, text=True, timeout=30, cwd=tmpdir,
        )
        return result.stdout + "\n" + result.stderr, result.returncode, True, None
    except subprocess.TimeoutExpired:
        return "", None, True, "Node.js execution timed out after 30s"
    except FileNotFoundError:
        return "", None, False, "node not installed"
    except Exception as e:
        return "", None, False, str(e)


def _run_python(entrypoint: Path, tmpdir: str) -> tuple[str, int | None, bool, str | None]:
    try:
        result = subprocess.run(
            ["strace", "-f", "-e", "trace=network,file,process", "-s", "200",
             "python", str(entrypoint)],
            capture_output=True, text=True, timeout=30, cwd=tmpdir,
        )
        return result.stdout + "\n" + result.stderr, result.returncode, True, None
    except subprocess.TimeoutExpired:
        return "", None, True, "Execution timed out after 30s"
    except Exception as e:
        return "", None, False, str(e)


def _run_shell(entrypoint: Path, tmpdir: str) -> tuple[str, int | None, bool, str | None]:
    try:
        result = subprocess.run(
            ["strace", "-f", "-e", "trace=network,file,process", "-s", "200",
             "bash", str(entrypoint)],
            capture_output=True, text=True, timeout=30, cwd=tmpdir,
        )
        return result.stdout + "\n" + result.stderr, result.returncode, True, None
    except subprocess.TimeoutExpired:
        return "", None, True, "Shell execution timed out after 30s"
    except Exception as e:
        return "", None, False, str(e)


def _inspect_binary(binary_path: Path) -> tuple[str, int | None, bool, str | None]:
    """
    For binaries: run 'strings' to extract readable content for signal matching.
    Never execute the binary.
    """
    try:
        result = subprocess.run(
            ["strings", "-n", "8", str(binary_path)],
            capture_output=True, text=True, timeout=15,
        )
        return result.stdout, 0, False, "Binary inspected via strings (not executed)"
    except Exception as e:
        return "", None, False, f"Binary inspection failed: {e}"


# ---------------------------------------------------------------------------
# AWS helpers
# ---------------------------------------------------------------------------

def _s3():
    return boto3.client("s3")


def _ddb():
    return boto3.resource("dynamodb")


def _write_report(table_name: str, report: dict) -> None:
    table = _ddb().Table(table_name)
    clean = {k: v for k, v in report.items() if v is not None}
    table.put_item(Item=clean)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    artifact_id = os.environ["ARTIFACT_ID"]
    bucket = os.environ["SCANNER_BUCKET"]
    results_table = os.environ["SANDBOX_RESULTS_TABLE"]
    now = datetime.now(timezone.utc).isoformat()

    quarantine_key = f"quarantine/{artifact_id}/artifact"

    with tempfile.TemporaryDirectory() as tmpdir:
        artifact_dir = Path(tmpdir) / "artifact"
        artifact_dir.mkdir()
        local_file = artifact_dir / "artifact"

        try:
            _s3().download_file(bucket, quarantine_key, str(local_file))
        except Exception as e:
            _write_report(results_table, {
                "artifact_id": artifact_id,
                "executed": False,
                "events": [],
                "suspicious_event_count": 0,
                "execution_error": f"Failed to download artifact: {e}",
                "timestamp": now,
            })
            return

        # Try to extract archive
        _try_extract(local_file, artifact_dir)

        file_type, entrypoint = _detect_type(artifact_dir)

        if not entrypoint:
            _write_report(results_table, {
                "artifact_id": artifact_id,
                "executed": False,
                "events": [],
                "suspicious_event_count": 0,
                "execution_error": f"No executable entrypoint found (type: {file_type})",
                "timestamp": now,
            })
            return

        started = time.monotonic()

        if file_type == "python":
            output, exit_code, executed, error = _run_python(entrypoint, tmpdir)
        elif file_type == "javascript":
            output, exit_code, executed, error = _run_node(entrypoint, tmpdir)
        elif file_type == "shell":
            output, exit_code, executed, error = _run_shell(entrypoint, tmpdir)
        elif file_type == "binary":
            output, exit_code, executed, error = _inspect_binary(entrypoint)
        else:
            output, exit_code, executed, error = "", None, False, "Unknown file type — not executed"

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


def _try_extract(local_file: Path, artifact_dir: Path) -> None:
    """Try to extract the file as an archive in-place."""
    import tarfile
    import zipfile
    import io

    data = local_file.read_bytes()

    try:
        with tarfile.open(fileobj=io.BytesIO(data)) as tf:
            tf.extractall(path=str(artifact_dir))
        return
    except Exception:
        pass

    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            zf.extractall(path=str(artifact_dir))
        return
    except Exception:
        pass

    # Not an archive — rename to artifact.py if it looks like Python
    try:
        text = data.decode("utf-8", errors="ignore")
        if "import " in text or "def " in text or "class " in text:
            (artifact_dir / "artifact.py").write_bytes(data)
    except Exception:
        pass


if __name__ == "__main__":
    main()
