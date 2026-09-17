"""
Sandbox runner — executes an artifact inside a restricted Docker container
and returns a SandboxReport.

Security constraints enforced on the container:
  - No network access (--network none)
  - Read-only root filesystem (--read-only)
  - Writable /tmp only via tmpfs
  - No new privileges (--security-opt no-new-privileges)
  - Dropped all Linux capabilities (--cap-drop ALL)
  - Non-root user (--user 65534 = nobody)
  - Hard CPU and memory limits
  - Execution timeout (default 30s)

The artifact directory is mounted read-only at /artifact inside the container.
The container runs: python /artifact/<entrypoint> and we capture all output.

For the hackathon demo the base image is python:3.11-slim.
In production this would be replaced with a hardened minimal image.
"""

import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

from scanner.models.sandbox import SandboxReport
from scanner.sandbox.observer import observe

SANDBOX_IMAGE = "python:3.11-slim"
DEFAULT_TIMEOUT = 30  # seconds
MEMORY_LIMIT = "128m"
CPU_LIMIT = "0.5"


class SandboxError(Exception):
    pass


def _find_entrypoint(artifact_path: str) -> str | None:
    """Find the most likely Python entrypoint in the artifact directory."""
    base = Path(artifact_path)
    for candidate in ("setup.py", "main.py", "app.py", "__main__.py"):
        if (base / candidate).exists():
            return candidate
    # Fall back to first .py file found
    py_files = list(base.glob("*.py"))
    return py_files[0].name if py_files else None


def run(
    artifact_id: str,
    artifact_path: str,
    timeout: int = DEFAULT_TIMEOUT,
) -> SandboxReport:
    """
    Execute the artifact in a restricted Docker container.
    Returns a SandboxReport regardless of outcome — never raises.
    """
    started = time.monotonic()
    now = datetime.now(timezone.utc)

    entrypoint = _find_entrypoint(artifact_path)
    if not entrypoint:
        return SandboxReport(
            artifact_id=artifact_id,
            executed=False,
            execution_error="No Python entrypoint found in artifact",
            timestamp=now,
        )

    cmd = [
        "docker", "run",
        "--rm",
        "--network", "none",
        "--read-only",
        "--tmpfs", "/tmp:size=32m",
        "--security-opt", "no-new-privileges",
        "--cap-drop", "ALL",
        "--user", "65534",
        "--memory", MEMORY_LIMIT,
        "--cpus", CPU_LIMIT,
        "--volume", f"{artifact_path}:/artifact:ro",
        SANDBOX_IMAGE,
        "python", f"/artifact/{entrypoint}",
    ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        output = result.stdout + "\n" + result.stderr
        exit_code = result.returncode
    except subprocess.TimeoutExpired:
        duration = time.monotonic() - started
        return SandboxReport(
            artifact_id=artifact_id,
            executed=True,
            execution_error=f"Sandbox timed out after {timeout}s",
            duration_seconds=round(duration, 2),
            timestamp=now,
        )
    except FileNotFoundError:
        # Docker not installed — fail gracefully
        return SandboxReport(
            artifact_id=artifact_id,
            executed=False,
            execution_error="Docker not available in this environment",
            timestamp=now,
        )
    except Exception as e:
        return SandboxReport(
            artifact_id=artifact_id,
            executed=False,
            execution_error=str(e),
            timestamp=now,
        )

    duration = round(time.monotonic() - started, 2)
    events = observe(artifact_id, output)
    suspicious_count = sum(1 for e in events if e.suspicious)

    return SandboxReport(
        artifact_id=artifact_id,
        executed=True,
        exit_code=exit_code,
        events=events,
        suspicious_event_count=suspicious_count,
        duration_seconds=duration,
        timestamp=now,
    )
