from scanner.sandbox.observer import observe
from scanner.sandbox.runner import run
from scanner.sandbox.signals import SIGNALS


class SandboxError(Exception):
    """Kept for backwards compatibility — Fargate runner never raises but callers may catch this."""


__all__ = ["run", "observe", "SIGNALS", "SandboxError"]
