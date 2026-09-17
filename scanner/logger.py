"""
Scanner logger — structured JSON logging for Lambda and Fargate.

All scanner components import from here:
    from scanner.logger import get_logger
    log = get_logger(__name__)
    log.info("scan started", artifact_id=artifact_id, scanner="bandit")

Output format: JSON lines — one JSON object per log entry.
Lambda stdout is automatically captured by CloudWatch Logs.
Fargate stdout is captured by the awslogs driver.

Log levels follow standard Python logging:
    DEBUG   — detailed internal state (disabled in prod by default)
    INFO    — normal pipeline events (scan started, verdict produced, etc.)
    WARNING — recoverable issues (scanner tool not found, timeout, etc.)
    ERROR   — failures that affect a scan result
    CRITICAL — hard blocks, security-relevant events
"""

import json
import logging
import os
import sys
from datetime import datetime, timezone


# Read log level from environment — defaults to INFO
_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()


class _JsonFormatter(logging.Formatter):
    """Formats log records as single-line JSON objects."""

    def format(self, record: logging.LogRecord) -> str:
        entry: dict = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        # Attach any extra fields passed via log.info("msg", extra={...})
        for key, value in record.__dict__.items():
            if key not in (
                "name", "msg", "args", "levelname", "levelno", "pathname",
                "filename", "module", "exc_info", "exc_text", "stack_info",
                "lineno", "funcName", "created", "msecs", "relativeCreated",
                "thread", "threadName", "processName", "process", "message",
                "taskName",
            ):
                entry[key] = value

        if record.exc_info:
            entry["exception"] = self.formatException(record.exc_info)

        return json.dumps(entry, default=str)


def get_logger(name: str) -> logging.Logger:
    """
    Return a logger for the given module name.
    Configures JSON formatting on first call; subsequent calls reuse the handler.
    """
    logger = logging.getLogger(name)

    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(_JsonFormatter())
        logger.addHandler(handler)
        logger.propagate = False

    logger.setLevel(getattr(logging, _LEVEL, logging.INFO))
    return logger
