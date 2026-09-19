"""
kavach_logger.py — Centralized structured JSON logger for the Kavach platform.

Import:
    from kavach_logger import get_logger
    log = get_logger("kavach.agents.orchestrator")
    log.info("task delegated", extra={"agent": "orchestrator", "target": "research", "workflow_id": "wf-abc"})

Log files (logs/):
    kavach.log   — full platform firehose, every subsystem, DEBUG+
    agents.log   — 5 multi-agent workflow events only
    scanner.log  — scanner pipeline: gateway → static scan → sandbox → verdict → report
    shield.log   — shield runtime: authorization, Cedar, detection, incidents, enforcement
    audit.log    — security decisions only: every ALLOW/DENY, quarantine, violation (JSONL)
    errors.log   — WARNING+ across all subsystems, human-readable, for fast triage

Every log line is a single JSON object:
    {"timestamp": "...", "level": "INFO", "logger": "kavach.agents.orchestrator",
     "message": "task delegated", "agent": "orchestrator", "target": "research", "workflow_id": "wf-abc"}

Environment:
    LOG_LEVEL        — root console level, default INFO
    KAVACH_LOG_DIR   — override log directory, default ./logs
"""

import json
import logging
import logging.handlers
import os
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path


# ---------------------------------------------------------------------------
# Internal Python logging fields — never written to output JSON
# ---------------------------------------------------------------------------

_INTERNAL_FIELDS = frozenset({
    "name", "msg", "args", "levelname", "levelno", "pathname", "filename",
    "module", "exc_info", "exc_text", "stack_info", "lineno", "funcName",
    "created", "msecs", "relativeCreated", "thread", "threadName",
    "processName", "process", "message", "taskName",
})

_SETUP_LOCK = threading.Lock()
_INITIALIZED = False

# Sentinel class used to detect our own handlers and avoid duplicates
_KAVACH_HANDLER_ATTR = "_kavach_handler"


# ---------------------------------------------------------------------------
# Formatters
# ---------------------------------------------------------------------------

class _JsonFormatter(logging.Formatter):
    """Emits one compact JSON object per log record. No multi-line values."""

    def format(self, record: logging.LogRecord) -> str:
        entry: dict = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        for key, value in record.__dict__.items():
            if key not in _INTERNAL_FIELDS:
                entry[key] = value
        if record.exc_info:
            entry["exception"] = self.formatException(record.exc_info)
        return json.dumps(entry, default=str)


# Safe wrapper: renames any extra key that collides with a reserved LogRecord
# attribute before the record is created, preventing the KeyError crash.
_LOGRECORD_RESERVED = frozenset(logging.LogRecord("", 0, "", 0, "", (), None).__dict__.keys())


class _SafeLogger(logging.Logger):
    """Logger subclass that sanitizes extra= keys before record creation."""

    def makeRecord(self, name, level, fn, lno, msg, args, exc_info,
                   func=None, extra=None, sinfo=None):
        if extra:
            safe = {}
            for k, v in extra.items():
                safe[k if k not in _LOGRECORD_RESERVED else f"x_{k}"] = v
            extra = safe
        return super().makeRecord(name, level, fn, lno, msg, args, exc_info,
                                  func, extra, sinfo)


class _HumanFormatter(logging.Formatter):
    """Human-readable format for console and errors.log."""
    _FMT = "%(asctime)s  %(levelname)-8s  %(name)-42s  %(message)s"

    def __init__(self):
        super().__init__(fmt=self._FMT, datefmt="%Y-%m-%dT%H:%M:%S")


# ---------------------------------------------------------------------------
# Handler factory
# ---------------------------------------------------------------------------

def _rotating(log_dir: Path, filename: str, formatter: logging.Formatter) -> logging.handlers.RotatingFileHandler:
    h = logging.handlers.RotatingFileHandler(
        log_dir / filename, maxBytes=20 * 1024 * 1024, backupCount=5, encoding="utf-8"
    )
    h.setFormatter(formatter)
    setattr(h, _KAVACH_HANDLER_ATTR, True)
    return h


def _already_configured(logger: logging.Logger) -> bool:
    """Return True if this logger already has a Kavach handler attached."""
    return any(getattr(h, _KAVACH_HANDLER_ATTR, False) for h in logger.handlers)


# ---------------------------------------------------------------------------
# One-time setup — thread-safe, idempotent, no module-level I/O
# ---------------------------------------------------------------------------

def _setup() -> None:
    global _INITIALIZED
    if _INITIALIZED:
        return
    with _SETUP_LOCK:
        if _INITIALIZED:
            return

        log_dir = Path(os.environ.get("KAVACH_LOG_DIR", Path(__file__).resolve().parent / "logs"))
        log_dir.mkdir(parents=True, exist_ok=True)

        level_name = os.environ.get("LOG_LEVEL", "INFO").upper()
        level = getattr(logging, level_name, logging.INFO)

        json_fmt = _JsonFormatter()
        human_fmt = _HumanFormatter()

        root = logging.getLogger()
        root.setLevel(logging.DEBUG)

        # Only add handlers if not already present (guards against test re-imports)
        if not _already_configured(root):
            # kavach.log — full firehose, JSON, DEBUG+
            h_all = _rotating(log_dir, "kavach.log", json_fmt)
            h_all.setLevel(logging.DEBUG)
            root.addHandler(h_all)

            # errors.log — WARNING+ human-readable for fast triage
            h_err = _rotating(log_dir, "errors.log", human_fmt)
            h_err.setLevel(logging.WARNING)
            root.addHandler(h_err)

            # console — INFO+ (or LOG_LEVEL) human-readable
            h_con = logging.StreamHandler(sys.stdout)
            h_con.setFormatter(human_fmt)
            h_con.setLevel(level)
            setattr(h_con, _KAVACH_HANDLER_ATTR, True)
            root.addHandler(h_con)

        # Subsystem-specific files
        for prefix, filename in (
            ("kavach.agents",  "agents.log"),
            ("kavach.scanner", "scanner.log"),
            ("kavach.shield",  "shield.log"),
            ("kavach.audit",   "audit.log"),
            ("scanner",        "scanner.log"),
            ("shield",         "shield.log"),
        ):
            lg = logging.getLogger(prefix)
            if not _already_configured(lg):
                h = _rotating(log_dir, filename, json_fmt)
                h.setLevel(logging.DEBUG)
                lg.addHandler(h)
            lg.propagate = True

        _INITIALIZED = True


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def get_logger(name: str) -> logging.Logger:
    """
    Return a stdlib Logger for the given name.

    Naming convention:
        kavach.agents.<agent>    — orchestrator, research, coding, verification, deployment
        kavach.scanner.<module>  — gateway, pipeline, scanners, sandbox, verdict, agent
        kavach.shield.<module>   — authorization, detection, enforcement, identity, incidents
        kavach.audit             — security audit trail (ALLOW/DENY decisions, quarantine events)
        kavach.sandbox           — message bus, kavach_guard
        kavach.api               — REST API / FastAPI
    """
    _setup()
    # Use _SafeLogger for all kavach.* loggers so reserved-key collisions
    # in extra= dicts are silently renamed instead of crashing.
    prev_class = logging.getLoggerClass()
    logging.setLoggerClass(_SafeLogger)
    logger = logging.getLogger(name)
    logging.setLoggerClass(prev_class)
    return logger
