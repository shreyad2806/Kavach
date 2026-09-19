"""
Scanner logger — thin shim that delegates to the centralized kavach_logger.

All scanner components continue to use:
    from scanner.logger import get_logger
    log = get_logger(__name__)

Logs flow to:
    logs/scanner.log   — scanner-specific JSON log
    logs/kavach.log    — full platform firehose
    logs/errors.log    — WARNING+ for fast triage
"""

from kavach_logger import get_logger as _get_logger
import logging


def get_logger(name: str) -> logging.Logger:
    """
    Return a logger for the given scanner module name.
    Remaps 'scanner.*' names to 'kavach.scanner.*' so they route to scanner.log.
    """
    if name.startswith("scanner"):
        name = "kavach." + name
    return _get_logger(name)
