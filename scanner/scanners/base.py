"""
Abstract base interface for all scanner tools.
Every scanner takes a local file path and returns a list of ScanFinding objects.
"""

from abc import ABC, abstractmethod
from datetime import datetime, timezone

from scanner.models.finding import ScanFinding


class BaseScanner(ABC):

    @abstractmethod
    def scan(self, artifact_id: str, artifact_path: str) -> list[ScanFinding]:
        """
        Run the scanner against the artifact at artifact_path.
        Returns a (possibly empty) list of ScanFinding objects.
        Must never raise — return an empty list on tool failure and log the error.
        """

    def _now(self) -> datetime:
        return datetime.now(timezone.utc)
