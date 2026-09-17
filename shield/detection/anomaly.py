"""
Anomaly Detector — tracks per-agent denial counts and flags repeated-denial signals.
"""

from collections import defaultdict

from shield.gateway.models import AuthorizationDecision, AuthorizationResult
from shield.identity.models import AgentId

_DEFAULT_THRESHOLD = 3


class AnomalyDetector:
    def __init__(self, denial_threshold: int = _DEFAULT_THRESHOLD) -> None:
        self._threshold = denial_threshold
        self._denial_counts: dict[AgentId, int] = defaultdict(int)

    def observe(self, agent_id: AgentId, result: AuthorizationResult) -> list[str]:
        """Record result and return any newly triggered anomaly signal names."""
        if result.decision == AuthorizationDecision.DENY:
            self._denial_counts[agent_id] += 1

        signals: list[str] = []
        if self._denial_counts[agent_id] >= self._threshold:
            signals.append("REPEATED_DENIAL")

        return signals

    def get_denial_count(self, agent_id: AgentId) -> int:
        return self._denial_counts[agent_id]

    def reset(self, agent_id: AgentId | None = None) -> None:
        if agent_id is None:
            self._denial_counts.clear()
        else:
            self._denial_counts[agent_id] = 0
