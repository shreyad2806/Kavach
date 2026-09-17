"""
Anomaly Detector — tracks per-agent denial counts and flags repeated-denial signals.
"""

from collections import defaultdict

from kavach.detection.signals import SignalType, ThreatSignal, SIGNAL_MAP
from kavach.gateway.models import AuthorizationDecision, AuthorizationResult
from kavach.identity.models import AgentId

_DEFAULT_THRESHOLD = 3


class AnomalyDetector:
    def __init__(self, denial_threshold: int = _DEFAULT_THRESHOLD) -> None:
        self._threshold = denial_threshold
        self._denial_counts: dict[AgentId, int] = defaultdict(int)

    def observe(self, agent_id: AgentId, result: AuthorizationResult) -> list[ThreatSignal]:
        """Record result and return any newly triggered anomaly signals."""
        if result.decision == AuthorizationDecision.DENY:
            self._denial_counts[agent_id] += 1

        signals: list[ThreatSignal] = []
        if self._denial_counts[agent_id] >= self._threshold:
            signals.append(SIGNAL_MAP[SignalType.REPEATED_DENIAL])

        return signals

    def get_denial_count(self, agent_id: AgentId) -> int:
        return self._denial_counts[agent_id]

    def reset(self, agent_id: AgentId | None = None) -> None:
        if agent_id is None:
            self._denial_counts.clear()
        else:
            self._denial_counts[agent_id] = 0
