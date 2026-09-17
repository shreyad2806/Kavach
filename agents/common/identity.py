from dataclasses import dataclass
from typing import FrozenSet


@dataclass(frozen=True)
class AgentIdentity:
    agent_id: str
    name: str
    role: str
    capabilities: FrozenSet[str]