from enum import Enum
from pydantic import BaseModel, ConfigDict, Field


class AgentId(str, Enum):
    ORCHESTRATOR_01 = "orchestrator-01"
    RESEARCH_01 = "research-01"
    CODING_01 = "coding-01"
    DEPLOYMENT_01 = "deployment-01"
    VERIFICATION_01 = "verification-01"


class AgentRole(str, Enum):
    ORCHESTRATOR = "orchestrator"
    RESEARCH = "research"
    CODING = "coding"
    DEPLOYMENT = "deployment"
    VERIFICATION = "verification"


class SecurityState(str, Enum):
    ACTIVE = "ACTIVE"
    SUSPICIOUS = "SUSPICIOUS"
    QUARANTINED = "QUARANTINED"
    TERMINATED = "TERMINATED"


class AgentIdentity(BaseModel):
    """
    Cryptographic / logical agent identity contract.
    Represents identity and runtime security state only.
    Capabilities are intentionally maintained in a separate contract.
    """
    model_config = ConfigDict(extra="forbid")

    agent_id: AgentId = Field(
        ...,
        description="Exact identifier of the registered autonomous agent."
    )
    role: AgentRole = Field(
        ...,
        description="Assigned role category of the agent."
    )
    state: SecurityState = Field(
        default=SecurityState.ACTIVE,
        description="Current runtime security status of the agent."
    )
