from enum import Enum
from pydantic import BaseModel, ConfigDict, Field


class CapabilityName(str, Enum):
    RESEARCH_SEARCH = "research.search"
    RESEARCH_READ = "research.read"
    CODING_READ = "coding.read"
    CODING_WRITE = "coding.write"
    CODING_TEST = "coding.test"
    DEPLOYMENT_PREVIEW = "deployment.preview"
    DEPLOYMENT_PRODUCTION = "deployment.production"
    VERIFICATION_TEST = "verification.test"
    ORCHESTRATOR_DELEGATE = "orchestrator.delegate"
    ORCHESTRATOR_COORDINATE = "orchestrator.coordinate"


class Capability(BaseModel):
    """
    Capability contract representing an explicit permission grant.
    Defines what an agent is authorized to possess.
    Distinct from runtime requested actions.
    """
    model_config = ConfigDict(extra="forbid")

    name: CapabilityName = Field(
        ...,
        description="Constrained capability identifier."
    )
    description: str = Field(
        ...,
        min_length=1,
        description="Formal description of the operational scope permitted by this capability."
    )
