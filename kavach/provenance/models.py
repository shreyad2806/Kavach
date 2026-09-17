from pydantic import BaseModel, ConfigDict, Field, model_validator

from kavach.identity.models import AgentId


class Provenance(BaseModel):
    """
    Provenance contract representing the origin and delegation lineage of a request.
    Records invocation history without executing trust/policy decisions.
    """
    model_config = ConfigDict(extra="forbid")

    task_origin: AgentId = Field(
        ...,
        description="The root agent identifier that initiated the task execution."
    )
    delegation_chain: list[AgentId] = Field(
        ...,
        min_length=1,
        description="Ordered sequence of agent IDs tracing the delegation path to the current agent."
    )

    @model_validator(mode="after")
    def validate_origin_consistency(self) -> "Provenance":
        if not self.delegation_chain:
            raise ValueError("delegation_chain cannot be empty.")
        if self.delegation_chain[0] != self.task_origin:
            raise ValueError(
                f"task_origin '{self.task_origin.value}' must match the initial entry in delegation_chain '{self.delegation_chain[0].value}'."
            )
        return self
