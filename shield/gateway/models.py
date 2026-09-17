from datetime import datetime
from enum import Enum
from typing import Any
from pydantic import BaseModel, ConfigDict, Field, model_validator

from shield.capabilities.models import CapabilityName
from shield.identity.models import AgentId, SecurityState
from shield.provenance.models import Provenance


class ResourceName(str, Enum):
    RESEARCH_DATA = "research-data"
    WORKSPACE = "workspace"
    TEST_ENVIRONMENT = "test-environment"
    STAGING_ENVIRONMENT = "staging-environment"
    PRODUCTION_ENVIRONMENT = "production-environment"


class ActionName(str, Enum):
    RESEARCH_SEARCH = "research.search"
    RESEARCH_READ = "research.read"
    CODING_READ = "coding.read"
    CODING_WRITE = "coding.write"
    CODING_TEST = "coding.test"
    DEPLOYMENT_PREVIEW = "deployment.preview"
    DEPLOYMENT_DEPLOY = "deployment.deploy"
    VERIFICATION_TEST = "verification.test"
    ORCHESTRATOR_DELEGATE = "orchestrator.delegate"
    ORCHESTRATOR_COORDINATE = "orchestrator.coordinate"


class AuthorizationDecision(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"


class ReasonCode(str, Enum):
    IDENTITY_FAILURE = "IDENTITY_FAILURE"
    CAPABILITY_MISMATCH = "CAPABILITY_MISMATCH"
    AUTHORITY_MISMATCH = "AUTHORITY_MISMATCH"
    PROVENANCE_ANOMALY = "PROVENANCE_ANOMALY"
    POLICY_DENIED = "POLICY_DENIED"
    AGENT_QUARANTINED = "AGENT_QUARANTINED"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    SUSPICIOUS_BEHAVIOR = "SUSPICIOUS_BEHAVIOR"


class RequestContext(BaseModel):
    """
    Minimal context payload for supplemental metadata.
    Must not contain primary request entities (capability, action, resource, source_agent, target_agent).
    """
    model_config = ConfigDict(extra="allow")

    environment_tags: dict[str, str] = Field(
        default_factory=dict,
        description="Optional environmental or infrastructure tags."
    )

    @model_validator(mode="after")
    def reject_core_entities_in_context(self) -> "RequestContext":
        forbidden = {"capability", "action", "resource", "source_agent", "target_agent"}
        if self.model_extra:
            present_forbidden = forbidden.intersection(self.model_extra.keys())
            if present_forbidden:
                raise ValueError(
                    f"Core entities must not be placed inside context: {', '.join(sorted(present_forbidden))}"
                )
        return self


class ActionRequest(BaseModel):
    """
    ActionRequest contract representing a runtime request from an agent to the Kavach Gateway.
    Separates presented capability from requested action.
    Contains no authorization calculation logic or decision fields.
    """
    model_config = ConfigDict(extra="forbid")

    request_id: str = Field(
        ...,
        min_length=1,
        description="Unique request identifier."
    )
    timestamp: datetime = Field(
        ...,
        description="UTC ISO 8601 timestamp of the request."
    )
    source_agent: AgentId = Field(
        ...,
        description="Identity of the requesting agent."
    )
    target_agent: AgentId = Field(
        ...,
        description="Identity of the receiving agent or target handler."
    )
    task_id: str = Field(
        ...,
        min_length=1,
        description="Top-level workflow task identifier."
    )
    parent_event_id: str | None = Field(
        default=None,
        description="Optional causal parent event identifier."
    )
    action: ActionName = Field(
        ...,
        description="Requested action the agent is attempting to perform."
    )
    resource: ResourceName = Field(
        ...,
        description="Target resource operated on by the requested action."
    )
    claimed_authority: AgentId = Field(
        ...,
        description="Untrusted claim of delegating authority."
    )
    capability: CapabilityName = Field(
        ...,
        description="Capability token presented by the source agent."
    )
    provenance: Provenance = Field(
        ...,
        description="Lineage and delegation chain context."
    )
    context: RequestContext = Field(
        default_factory=RequestContext,
        description="Supplemental request context."
    )


class AuthorizationChecks(BaseModel):
    """
    Structured outcome flags for individual security verification stages.
    Populated by downstream security services; defaults to uncalculated (None).
    """
    model_config = ConfigDict(extra="forbid")

    identity: bool | None = Field(default=None, description="Identity validation outcome.")
    capability: bool | None = Field(default=None, description="Capability verification outcome.")
    provenance: bool | None = Field(default=None, description="Provenance graph validation outcome.")
    cedar: bool | None = Field(default=None, description="Cedar policy engine outcome.")
    deterministic_rules: bool | None = Field(default=None, description="Deterministic security rules outcome.")


class AuthorizationResult(BaseModel):
    """
    Output contract returned by Kavach Gateway downstream to callers.
    Provides deterministic verdict, reason codes, advisory score, and agent state.
    """
    model_config = ConfigDict(extra="forbid")

    request_id: str = Field(
        ...,
        min_length=1,
        description="Identifier of the evaluated request."
    )
    decision: AuthorizationDecision = Field(
        ...,
        description="Deterministic authorization outcome (ALLOW | DENY)."
    )
    reason_codes: list[ReasonCode] = Field(
        default_factory=list,
        description="List of security reason codes explaining the verdict."
    )
    risk_score: int | None = Field(
        default=None,
        ge=0,
        le=100,
        description="Advisory risk score (0-100). Not the authorization authority."
    )
    checks: AuthorizationChecks = Field(
        default_factory=AuthorizationChecks,
        description="Structured verification check details."
    )
    agent_state: SecurityState = Field(
        ...,
        description="Current runtime security status of the calling agent."
    )
