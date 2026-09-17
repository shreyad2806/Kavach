"""
Provenance Validator — deterministic structural validation of delegation provenance.

Answers strictly: "Is this request's provenance structurally and contextually consistent?"

Contains NO authorization logic: no Cedar, no policy evaluation, no risk or anomaly
scoring, no LLM reasoning, no enforcement, and no network calls. A valid provenance
outcome is one input to a later authorization stage — never a decision by itself.
"""

from pydantic import BaseModel, ConfigDict, Field, model_validator

from shield.gateway.models import ActionRequest, ReasonCode
from shield.identity.models import AgentId


# Minimal canonical delegation table (Phase 6 specification).
# The initial allowed delegation relationship is orchestrator-01 -> research-01.
# Research is NOT an unrestricted delegator; deliberately no generic graph engine
# and no large role hierarchy — deterministic and minimal by design.
_ALLOWED_DELEGATIONS: frozenset[tuple[AgentId, AgentId]] = frozenset(
    {
        (AgentId.ORCHESTRATOR_01, AgentId.RESEARCH_01),
    }
)


class ProvenanceValidationResult(BaseModel):
    """
    Deterministic provenance validation outcome for a single ActionRequest.
    Clearly distinguishes VALID from INVALID and carries an existing ReasonCode
    when invalid. Pure data contract: it performs no decision or enforcement logic.
    """

    model_config = ConfigDict(extra="forbid")

    valid: bool = Field(
        ...,
        description="True when provenance is structurally and contextually consistent.",
    )
    reason_code: ReasonCode | None = Field(
        default=None,
        description="Existing ReasonCode explaining invalid provenance; None when valid.",
    )

    @model_validator(mode="after")
    def enforce_reason_code_consistency(self) -> "ProvenanceValidationResult":
        if self.valid and self.reason_code is not None:
            raise ValueError("A valid provenance result must not carry a reason code.")
        if not self.valid and self.reason_code is None:
            raise ValueError("An invalid provenance result must carry a reason code.")
        return self


def _invalid(reason_code: ReasonCode) -> ProvenanceValidationResult:
    """Builds a deterministic invalid result for the given existing ReasonCode."""
    return ProvenanceValidationResult(valid=False, reason_code=reason_code)


def _claimed_authority_consistent(request: ActionRequest) -> bool:
    """
    RULE D / RULE E — the claimed authority must be represented consistently by
    the provenance chain:
      - self-originated single-element chain: the agent acts on its own authority;
      - delegated chain: the claimed authority must be the direct delegator
        (the chain element immediately preceding the source agent).
    """
    chain = request.provenance.delegation_chain
    if len(chain) == 1:
        return request.claimed_authority == request.source_agent
    return request.claimed_authority == chain[-2]


def validate_provenance(request: ActionRequest) -> ProvenanceValidationResult:
    """
    Deterministically validates the provenance of an existing ActionRequest.

    Evaluation order (first failure wins; fully deterministic):
      1. RULE A    — non-empty delegation chain (defensive re-check; already
                     enforced at the Provenance model boundary).
      2. RULE B    — chain root equals task_origin (defensive re-check; already
                     enforced at the Provenance model boundary).
      3. LOOP      — no agent repeats in the chain (delegation loops).
      4. RULE F    — every consecutive delegation step must be an allowed
                     delegation relationship (impossible delegation).
      5. RULE C    — chain terminates at source_agent.
      6. RULE D/E  — claimed_authority consistent with the chain, otherwise
                     AUTHORITY_MISMATCH.

    Returns a ProvenanceValidationResult; never raises for rule violations.
    This is provenance validation ONLY — it is not authorization and must not be
    treated as an authorization decision.
    """
    provenance = request.provenance
    chain = provenance.delegation_chain

    # RULE A — non-empty chain (safely handled even though the model enforces it).
    if not chain:
        return _invalid(ReasonCode.PROVENANCE_ANOMALY)

    # RULE B — task origin must be the chain root.
    if chain[0] != provenance.task_origin:
        return _invalid(ReasonCode.PROVENANCE_ANOMALY)

    # Loop prevention — a delegation chain must not revisit an agent.
    if len(set(chain)) != len(chain):
        return _invalid(ReasonCode.PROVENANCE_ANOMALY)

    # RULE F — impossible delegation: each consecutive step must be an allowed
    # delegation relationship.
    for delegator, delegate in zip(chain, chain[1:]):
        if (delegator, delegate) not in _ALLOWED_DELEGATIONS:
            return _invalid(ReasonCode.PROVENANCE_ANOMALY)

    # RULE C — the chain must terminate at the requesting agent.
    if chain[-1] != request.source_agent:
        return _invalid(ReasonCode.PROVENANCE_ANOMALY)

    # RULES D / E — claimed authority must be consistent with the chain.
    if not _claimed_authority_consistent(request):
        return _invalid(ReasonCode.AUTHORITY_MISMATCH)

    return ProvenanceValidationResult(valid=True)
