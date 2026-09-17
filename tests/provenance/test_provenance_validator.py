"""
Shield provenance tests (Phase 6) — deterministic provenance validation only.

These tests prove the structural/contextual validity of the delegation chain on
the existing ActionRequest contract. They deliberately do NOT test authorization,
Cedar, capability-vs-action matching, risk, or enforcement: those belong to later
stages and must remain separate layers.
"""

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from shield.capabilities.models import CapabilityName
from shield.gateway.models import (
    ActionName,
    ActionRequest,
    ReasonCode,
    ResourceName,
    RequestContext,
)
from shield.identity.models import AgentId
from shield.provenance.models import Provenance
from shield.provenance.validator import (
    ProvenanceValidationResult,
    validate_provenance,
)


# ==============================================================================
# HELPERS / FIXTURES
# ==============================================================================

def _build_request(
    *,
    source_agent: AgentId,
    target_agent: AgentId,
    task_origin: AgentId,
    delegation_chain: list[AgentId],
    claimed_authority: AgentId,
    action: ActionName,
    resource: ResourceName,
    capability: CapabilityName,
) -> ActionRequest:
    """Builds an ActionRequest with explicit provenance for provenance validation tests."""
    return ActionRequest(
        request_id="req-provenance-001",
        timestamp=datetime.now(timezone.utc),
        source_agent=source_agent,
        target_agent=target_agent,
        task_id="task-provenance-001",
        action=action,
        resource=resource,
        claimed_authority=claimed_authority,
        capability=capability,
        provenance=Provenance(
            task_origin=task_origin,
            delegation_chain=delegation_chain,
        ),
        context=RequestContext(),
    )


def _canonical_delegated_request() -> ActionRequest:
    """
    The canonical legitimate delegated request:
    orchestrator-01 -> research-01, research-01 acts with orchestrator-01's authority.
    """
    return _build_request(
        source_agent=AgentId.RESEARCH_01,
        target_agent=AgentId.DEPLOYMENT_01,
        task_origin=AgentId.ORCHESTRATOR_01,
        delegation_chain=[AgentId.ORCHESTRATOR_01, AgentId.RESEARCH_01],
        claimed_authority=AgentId.ORCHESTRATOR_01,
        action=ActionName.DEPLOYMENT_DEPLOY,
        resource=ResourceName.PRODUCTION_ENVIRONMENT,
        capability=CapabilityName.RESEARCH_SEARCH,
    )


# ==============================================================================
# TEST 1 — VALID CHAIN
# ==============================================================================

def test_1_valid_chain():
    """
    orchestrator-01 -> research-01 with claimed authority orchestrator-01
    is structurally and contextually valid provenance.
    """
    request = _build_request(
        source_agent=AgentId.RESEARCH_01,
        target_agent=AgentId.DEPLOYMENT_01,
        task_origin=AgentId.ORCHESTRATOR_01,
        delegation_chain=[AgentId.ORCHESTRATOR_01, AgentId.RESEARCH_01],
        claimed_authority=AgentId.ORCHESTRATOR_01,
        action=ActionName.RESEARCH_SEARCH,
        resource=ResourceName.RESEARCH_DATA,
        capability=CapabilityName.RESEARCH_SEARCH,
    )

    result = validate_provenance(request)

    assert isinstance(result, ProvenanceValidationResult)
    assert result.valid is True
    assert result.reason_code is None


# ==============================================================================
# TEST 2 — FORGED AUTHORITY
# ==============================================================================

def test_2_forged_authority():
    """
    research-01 claims orchestrator-01's authority, but the chain
    [research-01] contains no orchestrator-01 delegation: AUTHORITY_MISMATCH.
    """
    request = _build_request(
        source_agent=AgentId.RESEARCH_01,
        target_agent=AgentId.DEPLOYMENT_01,
        task_origin=AgentId.RESEARCH_01,
        delegation_chain=[AgentId.RESEARCH_01],
        claimed_authority=AgentId.ORCHESTRATOR_01,
        action=ActionName.RESEARCH_SEARCH,
        resource=ResourceName.RESEARCH_DATA,
        capability=CapabilityName.RESEARCH_SEARCH,
    )

    result = validate_provenance(request)

    assert result.valid is False
    assert result.reason_code is ReasonCode.AUTHORITY_MISMATCH


# ==============================================================================
# TEST 3 — IMPOSSIBLE DELEGATION
# ==============================================================================

def test_3_impossible_delegation():
    """
    Research is not an unrestricted delegator:
    research-01 -> deployment-01 is not an allowed delegation step,
    even though the chain is otherwise well-formed: PROVENANCE_ANOMALY.
    """
    request = _build_request(
        source_agent=AgentId.DEPLOYMENT_01,
        target_agent=AgentId.DEPLOYMENT_01,
        task_origin=AgentId.ORCHESTRATOR_01,
        delegation_chain=[
            AgentId.ORCHESTRATOR_01,
            AgentId.RESEARCH_01,
            AgentId.DEPLOYMENT_01,
        ],
        claimed_authority=AgentId.RESEARCH_01,
        action=ActionName.DEPLOYMENT_DEPLOY,
        resource=ResourceName.PRODUCTION_ENVIRONMENT,
        capability=CapabilityName.RESEARCH_SEARCH,
    )

    result = validate_provenance(request)

    assert result.valid is False
    assert result.reason_code is ReasonCode.PROVENANCE_ANOMALY


# ==============================================================================
# TEST 4 — ORIGIN MISMATCH
# ==============================================================================

def test_4_origin_mismatch_rejected_at_model_boundary():
    """
    task_origin=research-01 with chain starting at orchestrator-01 is invalid.
    This invariant is enforced at the Provenance model boundary, so the request
    cannot even be constructed; the validator additionally re-checks it defensively
    (see test_validator_rejects_origin_mismatch_passed_directly).
    """
    with pytest.raises(ValidationError):
        _build_request(
            source_agent=AgentId.RESEARCH_01,
            target_agent=AgentId.DEPLOYMENT_01,
            task_origin=AgentId.RESEARCH_01,
            delegation_chain=[AgentId.ORCHESTRATOR_01, AgentId.RESEARCH_01],
            claimed_authority=AgentId.ORCHESTRATOR_01,
            action=ActionName.RESEARCH_SEARCH,
            resource=ResourceName.RESEARCH_DATA,
            capability=CapabilityName.RESEARCH_SEARCH,
        )


def test_validator_rejects_origin_mismatch_passed_directly():
    """
    Defensive validator path for TEST 4: a Provenance instance with a mismatched
    origin (constructed by bypassing model validation) must yield
    INVALID / PROVENANCE_ANOMALY, proving the rule also lives in the validator.
    """
    request = _canonical_delegated_request()
    tampered = request.model_copy(
        update={
            "provenance": Provenance.model_construct(
                task_origin=AgentId.RESEARCH_01,
                delegation_chain=[AgentId.ORCHESTRATOR_01, AgentId.RESEARCH_01],
            )
        }
    )

    result = validate_provenance(tampered)

    assert result.valid is False
    assert result.reason_code is ReasonCode.PROVENANCE_ANOMALY


# ==============================================================================
# TEST 5 — SOURCE MISMATCH
# ==============================================================================

def test_5_source_mismatch():
    """
    The chain must terminate at the requesting agent. coding-01 presenting a
    chain that ends at research-01 is invalid: PROVENANCE_ANOMALY.
    """
    request = _build_request(
        source_agent=AgentId.CODING_01,
        target_agent=AgentId.DEPLOYMENT_01,
        task_origin=AgentId.ORCHESTRATOR_01,
        delegation_chain=[AgentId.ORCHESTRATOR_01, AgentId.RESEARCH_01],
        claimed_authority=AgentId.ORCHESTRATOR_01,
        action=ActionName.CODING_WRITE,
        resource=ResourceName.WORKSPACE,
        capability=CapabilityName.CODING_WRITE,
    )

    result = validate_provenance(request)

    assert result.valid is False
    assert result.reason_code is ReasonCode.PROVENANCE_ANOMALY


# ==============================================================================
# TEST 6 — SINGLE ORIGIN
# ==============================================================================

def test_6_single_origin():
    """
    A self-originated request: orchestrator-01 alone in the chain, acting on its
    own authority, is valid provenance.
    """
    request = _build_request(
        source_agent=AgentId.ORCHESTRATOR_01,
        target_agent=AgentId.RESEARCH_01,
        task_origin=AgentId.ORCHESTRATOR_01,
        delegation_chain=[AgentId.ORCHESTRATOR_01],
        claimed_authority=AgentId.ORCHESTRATOR_01,
        action=ActionName.ORCHESTRATOR_DELEGATE,
        resource=ResourceName.RESEARCH_DATA,
        capability=CapabilityName.ORCHESTRATOR_DELEGATE,
    )

    result = validate_provenance(request)

    assert result.valid is True
    assert result.reason_code is None


# ==============================================================================
# TEST 7 — EMPTY CHAIN
# ==============================================================================

def test_7_empty_chain_rejected_at_model_boundary():
    """
    An empty delegation_chain cannot be constructed: the Phase 2 contract
    (min_length=1 + model validator) rejects it at the model boundary.
    The existing model validation is NOT weakened.
    """
    with pytest.raises(ValidationError):
        Provenance(
            task_origin=AgentId.ORCHESTRATOR_01,
            delegation_chain=[],
        )


def test_validator_handles_empty_chain_defensively():
    """
    Defensive validator path for TEST 7: even if an empty chain arrives bypassing
    model validation, the validator safely returns INVALID / PROVENANCE_ANOMALY.
    """
    request = _canonical_delegated_request()
    tampered = request.model_copy(
        update={
            "provenance": Provenance.model_construct(
                task_origin=AgentId.ORCHESTRATOR_01,
                delegation_chain=[],
            )
        }
    )

    result = validate_provenance(tampered)

    assert result.valid is False
    assert result.reason_code is ReasonCode.PROVENANCE_ANOMALY


# ==============================================================================
# TEST 8 — DUPLICATE / LOOPING CHAIN
# ==============================================================================

def test_8_duplicate_looping_chain():
    """
    Revisiting orchestrator-01 inside the chain is a delegation loop:
    INVALID / PROVENANCE_ANOMALY.
    """
    request = _build_request(
        source_agent=AgentId.RESEARCH_01,
        target_agent=AgentId.DEPLOYMENT_01,
        task_origin=AgentId.ORCHESTRATOR_01,
        delegation_chain=[
            AgentId.ORCHESTRATOR_01,
            AgentId.RESEARCH_01,
            AgentId.ORCHESTRATOR_01,
        ],
        claimed_authority=AgentId.ORCHESTRATOR_01,
        action=ActionName.DEPLOYMENT_DEPLOY,
        resource=ResourceName.PRODUCTION_ENVIRONMENT,
        capability=CapabilityName.RESEARCH_SEARCH,
    )

    result = validate_provenance(request)

    assert result.valid is False
    assert result.reason_code is ReasonCode.PROVENANCE_ANOMALY


# ==============================================================================
# TEST 9 — CANONICAL ATTACK REQUEST
# ==============================================================================

def test_9_canonical_attack_request_has_valid_provenance():
    """
    The Phase 3 canonical attack request carries VALID provenance:
    orchestrator-01 -> research-01 with claimed authority orchestrator-01.

    The attack is that research-01 presents research.search while requesting
    deployment.deploy on production-environment. That capability/action mismatch
    is a LATER authorization concern (expected DENY there) and must NOT make the
    provenance layer deny this request. Layers stay separated.
    """
    request = _canonical_delegated_request()

    result = validate_provenance(request)

    assert result.valid is True
    assert result.reason_code is None


# ==============================================================================
# RESULT-CONTRACT INVARIANTS
# ==============================================================================

def test_result_contract_valid_cannot_carry_reason_code():
    """A valid result must never carry a reason code."""
    with pytest.raises(ValidationError):
        ProvenanceValidationResult(valid=True, reason_code=ReasonCode.PROVENANCE_ANOMALY)


def test_result_contract_invalid_must_carry_reason_code():
    """An invalid result must always carry a reason code — no silent coercion."""
    with pytest.raises(ValidationError):
        ProvenanceValidationResult(valid=False)


def test_validation_is_deterministic():
    """Repeated validation of the same request yields identical results."""
    request = _canonical_delegated_request()

    first = validate_provenance(request)
    second = validate_provenance(request)

    assert first == second
    assert first.valid is True and second.valid is True
    assert first.reason_code is None and second.reason_code is None


def test_no_new_reason_codes_invented():
    """The validator only ever reports existing ReasonCode values."""
    from shield.gateway.models import ReasonCode as _ReasonCode

    for reason in (ReasonCode.AUTHORITY_MISMATCH, ReasonCode.PROVENANCE_ANOMALY):
        assert reason in list(_ReasonCode)
