from datetime import datetime, timezone

from shield.detection import detect
from shield.gateway.models import ActionName, ActionRequest, ResourceName, RequestContext
from shield.capabilities.models import CapabilityName
from shield.identity.models import AgentId
from shield.provenance.models import Provenance


def request(
    *,
    action=ActionName.RESEARCH_SEARCH,
    resource=ResourceName.RESEARCH_DATA,
    capability=CapabilityName.RESEARCH_SEARCH,
    source=AgentId.RESEARCH_01,
    chain=None,
    authority=None,
    tags=None,
):
    chain = chain or [AgentId.ORCHESTRATOR_01, AgentId.RESEARCH_01]
    authority = authority or chain[-2] if len(chain) > 1 else source
    return ActionRequest(
        request_id="test-request",
        timestamp=datetime.now(timezone.utc),
        source_agent=source,
        target_agent=AgentId.ORCHESTRATOR_01,
        task_id="test-task",
        action=action,
        resource=resource,
        claimed_authority=authority,
        capability=capability,
        provenance=Provenance(task_origin=chain[0], delegation_chain=chain),
        context=RequestContext(environment_tags=tags or {}),
    )


def test_contextual_detector_keeps_valid_research_request_low_risk():
    result = detect(request())
    assert result.risk_score == 0
    assert result.signals == []
    assert len(result.all_signals) == 5


def test_detector_flags_wrong_capability_and_wrong_resource():
    result = detect(request(
        action=ActionName.DEPLOYMENT_DEPLOY,
        resource=ResourceName.PRODUCTION_ENVIRONMENT,
    ))
    assert result.has_signal("CAPABILITY_MISMATCH")
    assert result.has_signal("PRIVILEGE_ESCALATION")
    assert result.has_signal("SUSPICIOUS_BEHAVIOR")
    assert result.risk_score > 0


def test_detector_flags_resource_action_mismatch():
    result = detect(request(
        action=ActionName.RESEARCH_SEARCH,
        resource=ResourceName.PRODUCTION_ENVIRONMENT,
    ))
    assert result.has_signal("SUSPICIOUS_BEHAVIOR")
    assert any("sensitivity" in s.explanation for s in result.signals)


def test_detector_flags_unsafe_production_environment_tags():
    result = detect(request(tags={"environment": "production", "debug": "true"}))
    assert result.has_signal("SUSPICIOUS_BEHAVIOR")
    assert any("production" in s.explanation.lower() for s in result.signals)


def test_detector_flags_overlong_delegation_chain():
    # A repeated or unsupported edge is independently an invalid provenance
    # chain; construct a valid schema chain to test the contextual depth rule.
    from shield.identity.models import AgentId
    chain = [AgentId.ORCHESTRATOR_01, AgentId.RESEARCH_01, AgentId.CODING_01]
    # The provenance validator will also detect unsupported delegation.
    result = detect(request(chain=chain, source=AgentId.CODING_01, authority=AgentId.RESEARCH_01))
    assert result.has_signal("PROVENANCE_ANOMALY")
    assert result.has_signal("SUSPICIOUS_BEHAVIOR")


def test_score_is_capped_and_deduplicated():
    from shield.detection.signals import calculate_risk
    from shield.gateway.models import ReasonCode
    assert calculate_risk([ReasonCode.IDENTITY_FAILURE] * 3) == 40
