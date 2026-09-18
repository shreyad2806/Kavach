"""
Test stable schema across ALLOW and DENY results.
"""

from datetime import datetime, timezone

from shield.authorization.pipeline import authorize
from shield.gateway.models import (
    ActionName,
    ActionRequest,
    AuthorizationDecision,
    ResourceName,
)
from shield.identity.models import AgentId
from shield.provenance.models import Provenance
from shield.gateway.models import RequestContext


def test_stable_schema_allow_vs_deny():
    """
    TEST 9 — STABLE SCHEMA
    
    For ALLOW and DENY results verify the same top-level keys exist.
    The frontend must not need separate response shapes for success and failure.
    """
    # Create ALLOW result
    allow_request = ActionRequest(
        request_id="req-stable-001",
        timestamp=datetime.now(timezone.utc),
        source_agent=AgentId.RESEARCH_01,
        target_agent=AgentId.RESEARCH_01,
        task_id="task-001",
        action=ActionName.RESEARCH_SEARCH,
        resource=ResourceName.RESEARCH_DATA,
        claimed_authority=AgentId.ORCHESTRATOR_01,
        capability=ActionName.RESEARCH_SEARCH,
        provenance=Provenance(
            task_origin=AgentId.ORCHESTRATOR_01,
            delegation_chain=[AgentId.ORCHESTRATOR_01, AgentId.RESEARCH_01],
        ),
        context=RequestContext(),
    )

    allow_result = authorize(allow_request)

    # Create DENY result
    deny_request = ActionRequest(
        request_id="req-stable-002",
        timestamp=datetime.now(timezone.utc),
        source_agent=AgentId.RESEARCH_01,
        target_agent=AgentId.DEPLOYMENT_01,
        task_id="task-002",
        action=ActionName.DEPLOYMENT_DEPLOY,
        resource=ResourceName.PRODUCTION_ENVIRONMENT,
        claimed_authority=AgentId.ORCHESTRATOR_01,
        capability=ActionName.RESEARCH_SEARCH,
        provenance=Provenance(
            task_origin=AgentId.ORCHESTRATOR_01,
            delegation_chain=[AgentId.ORCHESTRATOR_01, AgentId.RESEARCH_01],
        ),
        context=RequestContext(),
    )

    deny_result = authorize(deny_request)

    # Serialize both to dicts
    allow_dict = allow_result.model_dump()
    deny_dict = deny_result.model_dump()

    # Verify both have the same top-level keys
    allow_keys = set(allow_dict.keys())
    deny_keys = set(deny_dict.keys())

    assert allow_keys == deny_keys

    # Verify expected keys exist in both
    expected_keys = {"request_id", "decision", "risk_score", "reason_codes", "checks", "agent_state"}
    assert expected_keys.issubset(allow_keys)
    assert expected_keys.issubset(deny_keys)

    # Verify checks sub-structure also has same keys
    allow_check_keys = set(allow_dict["checks"].keys())
    deny_check_keys = set(deny_dict["checks"].keys())

    assert allow_check_keys == deny_check_keys

    expected_check_keys = {
        "identity",
        "agent_state",
        "capability",
        "provenance",
        "cedar",
        "deterministic_rules",
    }
    assert expected_check_keys.issubset(allow_check_keys)
    assert expected_check_keys.issubset(deny_check_keys)
