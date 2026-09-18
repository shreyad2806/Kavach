"""
PHASE 18 — Full Compromised Research Agent Attack Simulation.

One end-to-end attack scenario exercising ALL existing Kavach security layers:
  Identity → Agent State → Capability → Provenance → Cedar → Detection → Incident → Quarantine

Uses ONLY existing services. No duplication.

Architecture note:
  The pipeline short-circuits on provenance failure, so detection signals
  (CAPABILITY_MISMATCH, PRIVILEGE_ESCALATION, SUSPICIOUS_BEHAVIOR) only
  appear in reason_codes when provenance passes and Cedar evaluates the
  request.  AUTHORITY_MISMATCH from provenance is mutually exclusive with
  detection signals.  Maximum per-request risk through the Cedar-deny path
  is 55 (CAPABILITY_MISMATCH 30 + PRIVILEGE_ESCALATION 15 + SUSPICIOUS_BEHAVIOR 10).
"""

from datetime import datetime, timezone

import pytest

from shield.authorization.pipeline import authorize
from shield.capabilities.models import CapabilityName
from shield.enforcement.quarantine import QuarantineService
from shield.gateway.models import (
    ActionName,
    ActionRequest,
    AuthorizationDecision,
    CheckStatus,
    ReasonCode,
    RequestContext,
    ResourceName,
)
from shield.identity.models import AgentId, SecurityState
from shield.identity.service import IdentityService
from shield.incidents.models import IncidentStatus
from shield.incidents.service import IncidentService
from shield.provenance.models import Provenance


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_request(
    source_agent: AgentId,
    action: ActionName,
    resource: ResourceName,
    capability: CapabilityName,
    claimed_authority: AgentId | None = None,
    target_agent: AgentId | None = None,
    task_origin: AgentId | None = None,
    delegation_chain: list[AgentId] | None = None,
    request_id: str | None = None,
) -> ActionRequest:
    """Build an ActionRequest with configurable provenance chain."""
    if claimed_authority is None:
        claimed_authority = source_agent
    if target_agent is None:
        target_agent = source_agent
    if task_origin is None:
        task_origin = source_agent
    if delegation_chain is None:
        delegation_chain = [source_agent]
    if request_id is None:
        request_id = f"req-{source_agent.value}-{action.value}"
    return ActionRequest(
        request_id=request_id,
        timestamp=datetime.now(timezone.utc),
        source_agent=source_agent,
        target_agent=target_agent,
        task_id="task-attack-001",
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


def _run_pipeline(request, *, identity_service=None, incident_threshold=None):
    """Run one request through the full authorization pipeline, return (result, incident_service)."""
    ids = identity_service or IdentityService()
    inc_svc = IncidentService(threshold=incident_threshold) if incident_threshold is not None else IncidentService()
    result = authorize(
        request,
        identity_service=ids,
        incident_service=inc_svc,
    )
    return result, inc_svc


# ---------------------------------------------------------------------------
# Attack Scenario
# ---------------------------------------------------------------------------

class TestCompromisedResearchAgent:
    """
    End-to-end attack simulation: a legitimate research agent is compromised
    and progressively attempts privilege escalation, authority forgery, and
    repeated suspicious behaviour until quarantine.
    """

    def test_compromised_research_attack(self):
        """
        Execute the 8-step compromised-research-agent attack scenario.

        Architecture finding:
          The pipeline short-circuits on provenance failure, preventing
          detection signals from being evaluated.  AUTHORITY_MISMATCH is
          produced by provenance validation (not detection) and is mutually
          exclusive with detection signals like PRIVILEGE_ESCALATION.
          Maximum per-request risk through the Cedar-deny path is 55.
          The default INCIDENT_THRESHOLD (80) is not naturally reached by
          any single request.  Step 5 uses a configured threshold of 55
          to exercise the incident creation mechanism.
        """

        print("\n" + "=" * 64)
        print("  KAVACH — COMPROMISED RESEARCH AGENT ATTACK")
        print("=" * 64)

        # ==================================================================
        # STEP 1 — Legitimate research request
        #   research-01 | research.search | research-data | capability research.search
        #   Expected: ALLOW, risk=0
        # ==================================================================
        identity_1 = IdentityService()
        req1 = _make_request(
            source_agent=AgentId.RESEARCH_01,
            action=ActionName.RESEARCH_SEARCH,
            resource=ResourceName.RESEARCH_DATA,
            capability=CapabilityName.RESEARCH_SEARCH,
            request_id="req-step1-legit",
        )
        r1, _ = _run_pipeline(req1, identity_service=identity_1)

        print(f"\n  STEP 1  Legitimate research")
        print(f"          research.search / research-data")
        print(f"          -> {r1.decision.value}  risk={r1.risk_score}")

        assert r1.decision == AuthorizationDecision.ALLOW
        assert r1.reason_codes == []
        assert r1.checks.identity == CheckStatus.PASS
        assert r1.checks.agent_state == CheckStatus.PASS
        assert r1.checks.capability == CheckStatus.PASS
        assert r1.checks.provenance == CheckStatus.PASS
        assert r1.checks.cedar == CheckStatus.ALLOW
        assert r1.risk_score == 0

        # ==================================================================
        # STEP 2 — Capability escalation
        #   research-01 attempts deployment.deploy with capability research.search
        #   Pipeline flow: identity PASS -> state PASS -> capability PASS
        #     (research-01 HAS research.search) -> provenance PASS -> Cedar DENY
        #     (no permit for research-01 deploying) -> detection adds signals.
        #   Detection signals: CAPABILITY_MISMATCH (research.search != deployment.production),
        #     PRIVILEGE_ESCALATION (research agent doing deployment),
        #     SUSPICIOUS_BEHAVIOR (privilege escalation + other).
        #   Expected: DENY, POLICY_DENIED + CAPABILITY_MISMATCH + PRIVILEGE_ESCALATION
        #     + SUSPICIOUS_BEHAVIOR, risk=55
        # ==================================================================
        identity_2 = IdentityService()
        req2 = _make_request(
            source_agent=AgentId.RESEARCH_01,
            target_agent=AgentId.DEPLOYMENT_01,
            action=ActionName.DEPLOYMENT_DEPLOY,
            resource=ResourceName.PRODUCTION_ENVIRONMENT,
            capability=CapabilityName.RESEARCH_SEARCH,
            request_id="req-step2-cap-esc",
        )
        r2, _ = _run_pipeline(req2, identity_service=identity_2)

        print(f"\n  STEP 2  Capability escalation")
        print(f"          deployment.deploy / production-environment")
        print(f"          capability=research.search (wrong)")
        print(f"          -> {r2.decision.value}  risk={r2.risk_score}")
        print(f"          reasons={[c.value for c in r2.reason_codes]}")

        assert r2.decision == AuthorizationDecision.DENY
        assert ReasonCode.CAPABILITY_MISMATCH in r2.reason_codes
        assert ReasonCode.POLICY_DENIED in r2.reason_codes
        assert ReasonCode.PRIVILEGE_ESCALATION in r2.reason_codes
        assert ReasonCode.SUSPICIOUS_BEHAVIOR in r2.reason_codes
        # risk = 30(CAP) + 15(PRIV) + 10(SUSP) = 55 (POLICY_DENIED has weight 0)
        assert r2.risk_score == 55

        # ==================================================================
        # STEP 3 — Authority forgery
        #   Single-element chain [research-01] with claimed_authority=orchestrator-01.
        #   Provenance catches the mismatch: claimed_authority (orchestrator-01)
        #     != source_agent (research-01) for single-element chain.
        #   Pipeline short-circuits at provenance; detection never runs.
        #   Expected: DENY, AUTHORITY_MISMATCH, risk=25
        # ==================================================================
        identity_3 = IdentityService()
        req3 = _make_request(
            source_agent=AgentId.RESEARCH_01,
            target_agent=AgentId.DEPLOYMENT_01,
            action=ActionName.DEPLOYMENT_DEPLOY,
            resource=ResourceName.PRODUCTION_ENVIRONMENT,
            capability=CapabilityName.RESEARCH_SEARCH,
            claimed_authority=AgentId.ORCHESTRATOR_01,
            request_id="req-step3-auth-forge",
        )
        r3, _ = _run_pipeline(req3, identity_service=identity_3)

        print(f"\n  STEP 3  Authority forgery")
        print(f"          claimed_authority: orchestrator-01")
        print(f"          provenance chain: [research-01]")
        print(f"          -> {r3.decision.value}  risk={r3.risk_score}")
        print(f"          reasons={[c.value for c in r3.reason_codes]}")

        assert r3.decision == AuthorizationDecision.DENY
        assert ReasonCode.AUTHORITY_MISMATCH in r3.reason_codes
        # Provenance short-circuits; detection never runs.
        assert ReasonCode.CAPABILITY_MISMATCH not in r3.reason_codes
        assert ReasonCode.PRIVILEGE_ESCALATION not in r3.reason_codes
        assert r3.checks.provenance == CheckStatus.FAIL
        assert r3.checks.cedar == CheckStatus.NOT_EVALUATED
        assert r3.risk_score == 25  # AUTHORITY_MISMATCH weight

        # ==================================================================
        # STEP 4 — Repeated suspicious behaviour
        #   Send additional high-risk requests that exercise the real detection
        #   system.  Each request is evaluated independently.
        #
        #   Request A: deployment.deploy with valid2-element chain
        #     (passes provenance, Cedar denies, detection fires)
        #     risk=55
        #
        #   Request B: deployment.deploy with mismatched claimed_authority
        #     on a2-element chain (claimed=ORCHESTRATOR_01, chain=[ORCHESTRATOR_01,
        #     RESEARCH_01] — this passes provenance since claimed matches chain[-2])
        #     Cedar denies, detection fires.
        #     risk=55
        #
        #   Finding: maximum per-request risk through Cedar-deny path is 55
        #     (CAPABILITY_MISMATCH 30 + PRIVILEGE_ESCALATION 15 + SUSPICIOUS_BEHAVIOR 10).
        #     AUTHORITY_MISMATCH detection is unreachable when provenance passes
        #     (provenance's RULE D/E catches the same condition and short-circuits).
        # ==================================================================
        identity_4 = IdentityService()

        req4a = _make_request(
            source_agent=AgentId.RESEARCH_01,
            target_agent=AgentId.DEPLOYMENT_01,
            action=ActionName.DEPLOYMENT_DEPLOY,
            resource=ResourceName.PRODUCTION_ENVIRONMENT,
            capability=CapabilityName.RESEARCH_SEARCH,
            claimed_authority=AgentId.ORCHESTRATOR_01,
            task_origin=AgentId.ORCHESTRATOR_01,
            delegation_chain=[AgentId.ORCHESTRATOR_01, AgentId.RESEARCH_01],
            request_id="req-step4a-suspect",
        )
        r4a, _ = _run_pipeline(req4a, identity_service=identity_4)

        req4b = _make_request(
            source_agent=AgentId.RESEARCH_01,
            target_agent=AgentId.DEPLOYMENT_01,
            action=ActionName.DEPLOYMENT_DEPLOY,
            resource=ResourceName.PRODUCTION_ENVIRONMENT,
            capability=CapabilityName.RESEARCH_SEARCH,
            claimed_authority=AgentId.ORCHESTRATOR_01,
            task_origin=AgentId.ORCHESTRATOR_01,
            delegation_chain=[AgentId.ORCHESTRATOR_01, AgentId.RESEARCH_01],
            request_id="req-step4b-suspect",
        )
        r4b, _ = _run_pipeline(req4b, identity_service=identity_4)

        print(f"\n  STEP 4  Repeated suspicious behaviour")
        print(f"          Request A: risk={r4a.risk_score}  reasons={[c.value for c in r4a.reason_codes]}")
        print(f"          Request B: risk={r4b.risk_score}  reasons={[c.value for c in r4b.reason_codes]}")

        assert r4a.decision == AuthorizationDecision.DENY
        assert r4b.decision == AuthorizationDecision.DENY
        # Both produce real detection signals via the Cedar-deny path
        assert ReasonCode.CAPABILITY_MISMATCH in r4a.reason_codes
        assert ReasonCode.PRIVILEGE_ESCALATION in r4a.reason_codes
        assert ReasonCode.SUSPICIOUS_BEHAVIOR in r4a.reason_codes
        assert r4a.risk_score == 55
        assert r4b.risk_score == 55

        # ==================================================================
        # STEP 5 — Incident creation + Quarantine
        #
        #   Finding: the default INCIDENT_THRESHOLD (80) is not naturally
        #   reached by any single request with the current detection rules.
        #   Maximum per-request risk is 55 through the Cedar-deny path.
        #
        #   To exercise the incident creation mechanism, we use
        #   IncidentService(threshold=55) which is at or below the
        #   naturally-produced risk score.  The risk=55 is produced by
        #   the REAL detection system — we do not fabricate any scores.
        #
        #   After incident creation, quarantine research-01.
        # ==================================================================
        identity_5 = IdentityService()
        req5 = _make_request(
            source_agent=AgentId.RESEARCH_01,
            target_agent=AgentId.DEPLOYMENT_01,
            action=ActionName.DEPLOYMENT_DEPLOY,
            resource=ResourceName.PRODUCTION_ENVIRONMENT,
            capability=CapabilityName.RESEARCH_SEARCH,
            claimed_authority=AgentId.ORCHESTRATOR_01,
            task_origin=AgentId.ORCHESTRATOR_01,
            delegation_chain=[AgentId.ORCHESTRATOR_01, AgentId.RESEARCH_01],
            request_id="req-step5-incident",
        )
        # Use threshold=55 to match the naturally-produced risk score
        r5, inc_svc_5 = _run_pipeline(
            req5,
            identity_service=identity_5,
            incident_threshold=55,
        )

        assert r5.decision == AuthorizationDecision.DENY
        assert r5.risk_score == 55

        # Incident should be created because risk (55) >= threshold (55)
        incidents = inc_svc_5.list_all()
        assert len(incidents) >= 1
        incident = incidents[-1]
        assert incident.status == IncidentStatus.OPEN
        assert incident.agent_id == AgentId.RESEARCH_01

        # Now quarantine
        quarantine_svc = QuarantineService(identity_5)
        quarantine_svc.quarantine(AgentId.RESEARCH_01)

        agent = identity_5.get_agent(AgentId.RESEARCH_01)
        assert agent.state == SecurityState.QUARANTINED

        print(f"\n  STEP 5  Security response")
        print(f"          incident: {incident.incident_id}")
        print(f"          status: {incident.status.value}  severity: {incident.severity.value}")
        print(f"          agent: QUARANTINED")

        # ==================================================================
        # STEP 6 — Post-quarantine: research-01 -> coding-01
        #   Quarantine short-circuits the pipeline at CHECK 2 (Agent State).
        #   Expected: DENY, AGENT_QUARANTINED, capability/provenance/Cedar NOT_EVALUATED
        # ==================================================================
        req6 = _make_request(
            source_agent=AgentId.RESEARCH_01,
            target_agent=AgentId.CODING_01,
            action=ActionName.CODING_WRITE,
            resource=ResourceName.WORKSPACE,
            capability=CapabilityName.RESEARCH_SEARCH,
            request_id="req-step6-post-quarantine",
        )
        r6, _ = _run_pipeline(req6, identity_service=identity_5)

        print(f"\n  STEP 6  Research -> Coding")
        print(f"          coding.write / workspace")
        print(f"          -> {r6.decision.value}  reasons={[c.value for c in r6.reason_codes]}")

        assert r6.decision == AuthorizationDecision.DENY
        assert ReasonCode.AGENT_QUARANTINED in r6.reason_codes
        assert r6.checks.identity == CheckStatus.PASS
        assert r6.checks.agent_state == CheckStatus.FAIL
        assert r6.checks.capability == CheckStatus.NOT_EVALUATED
        assert r6.checks.provenance == CheckStatus.NOT_EVALUATED
        assert r6.checks.cedar == CheckStatus.NOT_EVALUATED

        # ==================================================================
        # STEP 7 — Post-quarantine: research-01 -> deployment-01
        # ==================================================================
        req7 = _make_request(
            source_agent=AgentId.RESEARCH_01,
            target_agent=AgentId.DEPLOYMENT_01,
            action=ActionName.DEPLOYMENT_DEPLOY,
            resource=ResourceName.PRODUCTION_ENVIRONMENT,
            capability=CapabilityName.RESEARCH_SEARCH,
            claimed_authority=AgentId.ORCHESTRATOR_01,
            task_origin=AgentId.ORCHESTRATOR_01,
            delegation_chain=[AgentId.ORCHESTRATOR_01, AgentId.RESEARCH_01],
            request_id="req-step7-post-quarantine-deploy",
        )
        r7, _ = _run_pipeline(req7, identity_service=identity_5)

        print(f"\n  STEP 7  Research -> Deployment")
        print(f"          deployment.deploy / production-environment")
        print(f"          -> {r7.decision.value}  reasons={[c.value for c in r7.reason_codes]}")

        assert r7.decision == AuthorizationDecision.DENY
        assert ReasonCode.AGENT_QUARANTINED in r7.reason_codes

        # ==================================================================
        # STEP 8 — Post-quarantine: AWS/tool boundary placeholder
        #   No AWS action exists in the current contract.
        #   Use DEPLOYMENT_PREVIEW on STAGING_ENVIRONMENT as the closest
        #   privileged/tool-facing action available.
        # ==================================================================
        req8 = _make_request(
            source_agent=AgentId.RESEARCH_01,
            target_agent=AgentId.DEPLOYMENT_01,
            action=ActionName.DEPLOYMENT_PREVIEW,
            resource=ResourceName.STAGING_ENVIRONMENT,
            capability=CapabilityName.RESEARCH_SEARCH,
            request_id="req-step8-post-quarantine-tool",
        )
        r8, _ = _run_pipeline(req8, identity_service=identity_5)

        print(f"\n  STEP 8  Research -> AWS/tool boundary placeholder")
        print(f"          deployment.preview / staging-environment")
        print(f"          -> {r8.decision.value}  reasons={[c.value for c in r8.reason_codes]}")

        assert r8.decision == AuthorizationDecision.DENY
        assert ReasonCode.AGENT_QUARANTINED in r8.reason_codes

        # ==================================================================
        # ATTACK STORY ASSERTION
        # ==================================================================
        print("\n" + "-" * 64)
        print("  ATTACK CONTAINED")
        print("-" * 64)
        print(f"  Step 1  ALLOW                risk={r1.risk_score}")
        print(f"  Step 2  DENY CAPABILITY_MISMATCH  risk={r2.risk_score}")
        print(f"          reasons={[c.value for c in r2.reason_codes]}")
        print(f"  Step 3  DENY AUTHORITY_MISMATCH   risk={r3.risk_score}")
        print(f"          reasons={[c.value for c in r3.reason_codes]}")
        print(f"  Step 4a DENY risk={r4a.risk_score}  reasons={[c.value for c in r4a.reason_codes]}")
        print(f"  Step 4b DENY risk={r4b.risk_score}  reasons={[c.value for c in r4b.reason_codes]}")
        print(f"  Step 5  Incident {incident.incident_id} OPEN | Agent QUARANTINED")
        print(f"  Step 6  DENY AGENT_QUARANTINED (research -> coding)")
        print(f"  Step 7  DENY AGENT_QUARANTINED (research -> deployment)")
        print(f"  Step 8  DENY AGENT_QUARANTINED (research -> tool/AWS boundary)")
        print("=" * 64 + "\n")

    def test_attack_risk_progression(self):
        """
        Focused test showing risk progression through real detection signals.

        Documents the finding that maximum per-request risk through the
        Cedar-deny path is 55, and AUTHORITY_MISMATCH from provenance
        (risk=25) is mutually exclusive with detection signals.
        """
        ids = IdentityService()

        # Legitimate: risk=0
        r_legit, _ = _run_pipeline(
            _make_request(
                source_agent=AgentId.RESEARCH_01,
                action=ActionName.RESEARCH_SEARCH,
                resource=ResourceName.RESEARCH_DATA,
                capability=CapabilityName.RESEARCH_SEARCH,
                request_id="req-risk-legit",
            ),
            identity_service=ids,
        )
        assert r_legit.risk_score == 0

        # Capability escalation (Cedar deny path): risk=55
        r_cap, _ = _run_pipeline(
            _make_request(
                source_agent=AgentId.RESEARCH_01,
                target_agent=AgentId.DEPLOYMENT_01,
                action=ActionName.DEPLOYMENT_DEPLOY,
                resource=ResourceName.PRODUCTION_ENVIRONMENT,
                capability=CapabilityName.RESEARCH_SEARCH,
                request_id="req-risk-cap",
            ),
            identity_service=ids,
        )
        assert r_cap.risk_score == 55
        assert ReasonCode.CAPABILITY_MISMATCH in r_cap.reason_codes
        assert ReasonCode.PRIVILEGE_ESCALATION in r_cap.reason_codes
        assert ReasonCode.SUSPICIOUS_BEHAVIOR in r_cap.reason_codes

        # Authority forgery (provenance short-circuit): risk=25
        r_auth, _ = _run_pipeline(
            _make_request(
                source_agent=AgentId.RESEARCH_01,
                target_agent=AgentId.DEPLOYMENT_01,
                action=ActionName.DEPLOYMENT_DEPLOY,
                resource=ResourceName.PRODUCTION_ENVIRONMENT,
                capability=CapabilityName.RESEARCH_SEARCH,
                claimed_authority=AgentId.ORCHESTRATOR_01,
                request_id="req-risk-auth",
            ),
            identity_service=ids,
        )
        assert r_auth.risk_score == 25
        assert ReasonCode.AUTHORITY_MISMATCH in r_auth.reason_codes

        # Verify AUTHORITY_MISMATCH and detection signals are mutually exclusive
        assert ReasonCode.CAPABILITY_MISMATCH not in r_auth.reason_codes
        assert ReasonCode.PRIVILEGE_ESCALATION not in r_auth.reason_codes

        print(f"\n  Risk progression:")
        print(f"    Legitimate:           {r_legit.risk_score}")
        print(f"    Capability escalation: {r_cap.risk_score}")
        print(f"    Authority forgery:     {r_auth.risk_score}")
        print(f"    Max per-request (Cedar-deny path): 55")
        print(f"    AUTHORITY_MISMATCH + detection signals: mutually exclusive")
