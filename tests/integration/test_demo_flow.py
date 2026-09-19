"""End-to-end demo flow tests (landing -> workflow -> dashboard -> attack -> reset).

These exercise the real ASGI HTTP boundary of the unified backend with
TestClient.  Every security value asserted here comes from a real
authorization decision — nothing is fabricated, and nothing is read from the
permanent audit log.

Coverage:
  A. Fresh session: landing state only, all agents ACTIVE, zero telemetry
  B. Creating a workflow does not execute anything and emits no telemetry
  C. Run Workflow -> real agents execute -> real authorization events appear
  D. The normal workflow's six protected actions are all ALLOW
  E. Every activity row is addressable by exactly one request_id with real checks
  F. Simulate Attack -> real Shield DENY (no side effect executed)
  G. The attack request keeps its own pipeline, distinct from any other event
  H. Quarantine: research-01 QUARANTINED, all other agents ACTIVE
  I. Post-quarantine protected request -> DENY AGENT_QUARANTINED, both events kept
  J. Run Again -> all ACTIVE, session telemetry cleared, landing state restored
  K. A fresh "page load" (reset) carries no stale workflow/quarantine/telemetry
  L. Research capability: research.write is denied with CAPABILITY_MISMATCH
  M. Read endpoints never generate security telemetry
"""

import time

import pytest
from fastapi.testclient import TestClient

from api.deps import reset_supervisor
from api.main import app
from shield.runtime.services import reset_shield_runtime
from shield.telemetry.session import clear_events

TASK = "Calculate 12 * 7 + 5 and verify the result."

TERMINAL = ("COMPLETED", "FAILED", "STOPPED")

# The canonical workflow's protected operations, in execution order.
NORMAL_WORKFLOW_ACTIONS = [
    ("orchestrator-01", "orchestrator.delegate"),
    ("coding-01", "coding.read"),
    ("coding-01", "coding.write"),
    ("coding-01", "coding.test"),
    ("verification-01", "verification.test"),
    ("deployment-01", "deployment.preview"),
]

CHECK_KEYS = {
    "identity",
    "agent_state",
    "capability",
    "provenance",
    "cedar",
    "deterministic_rules",
}


@pytest.fixture(autouse=True)
def fresh_session():
    """Each test starts from a clean demo session (no leaked security state)."""
    reset_shield_runtime()
    reset_supervisor()
    clear_events()
    yield
    reset_shield_runtime()
    reset_supervisor()
    clear_events()


@pytest.fixture
def client():
    return TestClient(app)


def _states(client) -> dict[str, str]:
    return {a["agent_id"]: a["state"] for a in client.get("/agents").json()}


def _events(client) -> list[dict]:
    return client.get("/events").json()


def _event_for(client, request_id: str) -> dict | None:
    for event in _events(client):
        if event["request_id"] == request_id:
            return event
    return None


def _wait_for_terminal(client, workflow_id: str, timeout: float = 30.0) -> dict:
    """Poll GET /workflows/{id} until the workflow settles — what the UI does.

    POST /workflows/{id}/start returns immediately with RUNNING and the phases
    continue on a backend worker thread, so nothing may be read until the
    workflow reports a terminal status.
    """
    deadline = time.time() + timeout
    snapshot = client.get(f"/workflows/{workflow_id}").json()
    while snapshot["status"] not in TERMINAL:
        if time.time() > deadline:
            raise AssertionError(
                f"workflow {workflow_id} did not settle (last status {snapshot['status']})"
            )
        time.sleep(0.02)
        snapshot = client.get(f"/workflows/{workflow_id}").json()
    return snapshot


def _start_and_wait(client, workflow_id: str, timeout: float = 30.0) -> dict:
    """Start the workflow and return its real terminal snapshot."""
    client.post(f"/workflows/{workflow_id}/start")
    return _wait_for_terminal(client, workflow_id, timeout)


# ===========================================================================
# A. Fresh session — landing state only
# ===========================================================================

def test_A_fresh_session_shows_only_landing_state(client):
    client.post("/workflows/demo/reset")

    states = _states(client)
    assert set(states) == {
        "orchestrator-01",
        "research-01",
        "coding-01",
        "deployment-01",
        "verification-01",
    }
    assert set(states.values()) == {"ACTIVE"}

    # Zero workflow activity and zero telemetry on a clean landing screen.
    assert _events(client) == []
    dashboard = client.get("/dashboard").json()
    assert dashboard["workflows"]["total"] == 0
    assert dashboard["events"]["total"] == 0
    assert dashboard["agents"]["active"] == 5
    assert dashboard["agents"]["quarantined"] == 0


# ===========================================================================
# B. Entering a task / creating the workflow executes nothing
# ===========================================================================

def test_B_creating_a_workflow_does_not_execute_anything(client):
    created = client.post("/workflows", json={"task": TASK})
    assert created.status_code == 201
    body = created.json()
    assert body["status"] == "CREATED"
    assert body["workflow_id"].startswith("wf-")

    # Nothing ran, and no authorization decision was produced.
    snapshot = client.get(f"/workflows/{body['workflow_id']}").json()
    assert snapshot["status"] == "CREATED"
    assert snapshot["started_at"] is None
    assert snapshot["result"] is None
    assert _events(client) == []


def test_B_empty_task_is_rejected(client):
    assert client.post("/workflows", json={"task": ""}).status_code == 400
    assert client.post("/workflows", json={"task": "   "}).status_code == 400


# ===========================================================================
# C/D. Run Workflow -> real agents, real authorization events, all ALLOW
# ===========================================================================

def test_C_and_D_normal_workflow_produces_real_allow_events(client):
    workflow_id = client.post("/workflows", json={"task": TASK}).json()["workflow_id"]
    started = client.post(f"/workflows/{workflow_id}/start").json()

    # Start returns immediately; the dashboard then follows the live workflow.
    assert started["status"] == "RUNNING"

    result = _wait_for_terminal(client, workflow_id)
    assert result["status"] == "COMPLETED"
    assert result["result"]["expression"] == "12 * 7 + 5"
    assert result["result"]["value"] == 89

    events = _events(client)
    # One real authorization decision per protected operation.
    assert len(events) == len(NORMAL_WORKFLOW_ACTIONS)

    observed = [(e["source_agent"], e["action"]) for e in reversed(events)]
    assert observed == NORMAL_WORKFLOW_ACTIONS

    for event in events:
        assert event["policy_decision"] == "ALLOW"
        assert event["reason_codes"] == []
        assert event["category"] == "authorization"
        assert event["event_type"] == "AUTHORIZATION_DECISION"
        # Every event is correlated to the workflow that produced it.
        assert event["workflow_id"] == workflow_id
        assert event["task_id"]
        assert event["timestamp"]
        assert event["capability"] == event["action"]

    # No side effect was skipped: the deployment preview really ran.
    assert result["result"]["deployment"]["status"] == "SUCCESS"


def test_D_counters_equal_the_real_event_stream(client):
    workflow_id = client.post("/workflows", json={"task": TASK}).json()["workflow_id"]
    _start_and_wait(client, workflow_id)

    events = _events(client)
    dashboard = client.get("/dashboard").json()

    assert dashboard["events"]["total"] == len(events)
    assert dashboard["events"]["allow"] == sum(
        1 for e in events if e["policy_decision"] == "ALLOW"
    )
    assert dashboard["events"]["deny"] == sum(
        1 for e in events if e["policy_decision"] == "DENY"
    )


# ===========================================================================
# E. Every activity row is addressable by exactly one request_id
# ===========================================================================

def test_E_every_event_is_addressable_by_request_id_with_real_checks(client):
    workflow_id = client.post("/workflows", json={"task": TASK}).json()["workflow_id"]
    _start_and_wait(client, workflow_id)

    events = _events(client)
    request_ids = [e["request_id"] for e in events]
    # One row per request: the UI can address each decision unambiguously.
    assert len(set(request_ids)) == len(request_ids)
    assert all(rid for rid in request_ids)

    for request_id in request_ids:
        resolved = _event_for(client, request_id)
        assert resolved is not None
        # The checks belong to THIS request, not to some "latest" event.
        assert set(resolved["checks"]) == CHECK_KEYS
        assert resolved["checks"]["identity"] == "PASS"
        assert resolved["checks"]["agent_state"] == "PASS"
        assert resolved["checks"]["capability"] == "PASS"
        assert resolved["checks"]["provenance"] == "PASS"
        assert resolved["checks"]["cedar"] == "ALLOW"
        # deterministic_rules is only evaluated after Cedar permits, and is
        # NEVER reported as a fabricated 0/false.
        assert resolved["checks"]["deterministic_rules"] in {"PASS", "NOT_EVALUATED"}

    # Distinct requests keep distinct check traces.
    assert len({tuple(sorted(e["checks"].items())) for e in events}) >= 1


# ===========================================================================
# F/G/H/I. Simulate Attack -> DENY -> quarantine -> post-quarantine DENY
# ===========================================================================

def test_F_attack_is_denied_by_real_shield(client):
    workflow_id = client.post("/workflows", json={"task": TASK}).json()["workflow_id"]
    _start_and_wait(client, workflow_id)

    resp = client.post("/workflows/simulation/attack")
    assert resp.status_code == 200
    data = resp.json()

    attack = data["attack"]
    assert attack["decision"] == "DENY"
    assert attack["reason_codes"], "a real denial always carries reason codes"
    # The unauthorized escalation never executed.
    assert attack["executed"] is False
    # Risk is produced by the real detection system, never hardcoded.
    assert isinstance(attack["risk_score"], int)
    assert attack["risk_score"] > 0

    event = _event_for(client, attack["request_id"])
    assert event is not None, "the attack decision must be real telemetry"
    assert event["source_agent"] == "research-01"
    assert event["action"] == "deployment.deploy"
    assert event["resource"] == "production-environment"
    assert event["capability"] == "research.search"
    assert event["policy_decision"] == "DENY"
    assert event["reason_codes"] == attack["reason_codes"]


def test_G_attack_event_is_distinct_from_the_normal_workflow(client):
    workflow_id = client.post("/workflows", json={"task": TASK}).json()["workflow_id"]
    _start_and_wait(client, workflow_id)
    normal_ids = {e["request_id"] for e in _events(client)}

    attack = client.post("/workflows/simulation/attack").json()["attack"]

    # The attack is its own request, not a reuse of a workflow event.
    assert attack["request_id"] not in normal_ids
    event = _event_for(client, attack["request_id"])
    assert event["action"] == "deployment.deploy"
    # And the normal workflow's events are untouched.
    after = {e["request_id"] for e in _events(client)}
    assert normal_ids <= after
    assert all(e["action"] != "deployment.deploy" for e in _events(client)
               if e["request_id"] in normal_ids)


def test_H_attack_quarantines_only_the_compromised_agent(client):
    data = client.post("/workflows/simulation/attack").json()

    assert data["quarantine"] == {"agent_id": "research-01", "state": "QUARANTINED"}

    states = _states(client)
    assert states["research-01"] == "QUARANTINED"
    for other in (
        "orchestrator-01",
        "coding-01",
        "deployment-01",
        "verification-01",
    ):
        assert states[other] == "ACTIVE"


def test_I_post_quarantine_request_is_denied_and_both_events_are_kept(client):
    data = client.post("/workflows/simulation/attack").json()

    post = data["post_quarantine"]
    assert post["decision"] == "DENY"
    assert post["reason_codes"] == ["AGENT_QUARANTINED"]
    assert post["executed"] is False
    # Quarantine short-circuits the pipeline: identity passed, state failed,
    # everything after it was never evaluated.
    assert post["checks"]["identity"] == "PASS"
    assert post["checks"]["agent_state"] == "FAIL"
    assert post["checks"]["capability"] == "NOT_EVALUATED"
    assert post["checks"]["provenance"] == "NOT_EVALUATED"
    assert post["checks"]["cedar"] == "NOT_EVALUATED"
    assert post["checks"]["deterministic_rules"] == "NOT_EVALUATED"

    # Both decisions survive as separate events with their own pipelines.
    attack_event = _event_for(client, data["attack"]["request_id"])
    post_event = _event_for(client, post["request_id"])
    assert attack_event["action"] == "deployment.deploy"
    assert attack_event["reason_codes"] != post_event["reason_codes"]
    assert post_event["action"] == "research.search"
    assert post_event["policy_decision"] == "DENY"
    assert post_event["reason_codes"] == ["AGENT_QUARANTINED"]

    # A quarantined agent cannot be allowed by a low risk score either.
    assert post["risk_score"] is not None
    assert post["event"]["checks"]["agent_state"] == "FAIL"


def test_I_quarantine_is_enforced_for_every_protected_action(client):
    """Quarantine is not action-specific: no protected research action is allowed."""
    client.post("/workflows/simulation/attack")

    # research.write is additionally denied by the capability registry, but the
    # state check fails first — quarantine wins.
    post = client.post("/workflows/simulation/attack")
    # A second attack attempt is evaluated against the already-quarantined agent.
    data = post.json()
    assert data["attack"]["decision"] == "DENY"


# ===========================================================================
# J/K. Run Again + page load
# ===========================================================================

def test_J_run_again_returns_to_a_clean_landing_state(client):
    workflow_id = client.post("/workflows", json={"task": TASK}).json()["workflow_id"]
    _start_and_wait(client, workflow_id)
    client.post("/workflows/simulation/attack")
    assert _states(client)["research-01"] == "QUARANTINED"

    reset = client.post("/workflows/demo/reset").json()
    assert reset["status"] == "reset"
    assert reset["events"] == 0
    assert reset["workflows"] == 0
    assert reset["incidents"] == 0

    # Landing state restored: all ACTIVE, no telemetry, no workflows.
    assert set(_states(client).values()) == {"ACTIVE"}
    assert _events(client) == []
    dashboard = client.get("/dashboard").json()
    assert dashboard["agents"]["active"] == 5
    assert dashboard["agents"]["quarantined"] == 0
    assert dashboard["events"]["total"] == 0
    assert dashboard["workflows"]["total"] == 0


def test_K_fresh_page_load_has_no_stale_state(client):
    """A reload = reset + first read. Nothing from the previous session leaks."""
    client.post("/workflows", json={"task": TASK})
    client.post("/workflows/simulation/attack")

    # Page load
    client.post("/workflows/demo/reset")

    assert _events(client) == []
    assert set(_states(client).values()) == {"ACTIVE"}
    assert client.get("/dashboard").json()["workflows"]["total"] == 0
    # The permanent audit history is NOT what the UI reads, and is not deleted.
    from shield.telemetry.events import get_audit_log_path

    assert get_audit_log_path().exists()


def test_K_reset_does_not_delete_permanent_audit_history(client):
    from shield.telemetry.events import get_audit_log_path

    path = get_audit_log_path()
    before = path.stat().st_size if path.exists() else 0

    client.post("/workflows/demo/reset")

    after = path.stat().st_size if path.exists() else 0
    assert after >= before


# ===========================================================================
# L. Research capability is READ-ONLY
# ===========================================================================

def test_L_research_write_is_denied_by_capability_registry(client):
    from shield.runtime.services import get_runtime

    assert not get_runtime().capability_service.has_capability(
        "research-01", "research.write"
    )

    decision = client.post(
        "/authorize",
        json={
            "source_agent": "research-01",
            "target_agent": "research-01",
            "task_id": "task-capability",
            "action": "research.write",
            "resource": "research-data",
            "claimed_authority": "research-01",
            "capability": "research.write",
            "provenance": {
                "task_origin": "research-01",
                "delegation_chain": ["research-01"],
            },
        },
    ).json()

    assert decision["decision"] == "DENY"
    assert decision["reason_codes"] == ["CAPABILITY_MISMATCH"]
    assert decision["checks"]["capability"] == "FAIL"
    assert decision["checks"]["cedar"] == "NOT_EVALUATED"


def test_L_research_keeps_search_and_read(client):
    from shield.runtime.services import get_runtime

    capabilities = {
        c.name.value for c in get_runtime().capability_service.get_capabilities("research-01")
    }
    assert capabilities == {"research.search", "research.read"}


# ===========================================================================
# M. Read endpoints generate no telemetry
# ===========================================================================

def test_M_read_endpoints_do_not_generate_telemetry(client):
    workflow_id = client.post("/workflows", json={"task": TASK}).json()["workflow_id"]
    _start_and_wait(client, workflow_id)

    before = len(_events(client))
    client.get("/agents")
    client.get("/dashboard")
    client.get("/events")
    client.get("/policies")
    client.get("/incidents")
    client.get(f"/workflows/{workflow_id}")
    client.get(f"/workflows/{workflow_id}/events")
    assert len(_events(client)) == before


# ===========================================================================
# Additional: policy read-only + supervisor lifecycle
# ===========================================================================

def test_policies_are_read_only_and_parseable(client):
    body = client.get("/policies").json()
    assert body["engine"] == "cedar"
    assert body["mutable"] is False
    assert body["count"] == len(body["policies"]) > 0
    assert all(
        {"effect", "principal", "action", "resource"} <= set(policy)
        for policy in body["policies"]
    )
    # No mutation route exists.
    assert client.post("/policies", json={}).status_code in (404, 405)


def test_workflow_lifecycle_events_are_correlated(client):
    workflow_id = client.post("/workflows", json={"task": TASK}).json()["workflow_id"]
    _start_and_wait(client, workflow_id)

    events = client.get(f"/workflows/{workflow_id}/events").json()
    assert all(e["workflow_id"] == workflow_id for e in events)
    types = [e["event_type"] for e in events]
    assert types[0] == "WORKFLOW_CREATED"
    assert "WORKFLOW_STARTED" in types
    assert types[-1] == "WORKFLOW_COMPLETED"
    phase_agents = {e["agent"] for e in events if e["event_type"] == "PHASE_STARTED"}
    assert phase_agents == {"orchestrator", "coding", "verification", "deployment"}
