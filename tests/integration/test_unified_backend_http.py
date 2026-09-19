"""HTTP integration tests for the unified Python backend (api.main).

These exercise the real ASGI HTTP boundary (FastAPI routing, middleware,
serialization) with TestClient — not direct Python function calls.  The
centerpiece is the end-to-end security invariant:

    HTTP isolate -> QuarantineService -> get_shield_runtime().identity_service
    HTTP workflow start -> real P1 AgentTools -> KavachGuard
                         -> get_shield_runtime() -> authorize() -> DENY
                         -> AGENT_QUARANTINED

proving the HTTP control plane and the real P1 runtime share ONE Shield state.
"""

import time

import pytest
from fastapi.testclient import TestClient

from api.deps import reset_supervisor
from api.main import app
from shield.runtime.services import reset_shield_runtime

TERMINAL = ("COMPLETED", "FAILED", "STOPPED")


def _start(client, workflow_id):
    """Start a workflow; returns the IMMEDIATE snapshot (status RUNNING).

    POST /workflows/{id}/start intentionally does not block: the phases run on
    a backend worker thread and the caller polls, exactly like the UI.
    """
    started = client.post(f"/workflows/{workflow_id}/start")
    assert started.status_code == 200
    return started.json()


def _wait_for_terminal(client, workflow_id, timeout=30.0):
    """Poll GET /workflows/{id} until the workflow settles."""
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


def _start_and_wait(client, workflow_id, timeout=30.0):
    """Start a workflow and wait for its real terminal snapshot."""
    _start(client, workflow_id)
    return _wait_for_terminal(client, workflow_id, timeout)


@pytest.fixture(autouse=True)
def fresh_state():
    """Each test gets a clean shared runtime and supervisor, restored after."""
    reset_shield_runtime()
    reset_supervisor()
    yield
    reset_shield_runtime()
    reset_supervisor()


@pytest.fixture
def client():
    return TestClient(app)


# ---------------------------------------------------------------------------
# 1. Health
# ---------------------------------------------------------------------------

def test_health(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


# ---------------------------------------------------------------------------
# 8. Agents list / get / unknown
# ---------------------------------------------------------------------------

def test_agents_list_exposes_five_real_identities(client):
    resp = client.get("/agents")
    assert resp.status_code == 200
    agents = resp.json()
    assert isinstance(agents, list)
    ids = {a["agent_id"] for a in agents}
    assert ids == {
        "orchestrator-01",
        "research-01",
        "coding-01",
        "deployment-01",
        "verification-01",
    }
    for agent in agents:
        assert agent["state"] == "ACTIVE"
        assert agent["role"]
        # risk_score is not authoritative in Shield -> must be null, never faked.
        assert agent["risk_score"] is None


def test_get_agent_and_unknown(client):
    assert client.get("/agents/research-01").json()["agent_id"] == "research-01"
    assert client.get("/agents/does-not-exist").status_code == 404


# ---------------------------------------------------------------------------
# 9/11. Quarantine + restore through HTTP, reflected in real identity state
# ---------------------------------------------------------------------------

def test_isolate_and_restore(client):
    assert client.post("/agents/research-01/isolate").json()["state"] == "QUARANTINED"
    assert client.get("/agents/research-01").json()["state"] == "QUARANTINED"
    assert client.post("/agents/research-01/restore").json()["state"] == "ACTIVE"
    assert client.get("/agents/research-01").json()["state"] == "ACTIVE"


def test_isolate_unknown_agent(client):
    assert client.post("/agents/ghost/isolate").status_code == 404


# ---------------------------------------------------------------------------
# 4-7. Workflow lifecycle over HTTP (real WorkflowSupervisor + real P1 agents)
# ---------------------------------------------------------------------------

def test_workflow_create_start_complete_and_events(client):
    created = client.post("/workflows", json={"task": "compute fibonacci"})
    assert created.status_code == 201
    body = created.json()
    assert body["status"] == "CREATED"
    workflow_id = body["workflow_id"]

    # GET before start reflects real state.
    assert client.get(f"/workflows/{workflow_id}").json()["status"] == "CREATED"

    started = client.post(f"/workflows/{workflow_id}/start")
    assert started.status_code == 200
    # Start returns IMMEDIATELY with RUNNING — it never blocks on the phases.
    assert started.json()["status"] == "RUNNING"
    summary = _wait_for_terminal(client, workflow_id)
    assert summary["status"] == "COMPLETED"
    # Real P1 results are present (coding/verification/deployment phases ran).
    assert summary["result"]["coding"]
    assert summary["result"]["deployment"]

    events = client.get(f"/workflows/{workflow_id}/events").json()
    assert isinstance(events, list) and len(events) > 0
    types = [e["event_type"] for e in events]
    assert "WORKFLOW_CREATED" in types
    assert "WORKFLOW_STARTED" in types
    assert "WORKFLOW_COMPLETED" in types
    assert all(e["workflow_id"] == workflow_id for e in events)


def test_workflow_create_requires_task(client):
    assert client.post("/workflows", json={"task": "   "}).status_code == 400


def test_workflow_start_twice_conflicts(client):
    workflow_id = client.post("/workflows", json={"task": "x"}).json()["workflow_id"]
    assert client.post(f"/workflows/{workflow_id}/start").status_code == 200
    # Already COMPLETED -> cannot start again.
    assert client.post(f"/workflows/{workflow_id}/start").status_code == 409


def test_workflow_stop_created(client):
    workflow_id = client.post("/workflows", json={"task": "stop me"}).json()["workflow_id"]
    stopped = client.post(f"/workflows/{workflow_id}/stop")
    assert stopped.status_code == 200
    assert stopped.json()["status"] == "STOPPED"


def test_unknown_workflow(client):
    assert client.get("/workflows/nope").status_code == 404
    assert client.post("/workflows/nope/start").status_code == 404
    assert client.get("/workflows/nope/events").status_code == 404


# ---------------------------------------------------------------------------
# 10/12/13. CRITICAL: HTTP quarantine reaches the real P1 KavachGuard
# ---------------------------------------------------------------------------

def test_http_quarantine_denies_real_p1_protected_operation(client):
    """The full invariant: HTTP -> real P1 AgentTools -> KavachGuard -> DENY.

    The canonical workflow runs orchestrator -> coding -> verification ->
    deployment, so coding-01 is the participating agent used here.
    """
    # Baseline: a legitimate workflow completes through the real P1 agents.
    baseline = client.post("/workflows", json={"task": "baseline"}).json()["workflow_id"]
    assert _start_and_wait(client, baseline)["status"] == "COMPLETED"

    # Quarantine coding-01 through the HTTP control plane.
    assert client.post("/agents/coding-01/isolate").json()["state"] == "QUARANTINED"

    # A real workflow whose first protected coding operation must now be denied
    # by the SAME ShieldRuntime the HTTP isolate mutated.
    attack = client.post("/workflows", json={"task": "exfiltrate"}).json()["workflow_id"]
    result = _start_and_wait(client, attack)

    assert result["status"] == "FAILED"
    assert result["result"]["kavach_denied"] is True
    assert result["result"]["decision"] == "DENY"
    assert "AGENT_QUARANTINED" in result["result"]["reason_codes"]
    assert "AGENT_QUARANTINED" in result["error"]

    # 13. Other agents remain operational (only coding-01 is quarantined).
    states = {a["agent_id"]: a["state"] for a in client.get("/agents").json()}
    assert states["coding-01"] == "QUARANTINED"
    for other in ("orchestrator-01", "research-01", "deployment-01", "verification-01"):
        assert states[other] == "ACTIVE"

    # 11/13. Restore -> legitimate work works again through real P1.
    assert client.post("/agents/coding-01/restore").json()["state"] == "ACTIVE"
    legit = client.post("/workflows", json={"task": "legit again"}).json()["workflow_id"]
    assert _start_and_wait(client, legit)["status"] == "COMPLETED"


# ---------------------------------------------------------------------------
# 7. Events reflect real authorization decisions (shared audit sink)
# ---------------------------------------------------------------------------

def test_events_expose_real_authorization_decisions(client):
    decision = client.post(
        "/authorize",
        json={
            "source_agent": "research-01",
            "target_agent": "research-01",
            "task_id": "task-events",
            "action": "research.search",
            "resource": "research-data",
            "claimed_authority": "research-01",
            "capability": "research.search",
            "provenance": {
                "task_origin": "research-01",
                "delegation_chain": ["research-01"],
            },
        },
    ).json()
    request_id = decision["request_id"]

    events = client.get("/events").json()
    assert isinstance(events, list)
    matching = [e for e in events if e.get("request_id") == request_id]
    assert matching, "the authorization decision must appear in /events"
    event = matching[-1]
    for field in (
        "event_id",
        "timestamp",
        "source_agent",
        "action",
        "resource",
        "policy_decision",
        "reason_codes",
    ):
        assert field in event
    assert event["category"] == "authorization"
    assert event["policy_decision"] == "ALLOW"


# ---------------------------------------------------------------------------
# 14. Incidents endpoint (shared IncidentService)
# ---------------------------------------------------------------------------

def test_incidents_endpoint(client):
    incidents = client.get("/incidents").json()
    assert isinstance(incidents, list)
    assert client.get("/incidents/does-not-exist").status_code == 404


# ---------------------------------------------------------------------------
# 15. Dashboard is a read-only projection of real state
# ---------------------------------------------------------------------------

def test_dashboard_projection(client):
    # Create some real state first.
    client.post("/agents/research-01/isolate")
    client.post("/workflows", json={"task": "dash"}).json()

    dash = client.get("/dashboard").json()
    assert dash["agents"]["total"] == 5
    assert dash["agents"]["quarantined"] == 1
    assert dash["agents"]["active"] == 4
    assert dash["workflows"]["created"] >= 1
    assert "incidents" in dash and "events" in dash


# ---------------------------------------------------------------------------
# Policies are read-only
# ---------------------------------------------------------------------------

def test_policies_read_only(client):
    body = client.get("/policies").json()
    assert body["engine"] == "cedar"
    assert body["mutable"] is False
    assert body["count"] > 0
    assert all({"effect", "principal", "action", "resource"} <= set(p) for p in body["policies"])
    # No mutation route exists -> POST is not allowed.
    assert client.post("/policies", json={}).status_code == 405


# ---------------------------------------------------------------------------
# 16/17. Scanner proxy contract + API-key handling + AWS unavailability
# ---------------------------------------------------------------------------

def test_artifacts_requires_api_key(client, monkeypatch):
    monkeypatch.setenv("API_KEY", "test-key")
    body = {
        "artifact_type": "python_package",
        "source_url": "https://example.com/pkg.tar.gz",
        "requested_by": "operator",
    }
    assert client.post("/artifacts/scan", json=body, headers={"x-api-key": "wrong"}).status_code == 401


def test_artifacts_scan_returns_503_when_aws_unavailable(client, monkeypatch):
    """Real handler is invoked; missing AWS config surfaces as 503, not 500."""
    monkeypatch.setenv("API_KEY", "test-key")
    # Force the AWS-backed storage layer to be unconfigured.
    monkeypatch.delenv("ARTIFACTS_TABLE", raising=False)
    monkeypatch.delenv("FINDINGS_TABLE", raising=False)
    monkeypatch.delenv("VERDICTS_TABLE", raising=False)
    body = {
        "artifact_type": "python_package",
        "source_url": "https://example.com/pkg.tar.gz",
        "requested_by": "operator",
    }
    resp = client.post("/artifacts/scan", json=body, headers={"x-api-key": "test-key"})
    assert resp.status_code == 503
    assert resp.json()["error"] == "Scanner service unavailable"


def test_artifacts_status_returns_503_when_aws_unavailable(client, monkeypatch):
    monkeypatch.setenv("API_KEY", "test-key")
    monkeypatch.delenv("ARTIFACTS_TABLE", raising=False)
    resp = client.get("/artifacts/art-unknown", headers={"x-api-key": "test-key"})
    assert resp.status_code == 503
    assert resp.json()["error"] == "Scanner service unavailable"
