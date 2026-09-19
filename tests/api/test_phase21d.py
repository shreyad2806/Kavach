"""
Phase 21D API tests — covers all required test cases A through T.

Tests prove:
- All new endpoints work correctly
- Shared-runtime invariant: quarantine via API → KavachGuard DENY
- Restore via API → KavachGuard ALLOW
- Other agents unaffected during quarantine
- Workflows use real KavachGuard enforcement path
- POST /policies does NOT mutate Cedar policies
"""

import pytest
from fastapi.testclient import TestClient

from agents.supervisor.registry import reset_registry
from sandbox.runtime.kavach_guard import KavachDeniedError, configure_all_guards
from shield.runtime.services import reset_runtime


@pytest.fixture(autouse=True)
def fresh_runtime_and_registry():
    """Reset shared state before each test for isolation."""
    runtime = reset_runtime()
    configure_all_guards(runtime)
    reset_registry()
    # Re-import app after reset so it picks up the new runtime
    yield


@pytest.fixture()
def client(fresh_runtime_and_registry):
    # Import app after fixture runs so module-level _runtime is fresh
    from shield.api.app import app
    return TestClient(app)


# ============================================================================
# A. GET /health → 200
# ============================================================================

def test_A_health(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


# ============================================================================
# B. POST /workflows → 201 + workflow_id
# ============================================================================

def test_B_create_workflow(client):
    r = client.post("/workflows", json={"task": "Research Fibonacci"})
    assert r.status_code == 201
    data = r.json()
    assert "workflow_id" in data
    assert data["workflow_id"].startswith("wf-")
    assert data["status"] == "CREATED"
    assert data["task"] == "Research Fibonacci"


# ============================================================================
# C. GET /workflows/{id} → CREATED
# ============================================================================

def test_C_get_workflow_created(client):
    r = client.post("/workflows", json={"task": "Test task"})
    wf_id = r.json()["workflow_id"]

    r2 = client.get(f"/workflows/{wf_id}")
    assert r2.status_code == 200
    assert r2.json()["status"] == "CREATED"
    assert r2.json()["workflow_id"] == wf_id


# ============================================================================
# D. POST /workflows/{id}/start → workflow executes → COMPLETED
# ============================================================================

def test_D_start_workflow_completes(client):
    r = client.post("/workflows", json={"task": "Fibonacci"})
    wf_id = r.json()["workflow_id"]

    r2 = client.post(f"/workflows/{wf_id}/start")
    assert r2.status_code == 200
    data = r2.json()
    assert data["status"] == "COMPLETED"
    assert len(data["steps_completed"]) > 0


# ============================================================================
# E. GET /workflows/{id}/events → correlated events
# ============================================================================

def test_E_workflow_events(client):
    r = client.post("/workflows", json={"task": "Fibonacci"})
    wf_id = r.json()["workflow_id"]
    client.post(f"/workflows/{wf_id}/start")

    r2 = client.get(f"/workflows/{wf_id}/events")
    assert r2.status_code == 200
    data = r2.json()
    assert data["workflow_id"] == wf_id
    assert len(data["events"]) > 0
    for evt in data["events"]:
        assert evt["workflow_id"] == wf_id


# ============================================================================
# F. POST /workflows/{id}/stop → correct lifecycle
# ============================================================================

def test_F_stop_created_workflow(client):
    r = client.post("/workflows", json={"task": "Stop test"})
    wf_id = r.json()["workflow_id"]

    r2 = client.post(f"/workflows/{wf_id}/stop")
    assert r2.status_code == 200
    assert r2.json()["status"] == "STOPPED"


def test_F_stop_completed_workflow_is_noop(client):
    r = client.post("/workflows", json={"task": "Stop noop"})
    wf_id = r.json()["workflow_id"]
    client.post(f"/workflows/{wf_id}/start")

    r2 = client.post(f"/workflows/{wf_id}/stop")
    assert r2.status_code == 200
    assert r2.json()["status"] == "COMPLETED"


# ============================================================================
# G. Unknown workflow → 404
# ============================================================================

def test_G_unknown_workflow_404(client):
    assert client.get("/workflows/wf-doesnotexist").status_code == 404
    assert client.post("/workflows/wf-doesnotexist/start").status_code == 404
    assert client.post("/workflows/wf-doesnotexist/stop").status_code == 404
    assert client.get("/workflows/wf-doesnotexist/events").status_code == 404


# ============================================================================
# H. GET /agents → all five agents
# ============================================================================

def test_H_list_agents(client):
    r = client.get("/agents")
    assert r.status_code == 200
    agents = r.json()
    assert len(agents) == 5
    ids = {a["agent_id"] for a in agents}
    assert ids == {
        "orchestrator-01", "research-01", "coding-01",
        "deployment-01", "verification-01",
    }


# ============================================================================
# I. GET /agents/research-01 → correct state
# ============================================================================

def test_I_get_research_agent(client):
    r = client.get("/agents/research-01")
    assert r.status_code == 200
    data = r.json()
    assert data["agent_id"] == "research-01"
    assert data["state"] == "ACTIVE"


# ============================================================================
# J. Isolate research-01 → QUARANTINED
# ============================================================================

def test_J_isolate_agent(client):
    r = client.post("/agents/research-01/isolate")
    assert r.status_code == 200
    assert r.json()["state"] == "QUARANTINED"


# ============================================================================
# K. GET agent confirms QUARANTINED
# ============================================================================

def test_K_get_confirms_quarantined(client):
    client.post("/agents/research-01/isolate")
    r = client.get("/agents/research-01")
    assert r.status_code == 200
    assert r.json()["state"] == "QUARANTINED"


# ============================================================================
# L. Real P1 protected research action after API quarantine → AGENT_QUARANTINED
# ============================================================================

def test_L_quarantine_blocks_real_tool(client):
    """
    Proves: HTTP API → QuarantineService → shared IdentityService →
    KavachGuard (module-level) → authorize() → DENY with AGENT_QUARANTINED.
    """
    client.post("/agents/research-01/isolate")

    # Now call the real protected ResearchTools.web_search via the module-level guard
    from agents.research.tools import ResearchTools
    from sandbox.runtime.message_bus import MessageBus

    tools = ResearchTools(MessageBus())
    with pytest.raises(KavachDeniedError) as exc_info:
        tools.web_search("test query")

    assert exc_info.value.result is not None
    reason_values = [rc.value for rc in exc_info.value.result.reason_codes]
    assert "AGENT_QUARANTINED" in reason_values


# ============================================================================
# M. Restore research-01 → ACTIVE
# ============================================================================

def test_M_restore_agent(client):
    client.post("/agents/research-01/isolate")
    r = client.post("/agents/research-01/restore")
    assert r.status_code == 200
    assert r.json()["state"] == "ACTIVE"


# ============================================================================
# N. Real research protected action after restore → ALLOW
# ============================================================================

def test_N_restore_allows_real_tool(client):
    client.post("/agents/research-01/isolate")
    client.post("/agents/research-01/restore")

    from agents.research.tools import ResearchTools
    from sandbox.runtime.message_bus import MessageBus

    tools = ResearchTools(MessageBus())
    result = tools.web_search("fibonacci")
    assert result["query"] == "fibonacci"


# ============================================================================
# O. Other agents remain functional while research is quarantined
# ============================================================================

def test_O_other_agents_unaffected(client):
    client.post("/agents/research-01/isolate")

    from agents.coding.tools import CodingTools
    from sandbox.runtime.message_bus import MessageBus

    tools = CodingTools(MessageBus())
    # coding.read should still work
    result = tools.run_tests()
    assert result["status"] == "PASSED"


# ============================================================================
# P. GET /incidents
# ============================================================================

def test_P_list_incidents(client):
    r = client.get("/incidents")
    assert r.status_code == 200
    assert isinstance(r.json(), list)


# ============================================================================
# Q. GET /events
# ============================================================================

def test_Q_list_events(client):
    r = client.get("/events")
    assert r.status_code == 200
    assert isinstance(r.json(), list)


# ============================================================================
# R. GET /dashboard
# ============================================================================

def test_R_dashboard(client):
    r = client.get("/dashboard")
    assert r.status_code == 200
    data = r.json()
    assert "agents" in data
    assert "workflows" in data
    assert "incidents" in data
    assert "events" in data
    assert data["agents"].get("ACTIVE", 0) == 5


# ============================================================================
# S. GET /policies
# ============================================================================

def test_S_get_policies(client):
    r = client.get("/policies")
    assert r.status_code == 200
    data = r.json()
    assert "cedar_policies" in data
    assert "action_capability_map" in data
    assert "Read-only" in data.get("note", "")


# ============================================================================
# T. POST /policies must NOT mutate Cedar policies
# ============================================================================

def test_T_post_policies_not_implemented(client):
    """
    POST /policies is not implemented in Python — returns 405.
    The Node proxy still exposes this route but it will 405 from Python.
    This is documented for hardening in Phase 21E.
    """
    r = client.post("/policies", json={"cedar_policies": "permit(principal, action, resource);"})
    # Must not be 200/201 — either 405 Method Not Allowed or 404
    assert r.status_code in (404, 405, 422)


# ============================================================================
# Shared-runtime invariant: workflow started via HTTP uses real KavachGuard
# ============================================================================

def test_workflow_via_http_uses_real_enforcement(client):
    """
    Proves: POST /workflows + POST /workflows/{id}/start goes through
    the real KavachGuard enforcement path, not a bypass.
    """
    # Quarantine research via API
    client.post("/agents/research-01/isolate")

    # Create and start a workflow — it will fail at research.search
    r = client.post("/workflows", json={"task": "Fibonacci"})
    wf_id = r.json()["workflow_id"]

    r2 = client.post(f"/workflows/{wf_id}/start")
    assert r2.status_code == 200
    data = r2.json()
    # Workflow must FAIL because research is quarantined
    assert data["status"] == "FAILED"
    assert data["error"] is not None
    # The error must mention the denial
    assert "AGENT_QUARANTINED" in data["error"] or "denied" in data["error"].lower() or "Kavach" in data["error"]


def test_unknown_agent_404(client):
    assert client.get("/agents/unknown-agent-99").status_code == 404
    assert client.post("/agents/unknown-agent-99/isolate").status_code == 404
    assert client.post("/agents/unknown-agent-99/restore").status_code == 404


def test_start_already_running_workflow_409(client):
    r = client.post("/workflows", json={"task": "409 test"})
    wf_id = r.json()["workflow_id"]
    client.post(f"/workflows/{wf_id}/start")
    # Try to start again — must be 409
    r2 = client.post(f"/workflows/{wf_id}/start")
    assert r2.status_code == 409
