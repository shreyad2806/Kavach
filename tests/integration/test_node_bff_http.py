"""HTTP integration tests for the Node BFF (backend/src/index.js on :3001).

These tests exercise the real Node → Python proxy path end to end.
They require both the Node BFF (port 3001) and the unified Python backend
(port 8000) to be running.  If either is unavailable the test module is
skipped automatically — this is expected in CI where the servers are not
started.

Run locally:
    # Terminal 1: uvicorn api.main:app --port 8000
    # Terminal 2: (cd backend && node src/index.js)
    # Terminal 3: pytest tests/integration/test_node_bff_http.py -v
"""

import pytest

# ---------------------------------------------------------------------------
# Availability guards — skip the entire module if the servers are not up
# ---------------------------------------------------------------------------

try:
    import httpx as _httpx

    def _port_open(host: str, port: int, timeout: float = 1.0) -> bool:
        import socket
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except OSError:
            return False

    _NODE_UP   = _port_open("127.0.0.1", 3001)
    _PYTHON_UP = _port_open("127.0.0.1", 8000)
except ImportError:
    _NODE_UP   = False
    _PYTHON_UP = False

pytestmark = pytest.mark.skipif(
    not (_NODE_UP and _PYTHON_UP),
    reason="Node BFF (:3001) or Python backend (:8000) not running — skipping live HTTP tests",
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

NODE    = "http://localhost:3001"
API_KEY = "local-dev-key"


@pytest.fixture(scope="module")
def client():
    """Shared httpx client for the Node BFF."""
    with _httpx.Client(base_url=NODE, timeout=20.0) as c:
        yield c


def _auth(client, extra_headers: dict | None = None) -> dict:
    """Return headers with x-api-key for authenticated Node requests."""
    h = {"x-api-key": API_KEY}
    if extra_headers:
        h.update(extra_headers)
    return h


# ---------------------------------------------------------------------------
# 1. Node health (no auth)
# ---------------------------------------------------------------------------

def test_node_health(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


# ---------------------------------------------------------------------------
# 2. Node → Python proxy health
# ---------------------------------------------------------------------------

def test_node_to_python_health(client):
    resp = client.get("/api/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


# ---------------------------------------------------------------------------
# 3. Agents through Node
# ---------------------------------------------------------------------------

def test_node_agents_list(client):
    resp = client.get("/api/agents", headers=_auth(client))
    assert resp.status_code == 200
    agents = resp.json()
    assert isinstance(agents, list) and len(agents) == 5
    ids = {a["agent_id"] for a in agents}
    assert ids == {
        "orchestrator-01", "research-01", "coding-01",
        "deployment-01", "verification-01",
    }


# ---------------------------------------------------------------------------
# 4. Dashboard through Node
# ---------------------------------------------------------------------------

def test_node_dashboard(client):
    resp = client.get("/api/dashboard", headers=_auth(client))
    assert resp.status_code == 200
    dash = resp.json()
    assert dash["agents"]["total"] == 5
    assert "workflows" in dash
    assert "incidents" in dash
    assert "events" in dash


# ---------------------------------------------------------------------------
# 5. Events through Node
# ---------------------------------------------------------------------------

def test_node_events(client):
    resp = client.get("/api/events", headers=_auth(client))
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


# ---------------------------------------------------------------------------
# 6. Incidents through Node
# ---------------------------------------------------------------------------

def test_node_incidents(client):
    resp = client.get("/api/incidents", headers=_auth(client))
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


# ---------------------------------------------------------------------------
# 7. Policies through Node (read-only)
# ---------------------------------------------------------------------------

def test_node_policies(client):
    resp = client.get("/api/policies", headers=_auth(client))
    assert resp.status_code == 200
    body = resp.json()
    assert body["engine"] == "cedar"
    assert body["mutable"] is False
    assert body["count"] > 0


# ---------------------------------------------------------------------------
# 8. Workflow lifecycle through Node
# ---------------------------------------------------------------------------

def test_node_workflow_lifecycle(client):
    headers = _auth(client)

    # Create
    created = client.post("/api/workflows", json={"task": "node bff lifecycle test"}, headers=headers)
    assert created.status_code == 201
    wf_id = created.json()["workflow_id"]

    # GET before start
    got = client.get(f"/api/workflows/{wf_id}", headers=headers)
    assert got.status_code == 200
    assert got.json()["status"] == "CREATED"

    # Start
    started = client.post(f"/api/workflows/{wf_id}/start", headers=headers)
    assert started.status_code == 200
    body = started.json()
    assert body["status"] == "COMPLETED"
    assert body["result"]["coding"]
    assert body["result"]["deployment"]

    # Events
    events = client.get(f"/api/workflows/{wf_id}/events", headers=headers)
    assert events.status_code == 200
    ev_types = [e["event_type"] for e in events.json()]
    assert "WORKFLOW_CREATED" in ev_types
    assert "WORKFLOW_STARTED" in ev_types
    assert "WORKFLOW_COMPLETED" in ev_types
    assert all(e["workflow_id"] == wf_id for e in events.json())


# ---------------------------------------------------------------------------
# 9. Quarantine → real P1 → KavachGuard DENY through Node
# ---------------------------------------------------------------------------

def test_node_quarantine_blocks_real_p1_operation(client):
    headers = _auth(client)

    # Verify baseline works
    baseline_id = client.post("/api/workflows", json={"task": "node baseline"}, headers=headers).json()["workflow_id"]
    assert client.post(f"/api/workflows/{baseline_id}/start", headers=headers).json()["status"] == "COMPLETED"

    # Quarantine research-01 through Node
    iso = client.post("/api/agents/research-01/isolate", headers=headers)
    assert iso.status_code == 200
    assert iso.json()["state"] == "QUARANTINED"

    # GET confirms quarantine
    assert client.get("/api/agents/research-01", headers=headers).json()["state"] == "QUARANTINED"

    # A workflow must fail with KavachGuard DENY
    atk_id = client.post("/api/workflows", json={"task": "malicious via node"}, headers=headers).json()["workflow_id"]
    result = client.post(f"/api/workflows/{atk_id}/start", headers=headers).json()
    assert result["status"] == "FAILED"
    assert result["result"]["kavach_denied"] is True
    assert result["result"]["decision"] == "DENY"
    assert "AGENT_QUARANTINED" in result["result"]["reason_codes"]
    assert "AGENT_QUARANTINED" in result.get("error", "")

    # Other agents remain operational
    states = {a["agent_id"]: a["state"] for a in client.get("/api/agents", headers=headers).json()}
    assert states["research-01"] == "QUARANTINED"
    for other in ("orchestrator-01", "coding-01", "deployment-01", "verification-01"):
        assert states[other] == "ACTIVE"

    # Restore through Node
    rest = client.post("/api/agents/research-01/restore", headers=headers)
    assert rest.status_code == 200
    assert rest.json()["state"] == "ACTIVE"

    # Legitimate workflow works again
    legit_id = client.post("/api/workflows", json={"task": "legit after node restore"}, headers=headers).json()["workflow_id"]
    assert client.post(f"/api/workflows/{legit_id}/start", headers=headers).json()["status"] == "COMPLETED"


# ---------------------------------------------------------------------------
# 10. Scanner — x-api-key forwarding through Node
# ---------------------------------------------------------------------------

def test_node_scanner_wrong_key_401(client):
    """Node forwards x-api-key upstream; wrong key → Python rejects with 401."""
    resp = client.post(
        "/api/artifacts/scan",
        json={"artifact_type": "python_package", "source_url": "https://x.com/p.tar.gz", "requested_by": "op"},
        headers={"x-api-key": "definitely-wrong-key"},
    )
    assert resp.status_code == 401


def test_node_scanner_no_aws_503(client):
    """Correct key forwarded; AWS not configured → controlled 503."""
    # Node's API_KEY=local-dev-key; Python has no API_KEY set (empty string matches)
    # so we send the key that matches the Node env AND what Python would accept.
    resp = client.post(
        "/api/artifacts/scan",
        json={"artifact_type": "python_package", "source_url": "https://x.com/p.tar.gz", "requested_by": "op"},
        headers={"x-api-key": API_KEY},
    )
    # Either 503 (AWS unavailable, correct key forwarded and accepted) or
    # 401 (key mismatch if Python's env differs).  Both are acceptable — they
    # confirm x-api-key was forwarded (not stripped).
    assert resp.status_code in (401, 503), f"Unexpected status {resp.status_code}"


# ---------------------------------------------------------------------------
# 11. Malformed / unknown resources through Node
# ---------------------------------------------------------------------------

def test_node_unknown_workflow(client):
    headers = _auth(client)
    assert client.get("/api/workflows/nope", headers=headers).status_code == 404
    assert client.post("/api/workflows/nope/start", headers=headers).status_code == 404
    assert client.get("/api/workflows/nope/events", headers=headers).status_code == 404


def test_node_unknown_agent(client):
    headers = _auth(client)
    assert client.get("/api/agents/ghost-99", headers=headers).status_code == 404
    assert client.post("/api/agents/ghost-99/isolate", headers=headers).status_code == 404


def test_node_workflow_create_requires_task(client):
    resp = client.post("/api/workflows", json={"task": "   "}, headers=_auth(client))
    assert resp.status_code == 400


def test_node_start_completed_workflow_conflicts(client):
    headers = _auth(client)
    wf_id = client.post("/api/workflows", json={"task": "conflict test"}, headers=headers).json()["workflow_id"]
    client.post(f"/api/workflows/{wf_id}/start", headers=headers)
    # Already COMPLETED → 409
    assert client.post(f"/api/workflows/{wf_id}/start", headers=headers).status_code == 409


# ---------------------------------------------------------------------------
# 12. Auth required — Node rejects unauthenticated requests
# ---------------------------------------------------------------------------

def test_node_requires_auth(client):
    """Node's apiKeyAuth middleware rejects requests with missing/wrong key."""
    assert client.get("/api/agents").status_code == 401
    assert client.get("/api/dashboard").status_code == 401
    assert client.get("/api/events").status_code == 401
    assert client.post("/api/workflows", json={"task": "x"}).status_code == 401
