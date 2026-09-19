async function request(path, options = {}) {
  const res = await fetch(`/api${path}`, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      "x-api-key": import.meta.env.VITE_API_KEY || "local-dev-key",
      ...options.headers,
    },
  });

  if (!res.ok) {
    throw new Error(`${res.status} ${res.statusText}`);
  }

  return res.json();
}

export const api = {
  // ── Health ────────────────────────────────────────────────────────────────
  getHealth: () => request("/health"),

  // ── Dashboard (summary projection) ───────────────────────────────────────
  getDashboard: () => request("/dashboard"),

  // ── Agents ───────────────────────────────────────────────────────────────
  getAgents:     ()         => request("/agents"),
  getAgent:      (id)       => request(`/agents/${id}`),
  isolateAgent:  (id)       => request(`/agents/${id}/isolate`,  { method: "POST" }),
  restoreAgent:  (id)       => request(`/agents/${id}/restore`,  { method: "POST" }),

  // ── Security events (Shield audit log) ───────────────────────────────────
  getEvents: (limit = 200) => request(`/events?limit=${limit}`),

  // ── Incidents ─────────────────────────────────────────────────────────────
  getIncidents: () => request("/incidents"),
  getIncident:  (id) => request(`/incidents/${id}`),

  // ── Policies (read-only) ──────────────────────────────────────────────────
  getPolicies: () => request("/policies"),

  // ── Workflows ─────────────────────────────────────────────────────────────
  // Create a workflow (POST /workflows) and return { workflow_id, status }
  createWorkflow:  (task)       => request("/workflows", { method: "POST", body: JSON.stringify({ task }) }),
  // Start execution — synchronous on the backend; may take several seconds
  startWorkflow:   (id)         => request(`/workflows/${id}/start`, { method: "POST", body: JSON.stringify({}) }),
  // Stop a running workflow
  stopWorkflow:    (id)         => request(`/workflows/${id}/stop`,  { method: "POST", body: JSON.stringify({}) }),
  // Get current workflow state
  getWorkflow:     (id)         => request(`/workflows/${id}`),
  // Get supervisor lifecycle events for a workflow
  getWorkflowEvents: (id)       => request(`/workflows/${id}/events`),

  // ── Scanner (not on main dashboard; kept for completeness) ────────────────
  scanArtifact: (body) => request("/artifacts/scan", { method: "POST", body: JSON.stringify(body) }),
  getArtifact:  (id)   => request(`/artifacts/${id}`),
};
