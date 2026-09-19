/**
 * Thin HTTP client for the Kavach backend.
 *
 * Errors are classified so the UI can distinguish a rate limit from an outage:
 *
 *   kind === "offline"      network failure / backend unreachable
 *   kind === "unauthorized" 401 | 403
 *   kind === "rate_limited" 429
 *   kind === "not_found"    404
 *   kind === "server"       5xx
 *   kind === "client"       other 4xx
 *
 * The classification is what lets the shell avoid claiming "backend offline"
 * just because one poll was throttled.
 */

export class ApiError extends Error {
  constructor(kind, status, message) {
    super(message);
    this.name = "ApiError";
    this.kind = kind;
    this.status = status;
  }
}

function classify(status) {
  if (status === 401 || status === 403) return "unauthorized";
  if (status === 429) return "rate_limited";
  if (status === 404) return "not_found";
  if (status >= 500) return "server";
  return "client";
}

async function request(path, options = {}) {
  const init = {
    ...options,
    headers: {
      "Content-Type": "application/json",
      "x-api-key": import.meta.env.VITE_API_KEY || "local-dev-key",
      ...options.headers,
    },
  };

  let res;
  try {
    res = await fetch(`/api${path}`, init);
  } catch (err) {
    throw new ApiError("offline", 0, "Backend unreachable");
  }

  if (!res.ok) {
    const kind = classify(res.status);
    throw new ApiError(kind, res.status, `${res.status} ${res.statusText}`);
  }

  if (res.status === 204) return null;
  return res.json();
}

export const api = {
  // ── Health ────────────────────────────────────────────────────────────────
  getHealth: () => request("/health"),

  // ── Demo session ──────────────────────────────────────────────────────────
  // Release every agent, forget the current session's telemetry and workflows.
  // The permanent audit log is untouched.
  resetDemoSession: () => request("/workflows/demo/reset", { method: "POST", body: JSON.stringify({}) }),

  // ── Workflows ─────────────────────────────────────────────────────────────
  // Create a workflow and return { workflow_id, status: "CREATED" }.
  createWorkflow: (task) =>
    request("/workflows", { method: "POST", body: JSON.stringify({ task }) }),

  // Start execution. Returns IMMEDIATELY with status RUNNING; the backend runs
  // the phases on a worker thread. Poll getWorkflow() for progress.
  startWorkflow: (id) =>
    request(`/workflows/${id}/start`, { method: "POST", body: JSON.stringify({}) }),

  stopWorkflow: (id) =>
    request(`/workflows/${id}/stop`, { method: "POST", body: JSON.stringify({}) }),

  // The single source of truth while a workflow is live:
  // { workflow_id, status, task, events[], agents[], phases[], result, ... }
  getWorkflow: (id) => request(`/workflows/${id}`),

  // Supervisor lifecycle events (created/started/phases/completed).
  getWorkflowEvents: (id) => request(`/workflows/${id}/events`),

  // ── Attack simulation ─────────────────────────────────────────────────────
  // Real KavachGuard denial + real quarantine + one real post-quarantine
  // denial. Returns both authorization events.
  simulateAttack: () =>
    request("/workflows/simulation/attack", { method: "POST", body: JSON.stringify({}) }),

  // ── Agents (not polled by the demo; available for direct inspection) ──────
  getAgents: () => request("/agents"),
  getAgent: (id) => request(`/agents/${id}`),
  isolateAgent: (id) => request(`/agents/${id}/isolate`, { method: "POST" }),
  restoreAgent: (id) => request(`/agents/${id}/restore`, { method: "POST" }),

  // ── Policies / incidents (read-only) ──────────────────────────────────────
  getPolicies: () => request("/policies"),
  getIncidents: () => request("/incidents"),
  getIncident: (id) => request(`/incidents/${id}`),

  // ── Scanner ───────────────────────────────────────────────────────────────
  scanArtifact: (body) => request("/artifacts/scan", { method: "POST", body: JSON.stringify(body) }),
  getArtifact: (id) => request(`/artifacts/${id}`),
};
