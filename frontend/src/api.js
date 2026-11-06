/**
 * HTTP client for Kavach's API.
 * Vercel uses its same-origin serverless BFF (/api/*); AWS builds set
 * VITE_API_BASE_URL to the AWS BFF origin. Never put secrets in VITE_*.
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

const apiBase = (import.meta.env.VITE_API_BASE_URL || "").replace(/\\/$/, "");

async function request(path, options = {}) {
  const init = {
    ...options,
    headers: { "Content-Type": "application/json", ...options.headers },
  };
  let res;
  try {
    res = await fetch(apiBase + "/api" + path, init);
  } catch {
    throw new ApiError("offline", 0, "Backend unreachable");
  }
  if (!res.ok) throw new ApiError(classify(res.status), res.status, res.status + " " + res.statusText);
  if (res.status === 204) return null;
  return res.json();
}

export const api = {
  getHealth: () => request("/health"),
  resetDemoSession: () => request("/workflows/demo/reset", { method: "POST", body: JSON.stringify({}) }),
  createWorkflow: (task) => request("/workflows", { method: "POST", body: JSON.stringify({ task }) }),
  startWorkflow: (id) => request("/workflows/" + id + "/start", { method: "POST", body: JSON.stringify({}) }),
  stopWorkflow: (id) => request("/workflows/" + id + "/stop", { method: "POST", body: JSON.stringify({}) }),
  getWorkflow: (id) => request("/workflows/" + id),
  getWorkflowEvents: (id) => request("/workflows/" + id + "/events"),
  simulateAttack: () => request("/workflows/simulation/attack", { method: "POST", body: JSON.stringify({}) }),
  getAgents: () => request("/agents"),
  getAgent: (id) => request("/agents/" + id),
  isolateAgent: (id) => request("/agents/" + id + "/isolate", { method: "POST" }),
  restoreAgent: (id) => request("/agents/" + id + "/restore", { method: "POST" }),
  getEvents: (limit = 100) => request("/events?limit=" + limit),
  getPolicies: () => request("/policies"),
  getIncidents: () => request("/incidents"),
  getIncident: (id) => request("/incidents/" + id),
  scanArtifact: (body) => request("/artifacts/scan", { method: "POST", body: JSON.stringify(body) }),
  getArtifact: (id) => request("/artifacts/" + id),
};
