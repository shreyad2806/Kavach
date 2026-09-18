const API_KEY = import.meta.env.VITE_API_KEY ?? "";

async function request(path, options = {}) {
  const res = await fetch(`/api${path}`, {
    ...options,
    headers: { "Content-Type": "application/json", "x-api-key": API_KEY, ...options.headers },
  });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json();
}

export const api = {
  getDashboard: () => request("/dashboard"),
  getAgents: () => request("/agents"),
  isolateAgent: (id) => request(`/agents/${id}/isolate`, { method: "POST" }),
  restoreAgent: (id) => request(`/agents/${id}/restore`, { method: "POST" }),
  getEvents: () => request("/events"),
  getIncidents: () => request("/incidents"),
  getPolicies: () => request("/policies"),
  scanArtifact: (body) => request("/artifacts/scan", { method: "POST", body: JSON.stringify(body) }),
  getArtifact: (id) => request(`/artifacts/${id}`),
};
