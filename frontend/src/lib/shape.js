export function asArrayOfOne(value) {
  if (Array.isArray(value)) return value;
  return value == null ? [] : [value];
}

function normalizeAgent(value) {
  if (!value || typeof value !== "object") return null;
  const agentId = value.agent_id ?? value.id;
  if (!agentId) return null;
  return {
    agent_id: String(agentId),
    role: value.role == null ? "" : String(value.role),
    state: value.state == null ? "UNKNOWN" : String(value.state),
    risk_score: Number.isFinite(value.risk_score) ? value.risk_score : null,
  };
}

export function normalizeAgents(value) {
  const source = Array.isArray(value)
    ? value
    : Array.isArray(value?.agents)
      ? value.agents
      : [];
  return source.map(normalizeAgent).filter(Boolean);
}

function normalizeEvent(value) {
  if (!value || typeof value !== "object" || !value.request_id) return null;
  return {
    ...value,
    request_id: String(value.request_id),
    event_id: value.event_id == null ? String(value.request_id) : String(value.event_id),
    timestamp: value.timestamp ?? new Date(0).toISOString(),
    source_agent: String(value.source_agent ?? "unknown"),
    target_agent: String(value.target_agent ?? "unknown"),
    action: String(value.action ?? "unknown"),
    resource: String(value.resource ?? "unknown"),
    policy_decision: String(value.policy_decision ?? "UNKNOWN"),
    reason_codes: Array.isArray(value.reason_codes) ? value.reason_codes.map(String) : [],
    checks: value.checks && typeof value.checks === "object" ? value.checks : {},
    risk_score: Number.isFinite(value.risk_score) ? value.risk_score : null,
  };
}

export function normalizeEvents(value) {
  const source = Array.isArray(value)
    ? value
    : Array.isArray(value?.events)
      ? value.events
      : Array.isArray(value?.snapshot?.events)
        ? value.snapshot.events
        : [];
  return source.map(normalizeEvent).filter(Boolean);
}
