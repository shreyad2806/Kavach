import { Panel } from "../ui/Panel.jsx";
import { Badge } from "../ui/index.jsx";
import { stateTone, riskColor } from "../lib/format.js";

// The identity registry is the source of truth for IDs and states; roles are
// presentational labels only.
const AGENT_ROLES = {
  "orchestrator-01": "coordinator",
  "research-01":     "researcher",
  "coding-01":       "developer",
  "deployment-01":   "deployer",
  "verification-01": "verifier",
};

const STATE_DOT = {
  ACTIVE:      { color: "#1fe98a", pulse: true },
  QUARANTINED: { color: "#ff4d5e", pulse: true },
  SUSPICIOUS:  { color: "#ffc046", pulse: false },
  TERMINATED:  { color: "#4a6b5d", pulse: false },
};

export function FleetList({ agents = [], selectedId, onSelect }) {
  return (
    <Panel className="p-4 flex flex-col gap-3 h-full">
      <div className="text-[14px] font-bold text-ink">Fleet</div>

      {agents.length === 0 ? (
        <div className="flex-1 flex items-center justify-center">
          <p className="text-[12.5px] text-ink3">Loading fleet…</p>
        </div>
      ) : (
        <div className="flex flex-col gap-1">
          {agents.map((agent) => {
            const dot = STATE_DOT[agent.state] || STATE_DOT.TERMINATED;
            const isSelected = agent.agent_id === selectedId;

            return (
              <button
                key={agent.agent_id}
                onClick={() => onSelect?.(agent.agent_id)}
                className={`w-full flex items-center gap-3 rounded-tile px-3 py-2.5 text-left transition-colors ${
                  isSelected ? "bg-neon/10 border border-neon/20" : "hover:bg-line border border-transparent"
                }`}
                aria-pressed={isSelected}
              >
                {/* Status dot */}
                <span
                  className={`w-2 h-2 rounded-full flex-shrink-0 ${dot.pulse ? "pulse" : ""}`}
                  style={{ background: dot.color, boxShadow: dot.pulse ? `0 0 6px ${dot.color}60` : "none" }}
                  aria-hidden="true"
                />

                {/* Agent ID + role */}
                <div className="flex-1 min-w-0">
                  <div className="text-[12.5px] font-mono text-ink truncate">{agent.agent_id}</div>
                  <div className="text-[11px] text-ink3 capitalize">
                    {agent.role ?? AGENT_ROLES[agent.agent_id] ?? "agent"}
                  </div>
                </div>

                {/* State badge */}
                <Badge label={agent.state} tone={stateTone(agent.state)} />

                {/* Risk score */}
                {agent.risk_score != null && (
                  <span
                    className="text-[12px] font-mono font-semibold w-8 text-right flex-shrink-0"
                    style={{ color: riskColor(agent.risk_score) }}
                    aria-label={`Risk score ${agent.risk_score}`}
                  >
                    {agent.risk_score}
                  </span>
                )}
              </button>
            );
          })}
        </div>
      )}
    </Panel>
  );
}
