import { ExternalLink } from "lucide-react";
import { Panel } from "../ui/Panel.jsx";
import { Button } from "../ui/Button.jsx";
import { Badge } from "../ui/index.jsx";
import { stateTone } from "../lib/format.js";

const AGENT_CAPABILITIES = {
  "orchestrator-01": "orchestrator.delegate · orchestrator.coordinate",
  "research-01":     "research.search · research.read",
  "coding-01":       "coding.read · coding.write · coding.test",
  "deployment-01":   "deployment.preview · deployment.production",
  "verification-01": "verification.test",
};

const AGENT_ROLES = {
  "orchestrator-01": "Coordinator",
  "research-01":     "Researcher",
  "coding-01":       "Developer",
  "deployment-01":   "Deployer",
  "verification-01": "Verifier",
};

export function AgentControlCard({
  agents = [],
  selectedId,
  onSelect,
  onIsolate,
  onRestore,
  deniedToday = 0,
  systemLocked = false,
}) {
  const agent = agents.find((a) => a.agent_id === selectedId) || agents[0];

  return (
    <Panel className="p-4 flex flex-col gap-3 h-full">
      {/* Header */}
      <div className="flex items-center gap-2">
        <span
          className="w-2 h-2 rounded-full bg-neon pulse flex-shrink-0"
          aria-hidden="true"
        />
        <span className="text-[11px] font-bold uppercase tracking-widest text-ink2">
          Agent control
        </span>
      </div>

      {/* Dropdown */}
      <div className="relative">
        <select
          value={selectedId}
          onChange={(e) => onSelect(e.target.value)}
          aria-label="Select agent"
          className="w-full appearance-none bg-panel2 border border-line rounded-tile px-3 py-2 text-[12.5px] text-ink font-mono outline-none cursor-pointer hover:border-line2 transition-colors"
        >
          {agents.map((a) => (
            <option key={a.agent_id} value={a.agent_id}>
              {a.agent_id}
            </option>
          ))}
        </select>
        <span className="pointer-events-none absolute right-3 top-1/2 -translate-y-1/2 text-ink3 text-[10px]">
          ▾
        </span>
      </div>

      {agent && (
        <>
          {/* Role + capability scope */}
          <div>
            <div className="text-[12px] text-ink3 mb-0.5">
              {AGENT_ROLES[agent.agent_id] || agent.role}
            </div>
            <div className="text-[11px] text-ink3 font-mono leading-relaxed">
              {AGENT_CAPABILITIES[agent.agent_id] || "—"}
            </div>
          </div>

          {/* Session ID + state badge */}
          <div className="flex items-center justify-between gap-2">
            <span className="text-[11px] font-mono text-ink3 truncate">
              {agent.agent_id}
            </span>
            <Badge label={agent.state} tone={stateTone(agent.state)} />
          </div>

          {/* Isolate / Restore */}
          <div className="flex gap-2">
            <Button
              tone={agent.state === "QUARANTINED" ? "outline" : "danger"}
              size="sm"
              disabled={agent.state === "QUARANTINED"}
              onClick={() => onIsolate(agent.agent_id)}
              className="flex-1"
            >
              Isolate
            </Button>
            <Button
              tone={agent.state === "ACTIVE" ? "outline" : "neon"}
              size="sm"
              disabled={agent.state === "ACTIVE" || systemLocked}
              onClick={() => onRestore(agent.agent_id)}
              title={systemLocked ? "System lock is enabled — restore is blocked" : undefined}
              className="flex-1"
            >
              Restore
            </Button>
          </div>
        </>
      )}

      {/* Footer */}
      <div className="mt-auto pt-3 border-t border-line flex items-center justify-between">
        <div>
          <div className="text-[11.5px] text-ink3">Denied calls today</div>
          <div className="text-[26px] font-mono font-semibold text-danger leading-tight">
            {deniedToday}
          </div>
        </div>
        <button className="flex items-center gap-1 text-[11.5px] text-ink3 hover:text-neon transition-colors">
          Edit scope <ExternalLink size={11} />
        </button>
      </div>
    </Panel>
  );
}
