import { useState, useMemo } from "react";
import { Maximize2, Filter, RotateCcw } from "lucide-react";
import { Panel } from "../ui/Panel.jsx";
import { Button } from "../ui/Button.jsx";
import { Chip, Badge } from "../ui/index.jsx";
import { decisionTone, relativeTime } from "../lib/format.js";

// Decision sequence — one bar per REAL authorization decision from this run,
// oldest on the left, newest on the right. Nothing is bucketed, smoothed or
// synthesised: a bar exists only because a decision exists.
function DecisionStrip({ events }) {
  const seq = useMemo(() => [...events].reverse().slice(-40), [events]);

  if (seq.length === 0) {
    return (
      <div className="h-[52px] flex items-center">
        <span className="text-[11.5px] text-ink3">No authorization decisions yet.</span>
      </div>
    );
  }

  return (
    <div
      className="flex items-stretch gap-[3px] h-[52px]"
      role="img"
      aria-label={`${seq.length} authorization decisions in this run`}
    >
      {seq.map((e, i) => (
        <span
          key={e.event_id || e.request_id || i}
          className="flex-1 min-w-[4px] rounded-sm"
          style={{
            background: e.policy_decision === "ALLOW" ? "#1fe98a" : "#ff4d5e",
            opacity: 0.8,
          }}
          title={`${e.source_agent} ${e.action} → ${e.policy_decision}`}
        />
      ))}
    </div>
  );
}

const REASON_CODE_COLORS = {
  POLICY_DENIED:        "#1fe98a",
  DETERMINISTIC_RULES:  "#a7c9ba",
  PROVENANCE_ANOMALY:   "#ffc046",
};

export function AgentActivityPanel({
  events = [],
  onEventSelect,
  selectedRequestId,
  quarantinedCount = 0,
  onReviewQuarantine,
}) {
  const [denialsOnly, setDenialsOnly] = useState(false);
  const [query, setQuery] = useState("");
  const [chips, setChips] = useState([]);

  const filtered = useMemo(() => {
    let list = events;
    if (denialsOnly) list = list.filter((e) => e.policy_decision === "DENY");
    if (query) {
      const q = query.toLowerCase();
      list = list.filter(
        (e) =>
          e.source_agent?.toLowerCase().includes(q) ||
          e.action?.toLowerCase().includes(q) ||
          e.resource?.toLowerCase().includes(q) ||
          e.reason_codes?.some((r) => r.toLowerCase().includes(q))
      );
    }
    return list.slice(0, 40);
  }, [events, denialsOnly, query]);

  const allowCount = events.filter((e) => e.policy_decision === "ALLOW").length;
  const denyCount  = events.filter((e) => e.policy_decision === "DENY").length;

  // Decision engine breakdown
  const cedarDeny   = events.filter((e) => e.reason_codes?.includes("POLICY_DENIED")).length;
  const rulesDeny   = events.filter((e) => e.reason_codes?.includes("PRIVILEGE_ESCALATION") || e.reason_codes?.includes("CAPABILITY_MISMATCH")).length;
  const provDeny    = events.filter((e) => e.reason_codes?.includes("PROVENANCE_ANOMALY")).length;

  return (
    <Panel className="p-4 flex flex-col gap-3 h-full">
      {/* Title row */}
      <div className="flex items-center justify-between gap-2 flex-wrap">
        <div className="text-[14px] font-bold text-ink">Agent activity</div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setDenialsOnly((v) => !v)}
            aria-pressed={denialsOnly}
            className={`flex items-center gap-1.5 rounded-btn px-2.5 py-1 text-[11.5px] font-semibold border transition-colors ${
              denialsOnly
                ? "bg-danger/10 text-danger border-danger/30"
                : "bg-transparent text-ink3 border-line hover:border-line2"
            }`}
          >
            Denials only
          </button>
          <button aria-label="Expand activity panel" className="w-7 h-7 rounded-btn flex items-center justify-center text-ink3 hover:text-ink hover:bg-line transition-colors">
            <Maximize2 size={13} />
          </button>
          <button
            aria-label="Reset filters"
            onClick={() => { setQuery(""); setChips([]); setDenialsOnly(false); }}
            className="w-7 h-7 rounded-btn flex items-center justify-center text-ink3 hover:text-ink hover:bg-line transition-colors"
          >
            <RotateCcw size={13} />
          </button>
          <button aria-label="Open filters" className="w-7 h-7 rounded-btn flex items-center justify-center text-ink3 hover:text-ink hover:bg-line transition-colors">
            <Filter size={13} />
          </button>
        </div>
      </div>

      {/* Search + chips */}
      <div className="flex items-center gap-2 flex-wrap">
        <input
          type="search"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Search agent, action, resource…"
          aria-label="Search activity"
          className="flex-1 min-w-[160px] bg-panel2 border border-line rounded-full px-3 py-1.5 text-[12px] text-ink placeholder:text-ink3 outline-none focus:border-line2"
        />
        {chips.map((c) => (
          <Chip key={c} label={c} onRemove={() => setChips((prev) => prev.filter((x) => x !== c))} />
        ))}
      </div>

      {/* Two-column mini-grid */}
      <div className="grid grid-cols-2 gap-3">
        {/* Decisions bar chart */}
        <div className="bg-panel2 border border-line rounded-tile p-3">
          <div className="text-[12px] font-semibold text-ink2 mb-2">Decision sequence</div>
          <DecisionStrip events={events} />
          <div className="text-[11px] text-ink3 mt-2 font-mono">
            <span className="text-neon">{allowCount} allowed</span>
            {" · "}
            <span className="text-danger">{denyCount} denied</span>
          </div>
        </div>

        {/* Decision engine breakdown */}
        <div className="bg-panel2 border border-line rounded-tile p-3">
          <div className="text-[12px] font-semibold text-ink2 mb-2">Decision engine</div>
          <div className="flex flex-col gap-2">
            {[
              { label: "Cedar policy",        count: cedarDeny,  color: "#1fe98a" },
              { label: "Deterministic rules",  count: rulesDeny,  color: "#a7c9ba" },
              { label: "Provenance",           count: provDeny,   color: "#ffc046" },
            ].map(({ label, count, color }) => (
              <div key={label} className="flex items-center justify-between gap-2">
                <div className="flex items-center gap-2">
                  <span className="w-2.5 h-2.5 rounded-sm flex-shrink-0" style={{ background: color }} aria-hidden="true" />
                  <span className="text-[11.5px] text-ink3">{label}</span>
                </div>
                <span className="text-[12px] font-mono font-semibold text-ink2">{count}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Quarantine callout */}
      {quarantinedCount > 0 && (
        <div className="flex items-center justify-between gap-3 rounded-tile bg-danger/10 border border-danger/20 px-3 py-2.5">
          <div>
            <div className="text-[12.5px] font-semibold text-danger">
              {quarantinedCount} agent{quarantinedCount !== 1 ? "s" : ""} in quarantine
            </div>
            <div className="text-[11.5px] text-ink3">Pending operator review</div>
          </div>
          <Button tone="danger" size="sm" onClick={onReviewQuarantine}>
            Review
          </Button>
        </div>
      )}

      {/* Event table */}
      <div className="flex-1 overflow-auto">
        {filtered.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-8 gap-2">
            <p className="text-[13px] text-ink3">No authorization events yet.</p>
            <p className="text-[11.5px] text-ink3">
              Decisions appear here as the workflow executes.
            </p>
          </div>
        ) : (
          <table className="w-full text-[12px]" role="table">
            <thead>
              <tr className="border-b border-line">
                <th className="text-left py-2 pr-3 text-[11px] font-semibold text-ink3 w-[90px]">Time</th>
                <th className="text-left py-2 pr-3 text-[11px] font-semibold text-ink3">Agent</th>
                <th className="text-left py-2 pr-3 text-[11px] font-semibold text-ink3">Action</th>
                <th className="text-left py-2 pr-3 text-[11px] font-semibold text-ink3">Resource</th>
                <th className="text-right py-2 text-[11px] font-semibold text-ink3">Decision</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((e, i) => {
                // Selection is by request_id — the same identity the
                // authorization pipeline renders against.
                const isSelected = e.request_id === selectedRequestId;
                return (
                  <tr
                    key={e.event_id || i}
                    onClick={() => onEventSelect?.(e)}
                    className={`border-b border-line cursor-pointer transition-colors ${
                      isSelected ? "bg-neon/5" : "hover:bg-line/50"
                    }`}
                    role="row"
                    tabIndex={0}
                    onKeyDown={(ev) => ev.key === "Enter" && onEventSelect?.(e)}
                    aria-selected={isSelected}
                  >
                    <td className="py-2 pr-3 font-mono text-ink3 whitespace-nowrap">
                      {relativeTime(e.timestamp)}
                    </td>
                    <td className="py-2 pr-3 font-mono text-ink2 whitespace-nowrap">
                      {e.source_agent}
                    </td>
                    <td className="py-2 pr-3 text-ink2 whitespace-nowrap">{e.action}</td>
                    <td className="py-2 pr-3 text-ink3 whitespace-nowrap">{e.resource}</td>
                    <td className="py-2 text-right">
                      <Badge
                        label={e.policy_decision}
                        tone={decisionTone(e.policy_decision)}
                      />
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>
    </Panel>
  );
}
