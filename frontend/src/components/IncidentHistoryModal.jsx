import { useEffect } from "react";
import { X } from "lucide-react";
import { Panel } from "../ui/Panel.jsx";
import { Badge } from "../ui/index.jsx";
import { relativeTime, decisionTone, severityTone } from "../lib/format.js";

export function IncidentHistoryModal({ incident, events = [], onClose }) {
  useEffect(() => {
    const handler = (e) => { if (e.key === "Escape") onClose(); };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [onClose]);

  if (!incident) return null;

  const agentEvents = events.filter((e) => e.source_agent === incident.agent_id);
  const accentColor = incident.severity === "CRITICAL" || incident.severity === "HIGH" ? "#ff4d5e" : "#ffc046";

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-4"
      style={{ background: "rgba(3,20,14,.85)", backdropFilter: "blur(6px)" }}
      onClick={onClose}
    >
      <Panel
        className="w-full max-w-2xl flex flex-col gap-4 p-5 max-h-[85vh]"
        style={{ borderColor: `${accentColor}30` }}
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-start justify-between gap-3">
          <div>
            <div className="flex items-center gap-2 mb-1">
              <span
                className="w-2 h-2 rounded-full pulse"
                style={{ background: accentColor }}
                aria-hidden="true"
              />
              <span className="text-[11px] font-bold uppercase tracking-widest" style={{ color: accentColor }}>
                {incident.severity} incident
              </span>
            </div>
            <div className="text-[14px] font-bold text-ink">
              {incident.reason_codes?.[0]?.replace(/_/g, " ") || "Security violation"}
            </div>
            <div className="text-[11.5px] font-mono text-ink3 mt-0.5">{incident.incident_id} · {incident.agent_id}</div>
          </div>
          <button
            onClick={onClose}
            aria-label="Close incident history"
            className="w-8 h-8 rounded-btn flex items-center justify-center text-ink3 hover:text-ink hover:bg-line transition-colors flex-shrink-0"
          >
            <X size={15} />
          </button>
        </div>

        {/* Incident details */}
        <div className="grid grid-cols-2 gap-3">
          <div className="bg-panel2 border border-line rounded-tile px-3 py-2.5">
            <div className="text-[11px] text-ink3 mb-1">Status</div>
            <Badge label={incident.status} tone={incident.status === "OPEN" ? "danger" : incident.status === "INVESTIGATING" ? "amber" : "dim"} />
          </div>
          <div className="bg-panel2 border border-line rounded-tile px-3 py-2.5">
            <div className="text-[11px] text-ink3 mb-1">Reported</div>
            <div className="text-[12.5px] font-mono text-ink2">{relativeTime(incident.timestamp)}</div>
          </div>
        </div>

        {/* Description */}
        {incident.description && (
          <div className="bg-panel2 border border-line rounded-tile px-3 py-2.5">
            <div className="text-[11px] text-ink3 mb-1.5">Description</div>
            <p className="text-[12.5px] text-ink2 leading-relaxed">{incident.description}</p>
          </div>
        )}

        {/* Reason codes */}
        {incident.reason_codes?.length > 0 && (
          <div>
            <div className="text-[11.5px] text-ink3 mb-2">Reason codes</div>
            <div className="flex flex-wrap gap-1.5">
              {incident.reason_codes.map((code) => (
                <span
                  key={code}
                  className="font-mono text-[11px] rounded-md px-2.5 py-1 border"
                  style={{ color: accentColor, background: `${accentColor}12`, borderColor: `${accentColor}25` }}
                >
                  {code}
                </span>
              ))}
            </div>
          </div>
        )}

        {/* Agent event history */}
        <div className="flex-1 overflow-auto">
          <div className="text-[12.5px] font-semibold text-ink2 mb-2">
            Events from {incident.agent_id}
            <span className="text-ink3 font-normal ml-1">({agentEvents.length} total)</span>
          </div>
          {agentEvents.length === 0 ? (
            <p className="text-[12px] text-ink3 py-4 text-center">No events recorded for this agent.</p>
          ) : (
            <div className="flex flex-col gap-1.5">
              {agentEvents.map((e, i) => (
                <div
                  key={e.event_id || i}
                  className="flex items-center gap-3 bg-panel2 border border-line rounded-tile px-3 py-2"
                >
                  <span className="text-[11px] font-mono text-ink3 w-16 flex-shrink-0">{relativeTime(e.timestamp)}</span>
                  <div className="flex-1 min-w-0">
                    <div className="text-[12px] font-mono text-ink2 truncate">{e.action}</div>
                    <div className="text-[11px] text-ink3 truncate">{e.resource}</div>
                  </div>
                  {e.reason_codes?.length > 0 && (
                    <div className="hidden sm:flex flex-wrap gap-1">
                      {e.reason_codes.slice(0, 2).map((code) => (
                        <span key={code} className="font-mono text-[9.5px] rounded px-1.5 py-0.5 bg-danger/10 text-danger border border-danger/20">
                          {code}
                        </span>
                      ))}
                    </div>
                  )}
                  <Badge label={e.policy_decision} tone={decisionTone(e.policy_decision)} />
                </div>
              ))}
            </div>
          )}
        </div>
      </Panel>
    </div>
  );
}
