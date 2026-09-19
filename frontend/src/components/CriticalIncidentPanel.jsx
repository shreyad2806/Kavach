import { AlertTriangle } from "lucide-react";
import { Panel } from "../ui/Panel.jsx";
import { Button } from "../ui/Button.jsx";
import { severityTone } from "../lib/format.js";

export function CriticalIncidentPanel({ incident, onResolve, onHistory }) {
  if (!incident) {
    return (
      <Panel className="p-5 flex flex-col items-center justify-center gap-2 h-full text-center">
        <div className="text-[13px] font-semibold text-ink2">Nothing needs you right now.</div>
        <div className="text-[12px] text-ink3">No open incidents.</div>
      </Panel>
    );
  }

  const isCritical = incident.severity === "CRITICAL" || incident.severity === "HIGH";
  const accentColor = isCritical ? "#ff4d5e" : "#ffc046";

  return (
    <Panel
      className="p-5 flex flex-col gap-3 h-full relative overflow-hidden"
      style={{ borderColor: `${accentColor}30` }}
    >
      {/* Decorative warning triangle — bleeds off bottom-right */}
      <div
        className="absolute bottom-[-20px] right-[-16px] pointer-events-none select-none"
        aria-hidden="true"
        style={{ opacity: 0.06 }}
      >
        <AlertTriangle size={140} color={accentColor} />
      </div>

      {/* Heading */}
      <div className="flex items-center gap-2">
        <span
          className="w-2 h-2 rounded-full flex-shrink-0 pulse"
          style={{ background: accentColor, boxShadow: `0 0 8px ${accentColor}60` }}
          aria-hidden="true"
        />
        <span
          className="text-[11px] font-bold uppercase tracking-widest"
          style={{ color: accentColor }}
        >
          {incident.severity} incident
        </span>
      </div>

      {/* Agent + ID */}
      <div>
        <div className="text-[11.5px] font-mono text-ink3">{incident.agent_id}</div>
        <div className="text-[11px] font-mono text-ink3 mt-0.5">{incident.incident_id}</div>
      </div>

      {/* Title */}
      <h3 className="text-[15px] font-bold text-ink leading-snug">
        {incident.reason_codes?.[0]?.replace(/_/g, " ") || "Security violation"}
      </h3>

      {/* Description */}
      {incident.description && (
        <p className="text-[12px] text-ink3 leading-relaxed">{incident.description}</p>
      )}

      {/* Key/value lines */}
      <div className="flex flex-col gap-1.5 text-[12px]">
        <div className="flex justify-between gap-2">
          <span className="text-ink3">Status</span>
          <span className="font-semibold text-ink2">{incident.status}</span>
        </div>
        <div className="flex justify-between gap-2">
          <span className="text-ink3">Severity</span>
          <span className="font-semibold" style={{ color: accentColor }}>{incident.severity}</span>
        </div>
        {incident.reason_codes?.length > 0 && (
          <div className="flex flex-col gap-1 mt-1">
            <span className="text-ink3">Reason codes</span>
            <div className="flex flex-wrap gap-1.5 mt-0.5">
              {incident.reason_codes.map((code) => (
                <span
                  key={code}
                  className="font-mono text-[10.5px] rounded-md px-2 py-0.5 border"
                  style={{
                    color: accentColor,
                    background: `${accentColor}12`,
                    borderColor: `${accentColor}25`,
                  }}
                >
                  {code}
                </span>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Enforcement footer */}
      <div className="mt-auto pt-3 border-t" style={{ borderColor: `${accentColor}20` }}>
        <div className="text-[11px] font-semibold uppercase tracking-wide text-ink3 mb-2">
          Enforcement
        </div>
        <div className="flex gap-2">
          <Button
            tone="danger"
            size="sm"
            onClick={() => onResolve?.(incident.incident_id)}
            className="flex-1"
          >
            Resolve incident
          </Button>
          <Button
            tone="outline"
            size="sm"
            onClick={() => onHistory?.(incident.incident_id)}
            className="flex-1"
          >
            Full history
          </Button>
        </div>
      </div>
    </Panel>
  );
}
