import { ArrowRight, CheckCircle2, CircleDashed, ShieldAlert } from "lucide-react";
import { Panel } from "../ui/Panel.jsx";
import { checkTone } from "../lib/format.js";

const CHECKS = [
  { key: "identity", label: "Identity", detail: "Registered principal" },
  { key: "agent_state", label: "Agent state", detail: "Quarantine / revocation" },
  { key: "capability", label: "Capability", detail: "Least-privilege grant" },
  { key: "provenance", label: "Provenance", detail: "Delegation lineage" },
  { key: "cedar", label: "Cedar policy", detail: "Declarative policy" },
  { key: "deterministic_rules", label: "Runtime rules", detail: "Context invariants" },
];

const statusPresentation = (status) => {
  if (status === "PASS" || status === "ALLOW") return { label: status, className: "text-emerald-300 border-emerald-400/20 bg-emerald-400/[.06]", Icon: CheckCircle2 };
  if (status === "FAIL" || status === "DENY" || status === "BLOCK") return { label: status, className: "text-rose-300 border-rose-400/20 bg-rose-400/[.06]", Icon: ShieldAlert };
  return { label: "NOT EVALUATED", className: "text-slate-500 border-white/[.07] bg-white/[.02]", Icon: CircleDashed };
};

export function AuthPipeline({ event = null, checks = {} }) {
  const failed = CHECKS.find(({ key }) => ["FAIL", "DENY", "BLOCK"].includes(checks?.[key]));
  const reasons = event?.reason_codes ?? [];

  return (
    <Panel className="p-4 sm:p-5 flex flex-col gap-4 h-full">
      <div className="flex items-start justify-between gap-3">
        <div>
          <div className="text-sm font-semibold text-slate-100">Authorization trace</div>
          <div className="text-[11px] text-slate-500 mt-1">Every gate is evaluated before a protected operation executes.</div>
        </div>
        {event && (
          <span className={\`text-[10px] font-bold tracking-wider px-2.5 py-1 rounded-full border \${event.policy_decision === "ALLOW" ? "text-emerald-300 border-emerald-400/20 bg-emerald-400/[.06]" : "text-rose-300 border-rose-400/20 bg-rose-400/[.06]"}\`}>
            {event.policy_decision}
          </span>
        )}
      </div>

      {!event ? (
        <div className="flex flex-col items-center justify-center text-center py-8">
          <div className="w-10 h-10 rounded-xl border border-white/[.07] bg-white/[.02] flex items-center justify-center mb-3"><CircleDashed size={17} className="text-slate-500" /></div>
          <div className="text-xs font-medium text-slate-300">Select a runtime decision</div>
          <div className="text-[11px] text-slate-500 mt-1">The full authorization trace will appear here.</div>
        </div>
      ) : (
        <>
          <div className="grid grid-cols-2 sm:grid-cols-3 gap-2">
            {CHECKS.map(({ key, label, detail }, index) => {
              const status = checks[key] || "NOT_EVALUATED";
              const presentation = statusPresentation(status);
              const Icon = presentation.Icon;
              return (
                <div key={key} className={\`rounded-xl border px-3 py-3 min-w-0 \${presentation.className}\`}>
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-[10px] font-semibold">{label}</span>
                    <Icon size={13} className="flex-shrink-0" />
                  </div>
                  <div className="text-[9px] opacity-60 mt-1">{detail}</div>
                  <div className="font-mono text-[9px] tracking-wide mt-3">{presentation.label}</div>
                </div>
              );
            })}
          </div>
          <div className="border-t border-white/[.06] pt-3">
            <div className="flex items-center gap-2 text-[11px] font-semibold text-slate-300 mb-2">
              {failed ? <ShieldAlert size={13} className="text-rose-300" /> : <CheckCircle2 size={13} className="text-emerald-300" />}
              {failed ? \`Stopped at \${failed.label}\` : event.policy_decision === "ALLOW" ? "Request passed authorization" : "Request denied"}
            </div>
            <p className="text-[11px] leading-relaxed text-slate-500">
              {reasons.length
                ? reasons.map(value => value.replaceAll("_", " ").toLowerCase()).join(" · ")
                : failed
                  ? \`The \${failed.label.toLowerCase()} gate rejected this operation. Later checks are not treated as approval.\`
                  : event.policy_decision === "ALLOW"
                    ? \`\${event.source_agent} was authorized to perform \${event.action} against \${event.resource}.\`
                    : "The request was denied by the authorization control plane."}
            </p>
            <div className="grid grid-cols-2 gap-3 mt-3 text-[10px]">
              <div><span className="text-slate-600">Request</span><div className="font-mono text-slate-400 mt-1 truncate">{event.request_id}</div></div>
              <div><span className="text-slate-600">Agent</span><div className="font-mono text-slate-400 mt-1 truncate">{event.source_agent}</div></div>
            </div>
          </div>
        </>
      )}
    </Panel>
  );
}
