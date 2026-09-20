import { Panel } from "../ui/Panel.jsx";
import { checkTone } from "../lib/format.js";

const CHECKS = [
  { key: "identity",           label: "Identity" },
  { key: "agent_state",        label: "Agent state" },
  { key: "capability",         label: "Capability" },
  { key: "provenance",         label: "Provenance" },
  { key: "cedar",              label: "Cedar policy" },
  { key: "deterministic_rules",label: "Det. rules" },
];

const TONE_STYLES = {
  allow:   { border: "#38bdf8", bg: "#38bdf818", text: "#38bdf8" },
  neon:    { border: "#38bdf8", bg: "#38bdf818", text: "#38bdf8" },
  danger:  { border: "#f87171", bg: "#f8717118", text: "#f87171" },
  neutral: { border: "#1a2a45", bg: "#101a2e",   text: "#3d5478" },
};

function firstFailedCheck(checks) {
  for (const { key, label } of CHECKS) {
    const status = checks?.[key];
    if (status === "FAIL" || status === "DENY" || status === "BLOCK") {
      return { key, label, status };
    }
  }
  return null;
}

function buildExplanation(event, checks) {
  if (!event) return "Select an authorization event to inspect.";
  const failed = firstFailedCheck(checks);
  if (!failed) {
    return `Request from ${event.source_agent} to ${event.action} on ${event.resource} passed all checks and was allowed.`;
  }
  const reasons = event.reason_codes?.join(", ") || failed.status;
  return `Request from ${event.source_agent} was denied at the ${failed.label} check. Reason: ${reasons}.`;
}

export function AuthPipeline({ event = null, checks = {} }) {
  const explanation = buildExplanation(event, checks);

  return (
    <Panel className="p-4 flex flex-col gap-4 h-full">
      <div className="text-[14px] font-bold text-ink">Authorisation pipeline</div>

      {/* Nodes + connector line */}
      <div className="pipeline-nodes relative flex items-start justify-between gap-1 overflow-x-auto pb-1">
        {/* Connector line behind nodes */}
        <div
          className="pipeline-connector absolute top-[17px] left-[17px] right-[17px] h-[2px] bg-line2 pointer-events-none"
          aria-hidden="true"
        />

        {CHECKS.map(({ key, label }, i) => {
          const status = checks[key] || "NOT_EVALUATED";
          const tone = checkTone(status);
          const styles = TONE_STYLES[tone] || TONE_STYLES.neutral;
          const isDecision = i === CHECKS.length - 1;

          return (
            <div key={key} className="flex flex-col items-center gap-1.5 flex-shrink-0 relative z-10">
              {/* Circle */}
              <div
                className="w-[34px] h-[34px] rounded-full flex items-center justify-center text-[10px] font-bold font-mono border-2"
                style={{
                  borderColor: styles.border,
                  background: styles.bg,
                  color: styles.text,
                  boxShadow: tone === "allow" || tone === "neon" ? "0 0 8px rgba(56,189,248,.25)" : tone === "danger" ? "0 0 8px rgba(248,113,113,.2)" : "none",
                }}
                aria-label={`${label}: ${status}`}
              >
                {tone === "allow" || tone === "neon" ? "✓" : tone === "danger" ? "✗" : "—"}
              </div>
              {/* Label */}
              <div className="text-[10.5px] text-ink3 text-center leading-tight max-w-[56px]">
                {label}
              </div>
              {/* Status in mono — a stage that never ran says so explicitly. */}
              <div
                className="text-[9.5px] font-mono font-semibold text-center leading-tight"
                style={{ color: styles.text }}
              >
                {status === "NOT_EVALUATED" ? "NOT EVALUATED" : status}
              </div>
            </div>
          );
        })}
      </div>

      {/* Plain-English explanation */}
      <p className="text-[12.5px] text-ink3 leading-relaxed border-t border-line pt-3">
        {explanation}
      </p>
    </Panel>
  );
}
