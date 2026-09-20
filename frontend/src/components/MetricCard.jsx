import { Panel } from "../ui/Panel.jsx";

export function MetricCard({ label, value, tone = "neutral", action, className = "" }) {
  const numColors = {
    neon:    "text-neon",
    danger:  "text-danger",
    amber:   "text-amber",
    dim:     "text-dim",
    neutral: "text-ink",
    allow:   "text-allow",
  };

  const accentColors = {
    neon:    "#38bdf8",
    danger:  "#f87171",
    amber:   "#fbbf24",
    dim:     "#1e3050",
    neutral: "#1a2a45",
    allow:   "#38bdf8",
  };

  const accent = accentColors[tone] ?? accentColors.neutral;

  return (
    <div
      className={`rounded-panel border border-line bg-panel panel-light p-4 flex flex-col justify-between ${className}`}
      style={{ borderTop: `2px solid ${accent}50` }}
    >
      <div className="flex items-start justify-between gap-2">
        <span className="text-[11.5px] font-semibold text-ink3 uppercase tracking-wide leading-snug">{label}</span>
        {action && <span className="flex-shrink-0">{action}</span>}
      </div>
      <div className={`text-[28px] font-mono font-bold leading-none mt-2 ${numColors[tone]}`}>
        {value ?? "—"}
      </div>
    </div>
  );
}
