import { Panel } from "../ui/Panel.jsx";

export function MetricCard({
  label,
  value,
  tone = "neutral",
  action,
  className = "",
}) {
  const numColors = {
    neon:    "text-neon",
    danger:  "text-danger",
    amber:   "text-amber",
    dim:     "text-dim",
    neutral: "text-ink",
  };

  return (
    <Panel className={`p-4 flex flex-col justify-between ${className}`}>
      <div className="flex items-start justify-between gap-2">
        <span className="text-[12.5px] font-semibold text-ink2 leading-snug">{label}</span>
        {action && (
          <span className="flex-shrink-0">{action}</span>
        )}
      </div>
      <div className={`text-[30px] font-mono font-semibold leading-none mt-2 ${numColors[tone]}`}>
        {value ?? "—"}
      </div>
    </Panel>
  );
}
