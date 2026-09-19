import { X } from "lucide-react";

// Pill — small rounded button/tag, tone-aware
export function Pill({ children, tone = "neutral", active = false, onClick, className = "" }) {
  const tones = {
    neon:    "bg-neon/10 text-neon border-neon/30",
    danger:  "bg-danger/10 text-danger border-danger/30",
    amber:   "bg-amber/10 text-amber border-amber/30",
    dim:     "bg-dim/20 text-ink3 border-dim/30",
    neutral: "bg-line text-ink2 border-line2",
  };
  const activeCls = active ? "border-neon text-neon bg-neon/10" : "";
  const interactive = onClick ? "cursor-pointer hover:border-line2 hover:text-ink" : "";
  return (
    <span
      role={onClick ? "button" : undefined}
      tabIndex={onClick ? 0 : undefined}
      onClick={onClick}
      onKeyDown={onClick ? (e) => e.key === "Enter" && onClick() : undefined}
      className={`inline-flex items-center gap-1 rounded-full border px-2.5 py-0.5 text-[11.5px] font-semibold select-none ${tones[tone]} ${activeCls} ${interactive} ${className}`}
    >
      {children}
    </span>
  );
}

// Chip — removable filter chip
export function Chip({ label, onRemove }) {
  return (
    <span className="inline-flex items-center gap-1 rounded-full bg-line border border-line2 px-2.5 py-0.5 text-[11.5px] font-semibold text-ink2">
      {label}
      {onRemove && (
        <button
          onClick={onRemove}
          aria-label={`Remove filter ${label}`}
          className="text-ink3 hover:text-danger transition-colors"
        >
          <X size={10} />
        </button>
      )}
    </span>
  );
}

// Badge — state/status badge, tone-aware, always has text label
export function Badge({ label, tone = "neutral" }) {
  const tones = {
    neon:    "bg-neon/10 text-neon border-neon/20",
    danger:  "bg-danger/10 text-danger border-danger/20",
    amber:   "bg-amber/10 text-amber border-amber/20",
    dim:     "bg-dim/20 text-ink3 border-dim/20",
    neutral: "bg-line text-ink2 border-line2",
  };
  return (
    <span
      className={`inline-flex items-center rounded-md border px-2 py-0.5 text-[10.5px] font-bold uppercase tracking-wide ${tones[tone]}`}
    >
      {label}
    </span>
  );
}

// SegmentedControl — two-option toggle
export function SegmentedControl({ options, value, onChange }) {
  return (
    <div className="inline-flex rounded-btn bg-panel2 border border-line p-0.5 gap-0.5">
      {options.map((opt) => (
        <button
          key={opt.value}
          type="button"
          onClick={() => onChange(opt.value)}
          className={`px-3 py-1 rounded-[9px] text-[11.5px] font-semibold transition-colors ${
            value === opt.value
              ? "bg-line2 text-ink"
              : "text-ink3 hover:text-ink2"
          }`}
        >
          {opt.label}
        </button>
      ))}
    </div>
  );
}
