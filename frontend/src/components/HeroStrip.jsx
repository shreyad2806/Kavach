import { ArrowRight, Mic } from "lucide-react";
import { Panel } from "../ui/Panel.jsx";
import { Button } from "../ui/Button.jsx";

// Shield SVG with lock — color-driven by hasIncident
function ShieldIcon({ hasIncident }) {
  const color = hasIncident ? "#ff4d5e" : "#1fe98a";
  const glow = hasIncident ? "rgba(255,77,94,.3)" : "rgba(31,233,138,.3)";
  return (
    <svg
      width="72"
      height="80"
      viewBox="0 0 72 80"
      fill="none"
      aria-hidden="true"
      style={{ filter: `drop-shadow(0 0 14px ${glow})` }}
    >
      <path
        d="M36 4L8 16v22c0 18.2 11.9 35.2 28 40 16.1-4.8 28-21.8 28-40V16L36 4z"
        fill={color}
        fillOpacity=".12"
        stroke={color}
        strokeWidth="1.5"
      />
      <rect x="28" y="30" width="16" height="14" rx="3" fill={color} fillOpacity=".7" />
      <path
        d="M32 30v-3a4 4 0 0 1 8 0v3"
        stroke={color}
        strokeWidth="1.8"
        strokeLinecap="round"
      />
      <circle cx="36" cy="37" r="2" fill={color} />
    </svg>
  );
}

export function HeroStrip({ openIncidents = 0, onCTA, onViewActivity }) {
  const hasIncident = openIncidents > 0;
  const today = new Date();
  const dayNum = today.getDate();
  const dayName = today.toLocaleDateString("en", { weekday: "short" });
  const monthName = today.toLocaleDateString("en", { month: "long" });

  return (
    <Panel className="px-5 py-4 flex items-center gap-4 flex-wrap">
      {/* Day circle */}
      <div className="flex items-center gap-3 flex-shrink-0">
        <div className="w-12 h-12 rounded-full border border-line2 flex flex-col items-center justify-center leading-tight">
          <span className="text-[18px] font-bold text-ink font-mono">{dayNum}</span>
        </div>
        <div className="hidden sm:block text-[12px] text-ink3 leading-snug">
          <span className="block font-semibold text-ink2">{dayName}</span>
          {monthName}
        </div>
      </div>

      {/* CTA */}
      <Button
        tone={hasIncident ? "danger" : "neon"}
        size="md"
        onClick={hasIncident ? onCTA : onViewActivity}
      >
        {hasIncident ? `Review ${openIncidents} incident${openIncidents !== 1 ? "s" : ""}` : "View activity"}
        <ArrowRight size={13} />
      </Button>

      {/* Headline */}
      <div className="flex-1 min-w-[180px]">
        <h1 className="text-[18px] font-extrabold text-ink leading-tight">
          {hasIncident
            ? openIncidents === 1
              ? "One agent needs attention"
              : `${openIncidents} agents need attention`
            : "Fleet is clean 🛡️"}
        </h1>
        <p className="text-[12.5px] text-ink3 mt-0.5">
          {hasIncident
            ? `${openIncidents} open incident${openIncidents !== 1 ? "s" : ""} require operator review.`
            : "All agents operating within policy. No open incidents."}
        </p>
      </div>

      {/* Right: shield + mic */}
      <div className="flex items-center gap-3 flex-shrink-0 ml-auto">
        <ShieldIcon hasIncident={hasIncident} />
        <button
          aria-label="Voice command"
          className="w-9 h-9 rounded-full border border-line2 flex items-center justify-center text-ink3 hover:text-ink hover:border-line transition-colors"
        >
          <Mic size={15} />
        </button>
      </div>
    </Panel>
  );
}
