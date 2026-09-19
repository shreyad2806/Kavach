import { Panel } from "../ui/Panel.jsx";

// points: array of numbers 0–100 (time series)
function RiskSparkline({ points }) {
  const W = 320;
  const H = 58;
  if (!points || points.length < 2) return null;

  const min = 0;
  const max = 100;
  const xStep = W / (points.length - 1);

  const coords = points.map((v, i) => {
    const x = i * xStep;
    const y = H - ((v - min) / (max - min)) * H;
    return `${x},${y}`;
  });

  const polyline = coords.join(" ");

  return (
    <svg
      width={W}
      height={H}
      viewBox={`0 0 ${W} ${H}`}
      aria-hidden="true"
      className="w-full"
      preserveAspectRatio="none"
    >
      <defs>
        <linearGradient id="risk-gradient" x1="0" y1="0" x2="1" y2="0">
          <stop offset="0%" stopColor="#1fe98a" />
          <stop offset="100%" stopColor="#ff4d5e" />
        </linearGradient>
      </defs>
      <polyline
        points={polyline}
        fill="none"
        stroke="url(#risk-gradient)"
        strokeWidth="2"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

export function FleetRiskCard({ score = 24, delta = +3, drivingAgent = "research-01", sparkline = [] }) {
  const rising = delta > 0;
  const scoreColor = score >= 80 ? "text-danger" : score >= 51 ? "text-amber" : "text-neon";

  // Sample sparkline if none provided
  const points = sparkline.length > 0
    ? sparkline
    : [12, 18, 15, 22, 19, 28, 24, 31, 27, 24];

  return (
    <Panel className="p-4 flex flex-col gap-2 h-full">
      <div className="flex items-start justify-between gap-2">
        <div className="text-[12.5px] font-semibold text-ink2">Fleet risk score</div>
        <span
          className={`inline-flex items-center rounded-full px-2 py-0.5 text-[11px] font-bold font-mono border ${
            rising
              ? "bg-danger/10 text-danger border-danger/20"
              : "bg-neon/10 text-neon border-neon/20"
          }`}
          aria-label={`Risk score ${rising ? "rising" : "falling"} by ${Math.abs(delta)}`}
        >
          {rising ? "▲" : "▼"} {Math.abs(delta)}
        </span>
      </div>

      <div className={`text-[34px] font-mono font-semibold leading-none ${scoreColor}`}>
        {score}
        <span className="text-[14px] text-ink3 font-sans font-semibold ml-1">/100</span>
      </div>

      <div className="mt-1 -mx-1">
        <RiskSparkline points={points} />
      </div>

      <div className="text-[11.5px] text-ink3 mt-1">
        Driven by{" "}
        <span className="font-mono text-ink2">{drivingAgent}</span>
      </div>
    </Panel>
  );
}
