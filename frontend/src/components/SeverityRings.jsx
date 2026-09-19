import { Panel } from "../ui/Panel.jsx";

function Ring({ cx, cy, r, percent, color, track = "#123a2c", strokeWidth = 8 }) {
  const circumference = 2 * Math.PI * r;
  const offset = circumference - (percent / 100) * circumference;
  return (
    <g>
      <circle cx={cx} cy={cy} r={r} fill="none" stroke={track} strokeWidth={strokeWidth} />
      <circle
        cx={cx} cy={cy} r={r}
        fill="none"
        stroke={color}
        strokeWidth={strokeWidth}
        strokeDasharray={circumference}
        strokeDashoffset={offset}
        strokeLinecap="round"
        style={{ transform: "rotate(-90deg)", transformOrigin: `${cx}px ${cy}px` }}
      />
    </g>
  );
}

export function SeverityRings({ low = 0, medium = 0, critical = 0 }) {
  const total = low + medium + critical || 1;
  const lowPct      = Math.round((low / total) * 100);
  const medPct      = Math.round((medium / total) * 100);
  const critPct     = Math.round((critical / total) * 100);

  const CX = 100;
  const CY = 100;

  return (
    <Panel className="p-4 flex flex-col gap-3 h-full">
      <div className="text-[14px] font-bold text-ink">Incidents by severity</div>

      <div className="flex items-center gap-4">
        {/* Rings */}
        <svg width="200" height="200" viewBox="0 0 200 200" aria-hidden="true" className="flex-shrink-0">
          <Ring cx={CX} cy={CY} r={84} percent={lowPct}  color="#1fe98a" strokeWidth={8} />
          <Ring cx={CX} cy={CY} r={60} percent={medPct}  color="#ffc046" strokeWidth={8} />
          <Ring cx={CX} cy={CY} r={36} percent={critPct} color="#ff4d5e" strokeWidth={8} />
          {/* Center total */}
          <text x={CX} y={CY - 6} textAnchor="middle" fill="#e8fff4" fontSize="20" fontFamily="IBM Plex Mono" fontWeight="600">
            {low + medium + critical}
          </text>
          <text x={CX} y={CY + 12} textAnchor="middle" fill="#6d8f80" fontSize="10" fontFamily="Manrope">
            total
          </text>
        </svg>

        {/* Legend */}
        <div className="flex flex-col gap-3">
          {[
            { label: "Low",      count: low,      color: "#1fe98a", r: 84 },
            { label: "Medium",   count: medium,   color: "#ffc046", r: 60 },
            { label: "Critical", count: critical, color: "#ff4d5e", r: 36 },
          ].map(({ label, count, color }) => (
            <div key={label} className="flex items-center gap-2">
              <span
                className="w-2.5 h-2.5 rounded-full flex-shrink-0"
                style={{ background: color }}
                aria-hidden="true"
              />
              <div>
                <div className="text-[11.5px] text-ink3">{label}</div>
                <div className="text-[18px] font-mono font-semibold leading-none" style={{ color }}>
                  {count}
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </Panel>
  );
}
