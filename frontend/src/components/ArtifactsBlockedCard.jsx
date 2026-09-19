import { Panel } from "../ui/Panel.jsx";
import { SegmentedControl } from "../ui/index.jsx";
import { useState } from "react";

// bars: array of numbers (7 values)
function BarChart({ bars, currentIndex }) {
  const max = Math.max(...bars, 1);
  const W = 160;
  const H = 48;
  const barW = 14;
  const gap = (W - bars.length * barW) / (bars.length - 1);

  return (
    <svg width={W} height={H} viewBox={`0 0 ${W} ${H}`} aria-hidden="true">
      {bars.map((val, i) => {
        const barH = Math.max(3, (val / max) * H);
        const x = i * (barW + gap);
        const y = H - barH;
        const isCurrent = i === currentIndex;
        return (
          <g key={i}>
            {isCurrent && (
              <rect
                x={x} y={y} width={barW} height={barH}
                rx="3"
                fill="#1fe98a"
                filter="url(#neon-glow)"
              />
            )}
            {!isCurrent && (
              <rect
                x={x} y={y} width={barW} height={barH}
                rx="3"
                fill="#123a2c"
              />
            )}
          </g>
        );
      })}
      <defs>
        <filter id="neon-glow" x="-50%" y="-50%" width="200%" height="200%">
          <feGaussianBlur stdDeviation="2.5" result="blur" />
          <feMerge>
            <feMergeNode in="blur" />
            <feMergeNode in="SourceGraphic" />
          </feMerge>
        </filter>
      </defs>
    </svg>
  );
}

const SAMPLE = {
  "last-week":  [2, 5, 3, 7, 4, 6, 3],
  "this-week":  [1, 4, 6, 2, 8, 5, 7],
};

export function ArtifactsBlockedCard({ data = SAMPLE }) {
  const [period, setPeriod] = useState("this-week");
  const bars = data[period] || SAMPLE[period];
  const currentIndex = bars.length - 1;
  const total = bars.reduce((a, b) => a + b, 0);

  return (
    <Panel className="p-4 flex flex-col gap-2 h-full">
      <div className="flex items-center justify-between">
        <div className="text-[12.5px] font-semibold text-ink2">Artifacts blocked</div>
        <SegmentedControl
          options={[
            { label: "Last wk", value: "last-week" },
            { label: "This wk", value: "this-week" },
          ]}
          value={period}
          onChange={setPeriod}
        />
      </div>
      <div className="text-[28px] font-mono font-semibold text-ink leading-none">
        {total}
      </div>
      <div className="mt-auto">
        <BarChart bars={bars} currentIndex={currentIndex} />
      </div>
    </Panel>
  );
}
