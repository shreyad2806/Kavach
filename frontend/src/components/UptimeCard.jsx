import { Panel } from "../ui/Panel.jsx";

// dots: array of booleans — true = clean day, false = partial/incident
export function UptimeCard({ days = 13, dots = [] }) {
  // Default: 13 clean days + 1 partial
  const dotData = dots.length > 0 ? dots : [
    ...Array(days).fill(true),
    false,
  ];

  return (
    <Panel className="p-4 flex flex-col gap-2 h-full">
      <div className="text-[12.5px] font-semibold text-ink2">Uptime</div>
      <div className="text-[30px] font-mono font-semibold text-ink leading-none">
        {days} <span className="text-[14px] text-ink3 font-sans font-semibold">days</span>
      </div>
      <div className="text-[11.5px] text-ink3">No policy violations</div>
      {/* Dot row */}
      <div className="flex flex-wrap gap-1.5 mt-auto pt-2">
        {dotData.map((clean, i) => (
          <span
            key={i}
            aria-label={clean ? "Clean day" : "Partial day"}
            className="w-[9px] h-[9px] rounded-full flex-shrink-0"
            style={{ background: clean ? "#1fe98a" : "#123a2c" }}
          />
        ))}
      </div>
    </Panel>
  );
}
