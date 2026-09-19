import { Lock, Unlock } from "lucide-react";
import { Panel } from "../ui/Panel.jsx";

export function SystemLockTile({ locked, onToggle }) {
  return (
    <Panel tone="deep" className="p-4 flex flex-col items-center justify-center gap-2 text-center h-full">
      <button
        onClick={onToggle}
        aria-label={locked ? "Disable system lock" : "Enable system lock"}
        className={`w-11 h-11 rounded-tile flex items-center justify-center transition-colors ${
          locked
            ? "bg-danger/15 text-danger glow-danger"
            : "bg-line text-ink3 hover:bg-line2 hover:text-ink"
        }`}
      >
        {locked ? <Lock size={18} /> : <Unlock size={18} />}
      </button>
      <div className="text-[12.5px] font-semibold text-ink">System lock</div>
      <div className={`text-[11.5px] font-semibold ${locked ? "text-danger" : "text-ink3"}`}>
        {locked ? "Enabled" : "Disabled"}
      </div>
    </Panel>
  );
}

export function ContainmentDonut({ percent = 0 }) {
  const r = 34;
  const stroke = 9;
  const circumference = 2 * Math.PI * r;
  const offset = circumference - (percent / 100) * circumference;

  return (
    <Panel tone="deep" className="p-4 flex flex-col items-center justify-center gap-2 h-full">
      <div className="relative w-[84px] h-[84px]">
        <svg
          width="84"
          height="84"
          viewBox="0 0 84 84"
          style={{ transform: "rotate(-90deg)" }}
          aria-hidden="true"
        >
          {/* Track */}
          <circle
            cx="42" cy="42" r={r}
            fill="none"
            stroke="#123a2c"
            strokeWidth={stroke}
          />
          {/* Arc */}
          <circle
            cx="42" cy="42" r={r}
            fill="none"
            stroke="#1fe98a"
            strokeWidth={stroke}
            strokeDasharray={circumference}
            strokeDashoffset={offset}
            strokeLinecap="round"
            className="transition-all duration-700"
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-[17px] font-mono font-semibold text-ink leading-none">
            {percent}%
          </span>
          <span className="text-[10px] text-ink3 mt-0.5">Active</span>
        </div>
      </div>
      <div className="text-[11.5px] text-ink3">Fleet containment</div>
    </Panel>
  );
}
