import { RefreshCw, WifiOff } from "lucide-react";
import { Panel } from "../ui/Panel.jsx";

/**
 * TopBar — Kavach branding + connection status + refresh.
 *
 * Props:
 *   connected   {boolean}  true when backend is reachable
 *   offline     {boolean}  true when last poll failed
 *   loading     {boolean}  true on first load before any data
 *   onRefresh   {function} manual refresh trigger
 */
export function TopBar({ connected, offline, loading, onRefresh }) {
  // Derive status indicator
  let statusDot, statusLabel, statusClass;
  if (loading) {
    statusDot   = "bg-ink3";
    statusLabel = "Connecting…";
    statusClass = "text-ink3";
  } else if (offline) {
    statusDot   = "bg-danger pulse";
    statusLabel = "Backend offline";
    statusClass = "text-danger";
  } else if (connected) {
    statusDot   = "bg-neon pulse";
    statusLabel = "Live";
    statusClass = "text-neon";
  } else {
    statusDot   = "bg-ink3";
    statusLabel = "Connecting…";
    statusClass = "text-ink3";
  }

  return (
    <Panel className="px-4 py-3 flex items-center gap-3 flex-wrap">
      {/* Left: logo + name */}
      <div className="flex items-center gap-3 flex-1 min-w-0">
        {/* KV logo */}
        <div
          className="w-9 h-9 rounded-full flex items-center justify-center font-extrabold text-[13px] text-deep bg-neon flex-shrink-0"
          style={{ boxShadow: "0 0 0 2px #04120d, 0 0 0 4px #1fe98a" }}
          aria-hidden="true"
        >
          KV
        </div>

        <div className="leading-tight min-w-0">
          <div className="text-[14px] font-bold text-ink">Kavach</div>
          <div className="text-[11.5px] text-ink3">Runtime security</div>
        </div>

        {/* Connection status pill */}
        <div
          className={`flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-[11.5px] font-semibold flex-shrink-0 ${
            offline
              ? "bg-danger/10 border-danger/20"
              : connected
              ? "bg-neon/10 border-neon/20"
              : "bg-line border-line2"
          } ${statusClass}`}
          role="status"
          aria-live="polite"
          aria-label={`Backend status: ${statusLabel}`}
        >
          <span className={`w-1.5 h-1.5 rounded-full flex-shrink-0 ${statusDot}`} aria-hidden="true" />
          {offline && <WifiOff size={10} className="flex-shrink-0" />}
          {statusLabel}
        </div>
      </div>

      {/* Right: refresh + avatar */}
      <div className="flex items-center gap-2 flex-shrink-0">
        <button
          onClick={onRefresh}
          aria-label="Refresh all data"
          className="w-8 h-8 rounded-btn flex items-center justify-center text-ink3 hover:text-ink hover:bg-line transition-colors"
        >
          <RefreshCw size={14} />
        </button>

        <div className="flex items-center gap-2">
          <div className="w-8 h-8 rounded-full bg-line2 border border-line flex items-center justify-center text-[11px] font-bold text-ink2 flex-shrink-0">
            SL
          </div>
          <div className="hidden sm:block leading-tight">
            <div className="text-[12.5px] font-semibold text-ink">Security lead</div>
            <div className="text-[11px] text-ink3">On shift</div>
          </div>
        </div>
      </div>
    </Panel>
  );
}
