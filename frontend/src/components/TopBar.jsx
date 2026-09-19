import { Menu, Plus, RefreshCw, Search, Wifi, WifiOff } from "lucide-react";
import { Panel } from "../ui/Panel.jsx";
import { Button } from "../ui/Button.jsx";

export function TopBar({ onNewScan, onRefresh, reconnecting = false }) {
  return (
    <Panel className="px-4 py-3 flex items-center gap-3 flex-wrap">
      {/* Left */}
      <div className="flex items-center gap-3 flex-1 min-w-0">
        <button
          aria-label="Open navigation menu"
          className="w-8 h-8 rounded-btn flex items-center justify-center text-ink3 hover:text-ink hover:bg-line transition-colors"
        >
          <Menu size={15} />
        </button>

        {/* KV logo — neon fill, dark glyph, 5px neon ring */}
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

        {/* Reconnecting indicator */}
        {reconnecting && (
          <div className="flex items-center gap-1.5 rounded-full bg-amber/10 border border-amber/20 px-2.5 py-1 text-[11px] font-semibold text-amber">
            <WifiOff size={11} />
            Reconnecting…
          </div>
        )}
      </div>

      {/* Right */}
      <div className="flex items-center gap-2 flex-shrink-0">
        <Button tone="neon" size="sm" onClick={onNewScan} aria-label="Submit new artifact scan">
          <Plus size={13} />
          New scan
        </Button>

        <button
          onClick={onRefresh}
          aria-label="Refresh all data"
          className="w-8 h-8 rounded-btn flex items-center justify-center text-ink3 hover:text-ink hover:bg-line transition-colors"
        >
          <RefreshCw size={14} />
        </button>

        {/* Avatar */}
        <div className="flex items-center gap-2">
          <div className="w-8 h-8 rounded-full bg-line2 border border-line flex items-center justify-center text-[11px] font-bold text-ink2 flex-shrink-0">
            SL
          </div>
          <div className="hidden sm:block leading-tight">
            <div className="text-[12.5px] font-semibold text-ink">Security lead</div>
            <div className="text-[11px] text-ink3">On shift</div>
          </div>
        </div>

        {/* Search */}
        <label className="hidden md:flex items-center gap-2 bg-panel2 border border-line rounded-full px-3 py-1.5 w-56">
          <Search size={12} className="text-ink3 flex-shrink-0" />
          <input
            type="search"
            placeholder="Search agents, resources, reason codes…"
            className="bg-transparent outline-none text-[12px] text-ink placeholder:text-ink3 w-full"
            aria-label="Search agents, resources, reason codes"
          />
        </label>
      </div>
    </Panel>
  );
}
