import { RefreshCw, WifiOff, ShieldAlert, Timer, Ban } from "lucide-react";
import { Panel } from "../ui/Panel.jsx";

/**
 * TopBar — Kavach branding + connection status.
 *
 * The status distinguishes real failure modes, so a single throttled poll never
 * gets reported as an outage:
 *
 *   offline      -> Backend offline
 *   unauthorized -> Unauthorized
 *   rate_limited -> Rate limited / retrying
 *   5xx          -> Backend error
 *
 * `minimal` is used on the landing screen: branding and status only, no
 * operator chrome.
 */
export function TopBar({
  connected = false,
  offline = false,
  loading = false,
  onRefresh,
  errorKind = null,
  minimal = false,
}) {
  let statusDot, statusLabel, statusClass, StatusIcon = null;

  if (errorKind === "offline") {
    statusDot = "bg-danger pulse"; statusLabel = "Backend offline";
    statusClass = "text-danger"; StatusIcon = WifiOff;
  } else if (errorKind === "unauthorized") {
    statusDot = "bg-danger"; statusLabel = "Unauthorized";
    statusClass = "text-danger"; StatusIcon = Ban;
  } else if (errorKind === "rate_limited") {
    statusDot = "bg-amber"; statusLabel = "Rate limited — retrying";
    statusClass = "text-amber"; StatusIcon = Timer;
  } else if (errorKind) {
    statusDot = "bg-danger pulse"; statusLabel = "Backend error";
    statusClass = "text-danger"; StatusIcon = ShieldAlert;
  } else if (loading) {
    statusDot = "bg-ink3"; statusLabel = "Connecting…"; statusClass = "text-ink3";
  } else if (offline) {
    statusDot = "bg-danger pulse"; statusLabel = "Backend offline";
    statusClass = "text-danger"; StatusIcon = WifiOff;
  } else if (connected) {
    statusDot = "bg-neon pulse"; statusLabel = "Live"; statusClass = "text-neon";
  } else {
    statusDot = "bg-ink3"; statusLabel = "Connecting…"; statusClass = "text-ink3";
  }

  const isBad = Boolean(errorKind) || offline;

  return (
    <Panel className="px-4 py-3 flex items-center gap-3 flex-wrap rounded-none border-x-0 border-t-0">
      {/* Left: logo + name */}
      <div className="flex items-center gap-3 flex-1 min-w-0">
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

        {/* Connection status */}
        <div
          className={`flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-[11.5px] font-semibold flex-shrink-0 ${
            isBad ? "bg-danger/10 border-danger/20" : connected ? "bg-neon/10 border-neon/20" : "bg-line border-line2"
          } ${statusClass}`}
          role="status"
          aria-live="polite"
          aria-label={`Backend status: ${statusLabel}`}
        >
          <span className={`w-1.5 h-1.5 rounded-full flex-shrink-0 ${statusDot}`} aria-hidden="true" />
          {StatusIcon && <StatusIcon size={10} className="flex-shrink-0" />}
          {statusLabel}
        </div>
      </div>

      {/* Right: refresh + operator (hidden on the landing screen) */}
      {!minimal && (
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
      )}
    </Panel>
  );
}
