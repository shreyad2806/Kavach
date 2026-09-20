import { RefreshCw, WifiOff, ShieldAlert, Timer, Ban, Shield, User } from "lucide-react";

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
    statusDot = "bg-amber"; statusLabel = "Rate limited";
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
    <div
      className="px-4 py-2.5 flex items-center gap-3 flex-wrap border-b border-line bg-bg"
    >
      {/* Left: branding */}
      <div className="flex items-center gap-3 flex-1 min-w-0">
        <div className="flex items-center gap-2">
          <Shield size={16} style={{ color: "#00d4ff" }} className="flex-shrink-0" />
          <span className="text-[13px] font-extrabold tracking-widest text-ink uppercase" style={{ letterSpacing: "0.1em" }}>
            KAVACH
          </span>
        </div>

        <span className="text-ink3 text-[11px] hidden sm:block">·</span>
        <span className="text-[11.5px] text-ink3 hidden sm:block">Runtime Security</span>

        {/* Status pill */}
        <div
          className={`flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-[11px] font-semibold flex-shrink-0 ml-1 ${
            isBad ? "bg-danger/10 border-danger/25" : connected ? "bg-neon/10 border-neon/20" : "bg-line border-line2"
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

      {/* Right: refresh + user */}
      {!minimal && (
        <div className="flex items-center gap-2 flex-shrink-0">
          <button
            onClick={onRefresh}
            aria-label="Refresh all data"
            className="w-7 h-7 rounded-tile flex items-center justify-center text-ink3 hover:text-neon hover:bg-line transition-colors"
          >
            <RefreshCw size={13} />
          </button>

          <div className="flex items-center gap-2 pl-2 border-l border-line">
            <div
              className="w-7 h-7 rounded-full flex items-center justify-center text-[11px] font-bold text-neon flex-shrink-0"
              style={{ background: "rgba(0,212,255,.1)", border: "1px solid rgba(0,212,255,.25)" }}
            >
              <User size={13} />
            </div>
            <div className="hidden sm:block leading-tight">
              <div className="text-[12px] font-semibold text-ink">Security Lead</div>
              <div className="text-[10.5px] text-ink3">On shift</div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
