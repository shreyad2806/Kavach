import { RefreshCw, WifiOff, ShieldAlert, Timer, Ban, Shield, User, Sun, Moon, Palette } from "lucide-react";

const THEME_OPTIONS = [
  { value: "navy-dark", label: "Navy · Dark" },
  { value: "navy-light", label: "Navy · Light" },
  { value: "rust-dark", label: "Rust · Dark" },
  { value: "rust-light", label: "Rust · Light" },
];

export function TopBar({
  connected = false, offline = false, loading = false, onRefresh,
  errorKind = null, minimal = false, theme = "navy-dark", onThemeChange,
}) {
  let statusDot, statusLabel, statusClass, StatusIcon = null;
  if (errorKind === "offline") { statusDot = "bg-danger pulse"; statusLabel = "Backend offline"; statusClass = "text-danger"; StatusIcon = WifiOff; }
  else if (errorKind === "unauthorized") { statusDot = "bg-danger"; statusLabel = "Unauthorized"; statusClass = "text-danger"; StatusIcon = Ban; }
  else if (errorKind === "rate_limited") { statusDot = "bg-amber"; statusLabel = "Rate limited"; statusClass = "text-amber"; StatusIcon = Timer; }
  else if (errorKind) { statusDot = "bg-danger pulse"; statusLabel = "Backend error"; statusClass = "text-danger"; StatusIcon = ShieldAlert; }
  else if (loading) { statusDot = "bg-ink3"; statusLabel = "Connecting…"; statusClass = "text-ink3"; }
  else if (offline) { statusDot = "bg-danger pulse"; statusLabel = "Backend offline"; statusClass = "text-danger"; StatusIcon = WifiOff; }
  else if (connected) { statusDot = "bg-allow pulse"; statusLabel = "Live"; statusClass = "text-allow"; }
  else { statusDot = "bg-ink3"; statusLabel = "Connecting…"; statusClass = "text-ink3"; }

  const isBad = Boolean(errorKind) || offline;
  const isLight = theme.endsWith("light");
  const palette = theme.startsWith("rust") ? "rust" : "navy";
  const toggleMode = () => onThemeChange?.(`${palette}-${isLight ? "dark" : "light"}`);
  const togglePalette = () => onThemeChange?.(`${palette === "navy" ? "rust" : "navy"}-${isLight ? "light" : "dark"}`);

  return (
    <header className="px-4 py-2.5 flex items-center gap-3 flex-wrap border-b border-line bg-bg/95 backdrop-blur-sm">
      <div className="flex items-center gap-3 flex-1 min-w-0">
        <div className="flex items-center gap-2">
          <Shield size={17} className="text-neon flex-shrink-0" />
          <span className="text-[13px] font-extrabold tracking-widest text-ink uppercase">KAVACH</span>
        </div>
        <span className="text-ink3 text-[11px] hidden sm:block">·</span>
        <span className="text-[11.5px] text-ink3 hidden sm:block">Runtime Security</span>
        <div className={`flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-[11px] font-semibold flex-shrink-0 ml-1 ${isBad ? "bg-danger/10 border-danger/25" : connected ? "bg-allow/10 border-allow/20" : "bg-line border-line2"} ${statusClass}`} role="status" aria-live="polite" aria-label={`Backend status: ${statusLabel}`}>
          <span className={`w-1.5 h-1.5 rounded-full flex-shrink-0 ${statusDot}`} aria-hidden="true" />
          {StatusIcon && <StatusIcon size={10} className="flex-shrink-0" />}
          {statusLabel}
        </div>
      </div>

      <div className="flex items-center gap-1.5 flex-shrink-0">
        <button type="button" onClick={togglePalette} title={`Switch to ${palette === "navy" ? "Rust + Ivory" : "Navy + Cream"} palette`} aria-label="Switch color palette" className="h-8 px-2.5 rounded-lg border border-line text-ink3 hover:text-neon hover:border-neon/40 flex items-center gap-1.5 transition-colors">
          <Palette size={14} /><span className="hidden md:inline text-[10px] font-semibold">{palette === "navy" ? "Navy" : "Rust"}</span>
        </button>
        <button type="button" onClick={toggleMode} title={`Switch to ${isLight ? "dark" : "light"} mode`} aria-label={`Switch to ${isLight ? "dark" : "light"} mode`} className="w-8 h-8 rounded-lg border border-line flex items-center justify-center text-ink3 hover:text-neon hover:border-neon/40 transition-colors">
          {isLight ? <Moon size={14} /> : <Sun size={14} />}
        </button>
        <select value={theme} onChange={e => onThemeChange?.(e.target.value)} aria-label="Choose Kavach theme" className="hidden xl:block max-w-[118px] h-8 rounded-lg border border-line bg-panel px-2 text-[10px] text-ink3 outline-none focus:border-neon/50">
          {THEME_OPTIONS.map(option => <option key={option.value} value={option.value}>{option.label}</option>)}
        </select>
        {!minimal && (
          <>
            <button onClick={onRefresh} aria-label="Refresh all data" className="w-8 h-8 rounded-lg flex items-center justify-center text-ink3 hover:text-neon hover:bg-line transition-colors"><RefreshCw size={13} /></button>
            <div className="flex items-center gap-2 pl-2 border-l border-line">
              <div className="w-8 h-8 rounded-full flex items-center justify-center text-[11px] font-bold text-neon bg-neon/10 border border-neon/25 flex-shrink-0"><User size={14} /></div>
              <div className="hidden sm:block leading-tight"><div className="text-[12px] font-semibold text-ink">Security Lead</div><div className="text-[10.5px] text-ink3">On shift</div></div>
            </div>
          </>
        )}
      </div>
    </header>
  );
}
