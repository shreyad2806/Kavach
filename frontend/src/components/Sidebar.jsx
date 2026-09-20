import { LayoutDashboard, ScanLine, Menu, Shield } from "lucide-react";

const NAV_ITEMS = [
  { id: "dashboard", label: "Dashboard",       Icon: LayoutDashboard },
  { id: "scanner",   label: "Artifact Scanner", Icon: ScanLine        },
];

export function Sidebar({ activePage, onNavigate, collapsed, onToggle }) {
  return (
    <aside
      className={`flex flex-col border-r border-line bg-bg transition-all duration-200 flex-shrink-0 ${
        collapsed ? "w-[56px]" : "w-[210px]"
      }`}
      style={{ minHeight: "100vh" }}
    >
      {/* Branding + hamburger */}
      <div className={`flex items-center border-b border-line px-3 py-4 ${collapsed ? "flex-col gap-3" : "gap-2.5"}`}>
        <button
          onClick={onToggle}
          title={collapsed ? "Expand sidebar" : "Collapse sidebar"}
          className="text-ink3 hover:text-neon transition-colors flex-shrink-0"
        >
          <Menu size={18} />
        </button>
        {!collapsed && (
          <>
            <div
              className="w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0"
              style={{
                background: "linear-gradient(135deg, #00d4ff22, #0064c822)",
                border: "1.5px solid #00d4ff40",
                boxShadow: "0 0 10px rgba(0,212,255,.18)",
              }}
            >
              <Shield size={15} style={{ color: "#00d4ff" }} />
            </div>
            <div className="leading-tight min-w-0">
              <div className="text-[13px] font-extrabold tracking-widest text-ink uppercase" style={{ letterSpacing: "0.12em" }}>
                KAVACH
              </div>
              <div className="text-[10px] text-ink3 tracking-wide">Zero-Trust Security</div>
            </div>
          </>
        )}
      </div>

      {/* Nav label */}
      {!collapsed && (
        <div className="px-3 pt-4 pb-1">
          <span className="text-[10px] font-bold uppercase tracking-widest text-ink3">Navigation</span>
        </div>
      )}

      {/* Nav items */}
      <nav className="flex flex-col gap-1 p-2 flex-1">
        {NAV_ITEMS.map(({ id, label, Icon }) => {
          const active = activePage === id;
          return (
            <button
              key={id}
              onClick={() => onNavigate(id)}
              title={collapsed ? label : undefined}
              className={`flex items-center gap-2.5 rounded-tile px-2.5 py-2.5 text-left transition-all w-full ${
                active
                  ? "text-neon border border-neon/20"
                  : "text-ink3 hover:text-ink2 hover:bg-line border border-transparent"
              } ${collapsed ? "justify-center" : ""}`}
              style={active ? {
                background: "linear-gradient(90deg, rgba(0,212,255,.08), rgba(0,212,255,.03))",
                boxShadow: "inset 2px 0 0 #00d4ff",
              } : {}}
            >
              <Icon size={15} className="flex-shrink-0" />
              {!collapsed && (
                <span className="text-[12.5px] font-semibold truncate">{label}</span>
              )}
            </button>
          );
        })}
      </nav>

      {/* System status */}
      {!collapsed && (
        <div className="px-3 pb-3">
          <div className="rounded-tile border border-line bg-panel2 px-3 py-2.5">
            <div className="text-[10px] font-bold uppercase tracking-widest text-ink3 mb-2">System</div>
            <div className="flex items-center gap-2">
              <span className="w-1.5 h-1.5 rounded-full bg-neon pulse flex-shrink-0" />
              <span className="text-[11px] text-ink2">Shield active</span>
            </div>
            <div className="flex items-center gap-2 mt-1">
              <span className="w-1.5 h-1.5 rounded-full bg-neon pulse flex-shrink-0" />
              <span className="text-[11px] text-ink2">Scanner online</span>
            </div>
          </div>
        </div>
      )}


    </aside>
  );
}
