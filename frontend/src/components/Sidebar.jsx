import { LayoutDashboard, ScanLine, ChevronLeft, ChevronRight } from "lucide-react";

const NAV_ITEMS = [
  { id: "dashboard", label: "Dashboard",       Icon: LayoutDashboard },
  { id: "scanner",   label: "Artifact Scanner", Icon: ScanLine        },
];

export function Sidebar({ activePage, onNavigate, collapsed, onToggle }) {
  return (
    <aside
      className={`flex flex-col border-r border-line bg-panel transition-all duration-200 flex-shrink-0 ${
        collapsed ? "w-[56px]" : "w-[200px]"
      }`}
      style={{ minHeight: "100vh" }}
    >
      {/* Logo */}
      <div className={`flex items-center gap-2.5 px-3 py-4 border-b border-line ${collapsed ? "justify-center" : ""}`}>
        <div
          className="w-8 h-8 rounded-full flex items-center justify-center font-extrabold text-[12px] text-deep bg-neon flex-shrink-0"
          style={{ boxShadow: "0 0 0 2px #04120d, 0 0 0 3px #1fe98a" }}
        >
          KV
        </div>
        {!collapsed && (
          <div className="leading-tight min-w-0">
            <div className="text-[13px] font-bold text-ink">Kavach</div>
            <div className="text-[10.5px] text-ink3">Zero-trust security</div>
          </div>
        )}
      </div>

      {/* Nav items */}
      <nav className="flex flex-col gap-1 p-2 flex-1">
        {NAV_ITEMS.map(({ id, label, Icon }) => {
          const active = activePage === id;
          return (
            <button
              key={id}
              onClick={() => onNavigate(id)}
              title={collapsed ? label : undefined}
              className={`flex items-center gap-2.5 rounded-tile px-2.5 py-2.5 text-left transition-colors w-full ${
                active
                  ? "bg-neon/10 border border-neon/20 text-neon"
                  : "text-ink3 hover:text-ink2 hover:bg-line border border-transparent"
              } ${collapsed ? "justify-center" : ""}`}
            >
              <Icon size={16} className="flex-shrink-0" />
              {!collapsed && (
                <span className="text-[12.5px] font-semibold truncate">{label}</span>
              )}
            </button>
          );
        })}
      </nav>

      {/* Collapse toggle */}
      <button
        onClick={onToggle}
        title={collapsed ? "Expand sidebar" : "Collapse sidebar"}
        className={`flex items-center gap-2 px-3 py-3 border-t border-line text-ink3 hover:text-ink2 transition-colors ${
          collapsed ? "justify-center" : ""
        }`}
      >
        {collapsed
          ? <ChevronRight size={14} />
          : <><ChevronLeft size={14} /><span className="text-[11.5px]">Collapse</span></>
        }
      </button>
    </aside>
  );
}
