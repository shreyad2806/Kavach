/**
 * App — Kavach shell with sidebar navigation.
 *
 * Pages:
 *   dashboard — live security overview (agents, events, incidents, workflow)
 *   scanner   — artifact pre-execution scanner
 *
 * Real-time: useKavach() polls /agents, /events, /incidents, /dashboard every 5 s.
 */
import { useState } from "react";
import { TopBar }         from "./components/TopBar.jsx";
import { Sidebar }        from "./components/Sidebar.jsx";
import { DashboardPage }  from "./pages/DashboardPage.jsx";
import { ScannerPage }    from "./pages/ScannerPage.jsx";
import { useKavach }      from "./hooks/useKavach.js";

export default function App() {
  const { agents, events, incidents, dashboard, connected, offline, loading, refresh } =
    useKavach();

  const [page,      setPage]      = useState("dashboard");
  const [collapsed, setCollapsed] = useState(false);

  return (
    <div className="flex min-h-screen w-full">

      {/* Sidebar */}
      <Sidebar
        activePage={page}
        onNavigate={setPage}
        collapsed={collapsed}
        onToggle={() => setCollapsed(v => !v)}
      />

      {/* Main content */}
      <div className="flex flex-col flex-1 min-w-0 overflow-x-hidden">

        {/* Top bar */}
        <TopBar
          connected={connected}
          offline={offline}
          loading={loading}
          onRefresh={refresh}
        />

        {/* Page content */}
        <main className="flex-1 px-4 py-4 overflow-y-auto">
          <div className="mx-auto max-w-[1400px]">
            {page === "dashboard" && (
              <DashboardPage
                agents={agents}
                events={events}
                incidents={incidents}
                dashboard={dashboard}
                loading={loading}
                refresh={refresh}
              />
            )}
            {page === "scanner" && (
              <ScannerPage />
            )}
          </div>
        </main>

        {/* Footer */}
        <footer className="text-center text-[11px] text-ink3 py-2 font-mono border-t border-line">
          kavach · zero-trust runtime security ·{" "}
          {connected ? "backend connected" : offline ? "backend offline" : "connecting…"}
        </footer>
      </div>
    </div>
  );
}
