import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Shield } from "lucide-react";
import { TopBar } from "./components/TopBar.jsx";
import { Sidebar } from "./components/Sidebar.jsx";
import { LandingPanel, RunWorkflowPanel } from "./components/LandingPanel.jsx";
import { SecurityTestPanel } from "./components/SecurityTestPanel.jsx";
import { DashboardPage } from "./pages/DashboardPage.jsx";
import { ScannerPage } from "./pages/ScannerPage.jsx";
import { useKavach } from "./hooks/useKavach.js";
import { api } from "./api.js";
import { asArrayOfOne, normalizeAgents, normalizeEvents } from "./lib/shape.js";

export function mergeEvents(...sources) {
  const byRequest = new Map();
  for (const source of sources) {
    for (const event of asArrayOfOne(source)) {
      if (event?.request_id && !byRequest.has(event.request_id)) byRequest.set(event.request_id, event);
    }
  }
  return [...byRequest.values()].sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
}

function messageFor(err) {
  switch (err?.kind) {
    case "offline": return "Backend unreachable — is the API available?";
    case "unauthorized": return "Unauthorized — check the API key.";
    case "rate_limited": return "Rate limited — try again in a moment.";
    case "server": return "Backend error while starting the workflow.";
    default: return err?.message || "Request failed.";
  }
}

export default function App() {
  const { snapshot, error: pollError, track, untrack, refresh } = useKavach();
  const [page, setPage] = useState("dashboard");
  const [collapsed, setCollapsed] = useState(true);
  // Shield is the default experience. The workflow composer is a separate view.
  const [view, setView] = useState("shield");
  const [task, setTask] = useState("");
  const [starting, setStarting] = useState(false);
  const [runError, setRunError] = useState("");
  const [selectedRequestId, setSelectedRequestId] = useState(null);
  const [userSelected, setUserSelected] = useState(false);
  const [manualAgentId, setManualAgentId] = useState(null);
  const [attack, setAttack] = useState(null);
  const [attacking, setAttacking] = useState(false);
  const [attackError, setAttackError] = useState("");
  const [resetting, setResetting] = useState(false);
  const [fleet, setFleet] = useState([]);
  const [sessionEvents, setSessionEvents] = useState([]);
  const [fleetError, setFleetError] = useState("");
  const unmounted = useRef(false);

  useEffect(() => {
    unmounted.current = false;
    return () => { unmounted.current = true; };
  }, []);

  const clearSelection = useCallback(() => {
    setSelectedRequestId(null);
    setUserSelected(false);
    setManualAgentId(null);
  }, []);

  const loadShieldState = useCallback(async () => {
    try {
      const [agentData, eventData] = await Promise.all([api.getAgents(), api.getEvents()]);
      if (unmounted.current) return;
      setFleet(normalizeAgents(agentData));
      setSessionEvents(normalizeEvents(eventData));
      setFleetError("");
    } catch (err) {
      if (!unmounted.current) setFleetError(messageFor(err));
    }
  }, []);

  useEffect(() => {
    loadShieldState();
    const timer = window.setInterval(loadShieldState, 5000);
    return () => window.clearInterval(timer);
  }, [loadShieldState]);

  const status = snapshot?.status ?? null;
  const events = useMemo(
    () => mergeEvents(sessionEvents, normalizeEvents(snapshot), attack?.attack?.event, attack?.post_quarantine?.event),
    [sessionEvents, snapshot, attack],
  );
  const agents = useMemo(() => {
    const fromAttack = normalizeAgents(attack);
    const fromSnapshot = normalizeAgents(snapshot);
    return fromAttack.length ? fromAttack : fromSnapshot.length ? fromSnapshot : fleet;
  }, [attack, snapshot, fleet]);

  useEffect(() => {
    if (view !== "dashboard" || userSelected || !events[0]?.request_id) return;
    if (selectedRequestId !== events[0].request_id) setSelectedRequestId(events[0].request_id);
  }, [view, userSelected, events, selectedRequestId]);

  const runWorkflow = useCallback(async () => {
    const trimmed = task.trim();
    if (!trimmed) { setRunError("Enter a workflow objective."); return; }
    setStarting(true);
    setRunError("");
    setAttack(null);
    setAttackError("");
    clearSelection();
    setView("dashboard");
    try {
      const created = await api.createWorkflow(trimmed);
      track(created.workflow_id);
      await api.startWorkflow(created.workflow_id);
    } catch (err) {
      if (!unmounted.current) {
        setRunError(messageFor(err));
        setView("run");
      }
    } finally {
      if (!unmounted.current) setStarting(false);
    }
  }, [task, track, clearSelection]);

  const simulateAttack = useCallback(async () => {
    setAttacking(true);
    setAttackError("");
    try {
      const result = await api.simulateAttack();
      if (unmounted.current) return;
      setAttack(result);
      setSelectedRequestId(result?.attack?.request_id ?? null);
      setUserSelected(true);
      setManualAgentId(null);
      await loadShieldState();
    } catch (err) {
      if (!unmounted.current) setAttackError(messageFor(err));
    } finally {
      if (!unmounted.current) setAttacking(false);
    }
  }, [loadShieldState]);

  const runAgain = useCallback(async () => {
    setResetting(true);
    try { await api.resetDemoSession(); } catch { /* best effort */ }
    if (unmounted.current) return;
    untrack();
    setAttack(null);
    setAttackError("");
    setRunError("");
    setTask("");
    clearSelection();
    setSessionEvents([]);
    await loadShieldState();
    setView("shield");
    setPage("dashboard");
    setResetting(false);
  }, [untrack, clearSelection, loadShieldState]);

  const handleEventSelect = useCallback((eventOrId) => {
    const id = typeof eventOrId === "string" ? eventOrId : eventOrId?.request_id;
    setSelectedRequestId(id ?? null);
    setUserSelected(true);
    setManualAgentId(null);
  }, []);

  const handleRefresh = useCallback(async () => {
    await Promise.all([refresh(), loadShieldState()]);
  }, [refresh, loadShieldState]);

  return (
    <div className="flex min-h-screen w-full">
      <Sidebar activePage={page} onNavigate={setPage} collapsed={collapsed} onToggle={() => setCollapsed(v => !v)} />
      <div className="flex flex-col flex-1 min-w-0 overflow-x-hidden">
        <TopBar errorKind={pollError?.kind ?? (fleetError ? "offline" : null)} connected={!pollError && !fleetError} loading={false} onRefresh={handleRefresh} />
        <main className="flex-1 px-4 py-5 sm:px-6 overflow-y-auto">
          <div className="mx-auto max-w-[1440px]">
            {page === "scanner" ? <ScannerPage /> : view === "run" ? (
              <RunWorkflowPanel task={task} onTaskChange={setTask} onRun={runWorkflow} busy={starting} error={runError} onBack={() => setView("shield")} />
            ) : view === "dashboard" ? (
              <DashboardPage
                snapshot={snapshot} events={events} agents={agents} starting={starting}
                selectedRequestId={selectedRequestId} onEventSelect={handleEventSelect}
                manualAgentId={manualAgentId} onAgentSelect={setManualAgentId}
                onMutate={handleRefresh}
              >
                <SecurityTestPanel status={status} attack={attack} onAttack={simulateAttack} attacking={attacking} error={attackError} onRunAgain={runAgain} resetting={resetting} />
              </DashboardPage>
            ) : (
              <LandingPanel
                task={task} onTaskChange={setTask} onRun={runWorkflow} busy={starting}
                error={fleetError} agents={agents} events={events}
                connected={!pollError && !fleetError}
                onOpenRunWorkflow={() => { setRunError(""); setView("run"); }}
                onInspectEvent={(event) => { setSelectedRequestId(event.request_id); setUserSelected(true); setView("dashboard"); }}
                onAgentSelect={(id) => { setManualAgentId(id); setPage("dashboard"); setView("dashboard"); }}
              />
            )}
          </div>
        </main>
        <footer className="flex items-center justify-center gap-2 text-[10px] text-slate-600 py-3 border-t border-white/[.06]">
          <Shield size={11} className="text-cyan-400/70" /> KAVACH <span className="text-slate-700">/</span> ZERO-TRUST RUNTIME SECURITY <span className="text-slate-700">/</span> {pollError || fleetError ? "CONTROL PLANE DEGRADED" : "CONTROL PLANE CONNECTED"}
        </footer>
      </div>
    </div>
  );
}
