/**
 * App — Kavach demo shell.
 *
 * ONE persistent application shell:
 *
 *   <Sidebar />            always mounted (landing, running, completed, attack)
 *   <TopBar />             always mounted
 *   main content           landing OR dashboard
 *
 * The landing screen and the runtime dashboard are two states of the SAME
 * application.  The shell is never unmounted because a workflow exists.
 *
 * Data rules enforced here:
 *   - The landing screen renders only the task input and Run Workflow.  The
 *     task starts EMPTY and nothing runs until the button is pressed.
 *   - Every value on the dashboard is a projection of the CURRENT workflow
 *     session (events scoped to this workflow_id + live Shield agent states).
 *     The permanent audit log is never read for display.
 *   - Exactly one selected request id.  Activity rows set it; the pipeline and
 *     Agent Control both derive from it.  Nothing picks its own event.
 *   - All API responses are normalised explicitly, so an unexpected shape can
 *     never throw during render.
 */
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { TopBar } from "./components/TopBar.jsx";
import { Sidebar } from "./components/Sidebar.jsx";
import { LandingPanel } from "./components/LandingPanel.jsx";
import { SecurityTestPanel } from "./components/SecurityTestPanel.jsx";
import { DashboardPage } from "./pages/DashboardPage.jsx";
import { ScannerPage } from "./pages/ScannerPage.jsx";
import { useKavach } from "./hooks/useKavach.js";
import { api } from "./api.js";
import { asArrayOfOne, normalizeAgents, normalizeEvents } from "./lib/shape.js";

// Merge the current workflow's events with the attack-session events, newest
// first, de-duplicated by request_id.
//
// The workflow contributes an ARRAY of events; the attack response contributes
// two SINGLE events.  Both shapes are normalised before iteration, so a single
// event is never treated as a list.
export function mergeEvents(...sources) {
  const byRequest = new Map();
  for (const source of sources) {
    for (const event of asArrayOfOne(source)) {
      if (event?.request_id && !byRequest.has(event.request_id)) {
        byRequest.set(event.request_id, event);
      }
    }
  }
  return [...byRequest.values()].sort(
    (a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime(),
  );
}

// Human-readable message for a classified API error.
function messageFor(err) {
  switch (err?.kind) {
    case "offline":      return "Backend unreachable — is the local API running?";
    case "unauthorized": return "Unauthorized — check the API key.";
    case "rate_limited": return "Rate limited — try again in a moment.";
    case "server":       return "Backend error while starting the workflow.";
    default:             return err?.message || "Request failed.";
  }
}

export default function App() {
  const { snapshot, error: pollError, track, untrack, refresh } = useKavach();

  const [page, setPage] = useState("dashboard");
  const [collapsed, setCollapsed] = useState(true);

  // "landing" | "dashboard" — in memory only, so a reload always starts clean.
  const [view, setView] = useState("landing");

  // The task input starts EMPTY.  Nothing is prefilled.
  const [task, setTask] = useState("");
  const [starting, setStarting] = useState(false);
  const [runError, setRunError] = useState("");

  // Exactly one selected request id, plus whether the operator chose it.
  const [selectedRequestId, setSelectedRequestId] = useState(null);
  const [userSelected, setUserSelected] = useState(false);

  // Agent Control follows the selected event's source agent.  A Fleet/Agent
  // Control click overrides that until the next event is selected — there is no
  // hardcoded default agent.
  const [manualAgentId, setManualAgentId] = useState(null);

  const [attack, setAttack] = useState(null);
  const [attacking, setAttacking] = useState(false);
  const [attackError, setAttackError] = useState("");
  const [resetting, setResetting] = useState(false);

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

  // A fresh browser session starts a fresh demo session: all five agents
  // ACTIVE, no previous telemetry, workflow, quarantine or incidents.  This
  // issues no authorization request, so it emits no security telemetry.
  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        await api.resetDemoSession();
      } catch {
        // Backend unreachable — the landing screen still renders.
      }
      if (!cancelled) clearSelection();
    })();
    return () => { cancelled = true; };
  }, [clearSelection]);

  // ---- Derived session view ------------------------------------------------

  const status = snapshot?.status ?? null;

  // Only current-session events.  The workflow's events arrive already scoped
  // to its workflow_id; the attack decisions come with the attack response.
  const events = useMemo(
    () =>
      mergeEvents(
        normalizeEvents(snapshot),
        attack?.attack?.event,
        attack?.post_quarantine?.event,
      ),
    [snapshot, attack],
  );

  // Live Shield agent states.  After the attack, the response carries the
  // post-quarantine snapshot (the workflow is already terminal by then).
  const agents = useMemo(() => {
    const fromAttack = normalizeAgents(attack);
    return fromAttack.length > 0 ? fromAttack : normalizeAgents(snapshot);
  }, [attack, snapshot]);

  const newestRequestId = events[0]?.request_id ?? null;

  // Auto-follow the newest decision until the operator picks a row.  Once they
  // click, the selection is theirs and never moves on its own.
  useEffect(() => {
    if (view !== "dashboard") return;
    if (userSelected) return;
    if (!newestRequestId) return;
    if (selectedRequestId !== newestRequestId) setSelectedRequestId(newestRequestId);
  }, [view, userSelected, newestRequestId, selectedRequestId]);

  // ---- Actions -------------------------------------------------------------

  const runWorkflow = useCallback(async () => {
    const trimmed = task.trim();
    if (!trimmed) {
      setRunError("Enter a task to run.");
      return;
    }

    setStarting(true);
    setRunError("");
    setAttack(null);
    setAttackError("");
    clearSelection();

    // Transition to the dashboard immediately — the workflow runs in the
    // backend and streams its real decisions in as they are made.
    setView("dashboard");

    try {
      // 1. Clean session: all five agents ACTIVE, telemetry and workflows clear.
      await api.resetDemoSession();
      // 2. Create the workflow (does not execute it).
      const created = await api.createWorkflow(trimmed);
      // 3. Track it — the single polled source of truth.
      track(created.workflow_id);
      // 4. Start it. Returns immediately with RUNNING; the phases continue in
      //    the backend on a worker thread.
      await api.startWorkflow(created.workflow_id);
    } catch (err) {
      if (unmounted.current) return;
      setRunError(messageFor(err));
      setView("landing");
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
      // Focus the pipeline on the attack request itself, and keep it there.
      // Agent Control then follows that request's source agent (research-01).
      setSelectedRequestId(result?.attack?.request_id ?? null);
      setUserSelected(true);
      setManualAgentId(null);
    } catch (err) {
      if (!unmounted.current) setAttackError(messageFor(err));
    } finally {
      if (!unmounted.current) setAttacking(false);
    }
  }, []);

  const runAgain = useCallback(async () => {
    setResetting(true);
    try {
      await api.resetDemoSession();
    } catch {
      // Best effort — local state is cleared regardless.
    }
    if (unmounted.current) return;
    untrack();
    setAttack(null);
    setAttackError("");
    setRunError("");
    setTask("");
    clearSelection();
    setPage("dashboard");
    setView("landing");
    if (!unmounted.current) setResetting(false);
  }, [untrack, clearSelection]);

  const handleEventSelect = useCallback((requestId) => {
    setSelectedRequestId(requestId);
    setUserSelected(true);
    // Agent Control follows the selected event from here on.
    setManualAgentId(null);
  }, []);

  // ---- Render --------------------------------------------------------------
  // ONE shell: the sidebar and top bar are always present.

  return (
    <div className="flex min-h-screen w-full">
      <Sidebar
        activePage={page}
        onNavigate={setPage}
        collapsed={collapsed}
        onToggle={() => setCollapsed((v) => !v)}
      />

      <div className="flex flex-col flex-1 min-w-0 overflow-x-hidden">
        <TopBar
          errorKind={pollError?.kind ?? null}
          connected={!pollError}
          loading={!snapshot && starting}
          onRefresh={view === "dashboard" ? refresh : undefined}
        />

        <main className="flex-1 px-4 py-4 overflow-y-auto">
          <div className="mx-auto max-w-[1400px]">
            {page === "scanner" ? (
              <ScannerPage />
            ) : view === "landing" ? (
              <LandingPanel
                task={task}
                onTaskChange={setTask}
                onRun={runWorkflow}
                busy={starting}
                error={runError}
              />
            ) : (
              <DashboardPage
                snapshot={snapshot}
                events={events}
                agents={agents}
                starting={starting}
                selectedRequestId={selectedRequestId}
                onEventSelect={handleEventSelect}
                manualAgentId={manualAgentId}
                onAgentSelect={setManualAgentId}
                onMutate={refresh}
              >
                <SecurityTestPanel
                  status={status}
                  attack={attack}
                  onAttack={simulateAttack}
                  attacking={attacking}
                  error={attackError}
                  onRunAgain={runAgain}
                  resetting={resetting}
                />
              </DashboardPage>
            )}
          </div>
        </main>

        <footer className="text-center text-[11px] text-ink3 py-2 font-mono border-t border-line" style={{ background: "#080c15" }}>
          kavach · zero-trust runtime security ·{" "}
          {pollError ? "backend error" : "backend connected"}
        </footer>
      </div>
    </div>
  );
}
