/**
 * WorkflowPanel — real workflow control over the existing WorkflowSupervisor.
 *
 * POST /api/workflows  → { workflow_id, status: "CREATED" }
 * POST /api/workflows/:id/start  → Workflow summary (synchronous; ~1-3 s)
 * GET  /api/workflows/:id/events → supervisor lifecycle events
 *
 * Shows:
 *   • A "Run Workflow" button that creates and starts a real 5-agent P1 workflow
 *   • Live phase progress as events arrive (PHASE_STARTED, PHASE_COMPLETED)
 *   • Final COMPLETED / FAILED / STOPPED status
 *   • Supervisor lifecycle event log for the last run
 *
 * Does NOT poll continuously — the start call is synchronous so the result
 * arrives in the response.  Events are fetched once the run finishes.
 */
import { useState, useCallback, useRef } from "react";
import { Play, Square, RefreshCw, ChevronDown, ChevronUp } from "lucide-react";
import { Panel } from "../ui/Panel.jsx";
import { Button } from "../ui/Button.jsx";
import { Badge } from "../ui/index.jsx";
import { api } from "../api.js";
import { relativeTime } from "../lib/format.js";

const STATUS_TONE = {
  CREATED:   "neutral",
  RUNNING:   "amber",
  STOPPING:  "amber",
  STOPPED:   "dim",
  COMPLETED: "neon",
  FAILED:    "danger",
};

const PHASE_AGENTS = [
  "orchestrator-01",
  "research-01",
  "coding-01",
  "verification-01",
  "deployment-01",
];

// Derive a compact phase label from supervisor events
function derivePhases(wfEvents) {
  if (!wfEvents || wfEvents.length === 0) return [];
  const phases = [];
  const seen = new Set();
  for (const ev of wfEvents) {
    if (ev.event_type === "PHASE_STARTED" && ev.agent && !seen.has(ev.agent)) {
      seen.add(ev.agent);
      const completed = wfEvents.some(
        (e) => e.event_type === "PHASE_COMPLETED" && e.agent === ev.agent
      );
      phases.push({ agent: ev.agent, completed });
    }
  }
  return phases;
}

export function WorkflowPanel({ onWorkflowComplete }) {
  const [phase,      setPhase]      = useState("idle");   // idle | creating | running | done | error
  const [workflow,   setWorkflow]   = useState(null);      // last Workflow summary
  const [wfEvents,   setWfEvents]   = useState([]);        // supervisor lifecycle events
  const [error,      setError]      = useState("");
  const [showEvents, setShowEvents] = useState(false);
  const [taskInput,  setTaskInput]  = useState("");
  const aborted = useRef(false);

  const runWorkflow = useCallback(async () => {
    const task = taskInput.trim() || "compute fibonacci sequence";
    aborted.current = false;
    setError("");
    setWorkflow(null);
    setWfEvents([]);
    setShowEvents(false);

    // 1. Create
    setPhase("creating");
    let created;
    try {
      created = await api.createWorkflow(task);
    } catch (e) {
      setError(`Create failed: ${e.message}`);
      setPhase("error");
      return;
    }
    if (aborted.current) return;

    setWorkflow(created);
    setPhase("running");

    // 2. Start (synchronous — blocks until COMPLETED/FAILED/STOPPED)
    let result;
    try {
      result = await api.startWorkflow(created.workflow_id);
    } catch (e) {
      setError(`Start failed: ${e.message}`);
      setPhase("error");
      return;
    }
    if (aborted.current) return;

    setWorkflow(result);
    setPhase("done");

    // 3. Fetch supervisor events for the event log
    try {
      const evs = await api.getWorkflowEvents(created.workflow_id);
      setWfEvents(evs);
    } catch {
      // non-fatal — result is already set
    }

    // Notify parent so the security events panel can refresh
    onWorkflowComplete?.();
  }, [taskInput, onWorkflowComplete]);

  const reset = useCallback(() => {
    aborted.current = true;
    setPhase("idle");
    setWorkflow(null);
    setWfEvents([]);
    setError("");
    setShowEvents(false);
  }, []);

  const phases = derivePhases(wfEvents);

  return (
    <Panel className="p-4 flex flex-col gap-3 h-full">
      {/* Header */}
      <div className="flex items-center justify-between gap-2">
        <div className="text-[14px] font-bold text-ink">Workflow</div>
        {(phase === "done" || phase === "error") && (
          <button
            onClick={reset}
            aria-label="Reset workflow"
            className="w-7 h-7 rounded-btn flex items-center justify-center text-ink3 hover:text-ink hover:bg-line transition-colors"
          >
            <RefreshCw size={13} />
          </button>
        )}
      </div>

      {/* Task input */}
      {phase === "idle" && (
        <div className="flex flex-col gap-2">
          <label className="text-[11.5px] text-ink3">Task description</label>
          <input
            type="text"
            value={taskInput}
            onChange={(e) => setTaskInput(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && runWorkflow()}
            placeholder="compute fibonacci sequence"
            className="bg-panel2 border border-line rounded-tile px-3 py-2 text-[12.5px] text-ink placeholder:text-ink3 outline-none focus:border-line2 font-mono"
          />
        </div>
      )}

      {/* Run button */}
      {phase === "idle" && (
        <Button tone="neon" size="md" onClick={runWorkflow} className="w-full">
          <Play size={13} />
          Run workflow
        </Button>
      )}

      {/* Creating */}
      {phase === "creating" && (
        <div className="flex items-center gap-2 text-[12.5px] text-ink2">
          <span className="w-2 h-2 rounded-full bg-amber pulse flex-shrink-0" aria-hidden="true" />
          Creating workflow…
        </div>
      )}

      {/* Running */}
      {phase === "running" && (
        <div className="flex flex-col gap-3">
          <div className="flex items-center gap-2 text-[12.5px] text-amber font-semibold">
            <span className="w-2 h-2 rounded-full bg-amber pulse flex-shrink-0" aria-hidden="true" />
            Running — 5-agent P1 pipeline
          </div>
          {workflow && (
            <div className="text-[11px] font-mono text-ink3 truncate">
              {workflow.workflow_id}
            </div>
          )}
          {/* Animated phase indicators while running */}
          <div className="flex flex-col gap-1.5">
            {PHASE_AGENTS.map((agent) => (
              <div key={agent} className="flex items-center gap-2">
                <span className="w-1.5 h-1.5 rounded-full bg-amber pulse flex-shrink-0" aria-hidden="true" />
                <span className="text-[11.5px] font-mono text-ink3">{agent}</span>
              </div>
            ))}
          </div>
          <div className="text-[11px] text-ink3">
            All protected actions enforced by KavachGuard →
          </div>
        </div>
      )}

      {/* Done */}
      {phase === "done" && workflow && (
        <div className="flex flex-col gap-3">
          {/* Status badge + workflow ID */}
          <div className="flex items-center justify-between gap-2">
            <Badge label={workflow.status} tone={STATUS_TONE[workflow.status] ?? "neutral"} />
            <span className="text-[11px] font-mono text-ink3 truncate">{workflow.workflow_id}</span>
          </div>

          {/* Kavach denial detail */}
          {workflow.status === "FAILED" && workflow.result?.kavach_denied && (
            <div className="rounded-tile bg-danger/10 border border-danger/20 px-3 py-2.5 flex flex-col gap-1">
              <div className="text-[12px] font-semibold text-danger">KavachGuard DENY</div>
              <div className="text-[11.5px] font-mono text-ink2">
                {workflow.result.decision} — {workflow.error}
              </div>
              {workflow.result.reason_codes?.map((rc) => (
                <span
                  key={rc}
                  className="inline-block text-[10.5px] font-mono rounded-md px-2 py-0.5 bg-danger/10 text-danger border border-danger/20 w-fit"
                >
                  {rc}
                </span>
              ))}
            </div>
          )}

          {/* Generic failure */}
          {workflow.status === "FAILED" && !workflow.result?.kavach_denied && workflow.error && (
            <div className="rounded-tile bg-danger/10 border border-danger/20 px-3 py-2 text-[11.5px] text-danger font-mono">
              {workflow.error}
            </div>
          )}

          {/* Phase summary (completed phases) */}
          {phases.length > 0 && (
            <div className="flex flex-col gap-1">
              {phases.map((p) => (
                <div key={p.agent} className="flex items-center gap-2">
                  <span
                    className={`w-1.5 h-1.5 rounded-full flex-shrink-0 ${p.completed ? "bg-neon" : "bg-amber"}`}
                    aria-hidden="true"
                  />
                  <span className="text-[11.5px] font-mono text-ink3">{p.agent}</span>
                  <span className={`text-[10.5px] font-semibold ml-auto ${p.completed ? "text-neon" : "text-amber"}`}>
                    {p.completed ? "done" : "partial"}
                  </span>
                </div>
              ))}
            </div>
          )}

          {/* Timing */}
          {workflow.completed_at && (
            <div className="text-[11px] text-ink3">
              Completed {relativeTime(workflow.completed_at)}
            </div>
          )}

          {/* Event log toggle */}
          {wfEvents.length > 0 && (
            <button
              onClick={() => setShowEvents((v) => !v)}
              className="flex items-center gap-1.5 text-[11.5px] text-ink3 hover:text-ink transition-colors"
            >
              {showEvents ? <ChevronUp size={12} /> : <ChevronDown size={12} />}
              {wfEvents.length} lifecycle events
            </button>
          )}

          {showEvents && (
            <div className="flex flex-col gap-1 max-h-[160px] overflow-y-auto">
              {wfEvents.map((ev) => (
                <div
                  key={ev.event_id}
                  className="flex items-center gap-2 text-[11px] font-mono py-1 border-b border-line last:border-0"
                >
                  <span className="text-ink3 flex-shrink-0 w-20">
                    {new Date(ev.timestamp).toLocaleTimeString()}
                  </span>
                  <span className="text-ink2 truncate">{ev.event_type}</span>
                  {ev.agent && (
                    <span className="text-ink3 truncate ml-auto">{ev.agent}</span>
                  )}
                </div>
              ))}
            </div>
          )}

          {/* New run */}
          <Button tone="outline" size="sm" onClick={reset} className="w-full mt-1">
            New run
          </Button>
        </div>
      )}

      {/* Error */}
      {phase === "error" && (
        <div className="flex flex-col gap-3">
          <div className="rounded-tile bg-danger/10 border border-danger/20 px-3 py-2.5 text-[12px] text-danger">
            {error}
          </div>
          <Button tone="outline" size="sm" onClick={reset} className="w-full">
            Try again
          </Button>
        </div>
      )}
    </Panel>
  );
}
