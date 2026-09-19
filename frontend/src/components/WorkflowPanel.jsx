/**
 * WorkflowPanel — status of the workflow started from the landing screen.
 *
 * It reads the same polled snapshot the rest of the dashboard uses and never
 * triggers work of its own.  The per-agent phases come from the supervisor's
 * own phase records, which are lifecycle telemetry correlated by workflow_id —
 * the security decisions live in Agent activity.
 */
import { Loader2 } from "lucide-react";
import { Panel } from "../ui/Panel.jsx";
import { Badge } from "../ui/index.jsx";
import { relativeTime } from "../lib/format.js";

const STATUS_TONE = {
  CREATED:   "neutral",
  RUNNING:   "amber",
  STOPPING:  "amber",
  STOPPED:   "dim",
  COMPLETED: "neon",
  FAILED:    "danger",
};

export function WorkflowPanel({ snapshot = null, starting = false }) {
  const status = snapshot?.status ?? (starting ? "CREATED" : null);
  const phases = snapshot?.phases ?? [];
  const result = snapshot?.result ?? null;

  return (
    <Panel className="p-4 flex flex-col gap-3 h-full">
      <div className="text-[14px] font-bold text-ink">Workflow</div>

      {!status ? (
        <div className="flex-1 flex items-center justify-center">
          <p className="text-[12.5px] text-ink3">No workflow has been run yet.</p>
        </div>
      ) : (
        <div className="flex flex-col gap-3">
          {/* Status + id */}
          <div className="flex items-center justify-between gap-2">
            <Badge label={status} tone={STATUS_TONE[status] ?? "neutral"} />
            <span className="text-[11px] font-mono text-ink3 truncate">
              {snapshot?.workflow_id ?? "—"}
            </span>
          </div>

          {/* Live progress */}
          {(status === "CREATED" || status === "RUNNING" || status === "STOPPING") && (
            <div className="flex items-center gap-2 text-[12px] text-amber">
              <Loader2 size={12} className="animate-spin flex-shrink-0" />
              {status === "RUNNING"
                ? "Agent workflow running…"
                : status === "STOPPING"
                ? "Stopping after the current operation…"
                : "Starting agent workflow..."}
            </div>
          )}

          {/* Task + real result */}
          <div className="text-[11.5px] text-ink3 leading-relaxed">
            <div className="font-mono text-ink2 break-words">{snapshot?.task}</div>
            {result?.task_kind && (
              <div className="mt-1">
                path: <span className="font-mono text-ink2">{result.task_kind}</span>
              </div>
            )}
            {result?.expression != null && (
              <div className="font-mono mt-1">
                {result.expression} = <span className="text-neon">{String(result.value)}</span>
              </div>
            )}
            {result?.summary && <div className="mt-1 text-ink2">{result.summary}</div>}
          </div>

          {/* Kavach denial detail — a real security outcome, never a success. */}
          {status === "FAILED" && result?.kavach_denied && (
            <div className="rounded-tile bg-danger/10 border border-danger/20 px-3 py-2.5 flex flex-col gap-1">
              <div className="text-[12px] font-semibold text-danger">KavachGuard DENY</div>
              <div className="text-[11.5px] font-mono text-ink2">
                {result.decision} — {snapshot?.error}
              </div>
              {result.reason_codes?.map((rc) => (
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
          {status === "FAILED" && !result?.kavach_denied && snapshot?.error && (
            <div className="rounded-tile bg-danger/10 border border-danger/20 px-3 py-2 text-[11.5px] text-danger font-mono">
              {snapshot.error}
            </div>
          )}

          {/* Real per-agent phases */}
          {phases.length > 0 && (
            <div className="flex flex-col gap-1">
              {phases.map((p) => (
                <div key={`${p.agent}-${p.started_at}`} className="flex items-center gap-2">
                  <span
                    className={`w-1.5 h-1.5 rounded-full flex-shrink-0 ${
                      p.status === "COMPLETED" ? "bg-neon" : p.status === "FAILED" ? "bg-danger" : "bg-amber"
                    }`}
                    aria-hidden="true"
                  />
                  <span className="text-[11.5px] font-mono text-ink3">{p.agent}</span>
                  <span
                    className={`text-[10.5px] font-semibold ml-auto ${
                      p.status === "COMPLETED" ? "text-neon" : p.status === "FAILED" ? "text-danger" : "text-amber"
                    }`}
                  >
                    {p.status === "COMPLETED" ? "done" : p.status === "FAILED" ? "failed" : "running"}
                  </span>
                </div>
              ))}
            </div>
          )}

          {/* Timing */}
          {snapshot?.completed_at && (
            <div className="text-[11px] text-ink3">
              Completed {relativeTime(snapshot.completed_at)}
            </div>
          )}
        </div>
      )}
    </Panel>
  );
}
