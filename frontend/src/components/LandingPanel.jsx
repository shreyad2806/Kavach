import { Panel } from "../ui/Panel.jsx";
import { Button } from "../ui/Button.jsx";

/**
 * The only thing visible on a fresh page load.
 *
 * Deliberately minimal: no counters, no events, no fleet, no security test.
 * The task input starts EMPTY — nothing is prefilled, nothing is fetched and
 * nothing runs until the operator types a task and presses Run Workflow.
 */
export function LandingPanel({ task, onTaskChange, onRun, busy = false, error = "" }) {
  const canRun = task.trim().length > 0 && !busy;

  const submit = (e) => {
    e.preventDefault();
    if (!canRun) return;
    onRun();
  };

  return (
    <div className="flex min-h-[68vh] items-center justify-center">
      <div className="w-full max-w-xl">
        <div className="text-center mb-8">
          <h1 className="text-[34px] font-extrabold tracking-tight text-ink">KAVACH</h1>
          <p className="mt-2 text-[13px] text-ink3">
            Zero-Trust Runtime Security for Autonomous Systems
          </p>
        </div>

        <Panel className="p-6">
          <form onSubmit={submit} className="space-y-5">
            <div>
              <h2 className="text-card-title text-ink">Run a secured agent workflow</h2>
              <p className="mt-1 text-caption text-ink3">
                Every protected operation is authorized by Kavach before it executes.
              </p>
            </div>

            <div>
              <label htmlFor="task" className="block text-[12.5px] font-semibold text-ink2 mb-1.5">
                Task
              </label>
              <textarea
                id="task"
                rows={3}
                value={task}
                onChange={(e) => onTaskChange(e.target.value)}
                placeholder="Enter a task for the agent team..."
                className="w-full rounded-tile border border-line2 bg-panel2 px-3 py-2 text-[13px] text-ink
                           placeholder:text-ink3 focus:border-neon focus:outline-none resize-none"
              />
            </div>

            <div className="flex items-center gap-3">
              <Button type="submit" size="lg" disabled={!canRun}>
                {busy ? "Starting…" : "Run Workflow"}
              </Button>
              {task.trim().length === 0 && (
                <span className="text-caption text-ink3">Enter a task to begin.</span>
              )}
            </div>

            {error && (
              <p className="text-caption text-danger rounded-tile border border-danger/20 bg-danger/10 px-3 py-2">
                {error}
              </p>
            )}
          </form>
        </Panel>
      </div>
    </div>
  );
}
