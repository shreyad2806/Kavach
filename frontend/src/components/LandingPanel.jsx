import { Shield, Zap } from "lucide-react";
import { Button } from "../ui/Button.jsx";

export function LandingPanel({ task, onTaskChange, onRun, busy = false, error = "" }) {
  const canRun = task.trim().length > 0 && !busy;

  const submit = (e) => {
    e.preventDefault();
    if (!canRun) return;
    onRun();
  };

  return (
    <div className="flex min-h-[72vh] items-center justify-center network-bg">
      <div className="w-full max-w-lg">

        {/* Hero */}
        <div className="text-center mb-8">
          <div className="flex items-center justify-center gap-3 mb-4">
            <div
              className="w-12 h-12 rounded-xl flex items-center justify-center"
              style={{
                background: "linear-gradient(135deg, rgba(0,212,255,.15), rgba(0,100,200,.1))",
                border: "1.5px solid rgba(0,212,255,.35)",
                boxShadow: "0 0 24px rgba(0,212,255,.15)",
              }}
            >
              <Shield size={22} style={{ color: "#00d4ff" }} />
            </div>
          </div>
          <h1
            className="text-[36px] font-extrabold tracking-widest text-ink uppercase"
            style={{ letterSpacing: "0.15em", textShadow: "0 0 30px rgba(0,212,255,.2)" }}
          >
            KAVACH
          </h1>
          <p className="mt-2 text-[12.5px] text-ink3 tracking-wide">
            Zero-Trust Runtime Security for Autonomous Systems
          </p>
        </div>

        {/* Card */}
        <div
          className="rounded-panel border border-line p-6 panel-light"
          style={{
            background: "linear-gradient(160deg, #0e1422, #0b0f1a)",
            boxShadow: "0 0 40px rgba(0,212,255,.06), 0 20px 60px rgba(0,0,0,.4)",
          }}
        >
          <form onSubmit={submit} className="space-y-5">
            <div>
              <div className="flex items-center gap-2 mb-1">
                <Zap size={13} style={{ color: "#00d4ff" }} />
                <h2 className="text-[13.5px] font-bold text-ink">Run a secured agent workflow</h2>
              </div>
              <p className="text-[11.5px] text-ink3 ml-5">
                Every protected operation is authorized by Kavach before it executes.
              </p>
            </div>

            <div>
              <label htmlFor="task" className="block text-[11.5px] font-semibold text-ink3 uppercase tracking-wide mb-1.5">
                Task
              </label>
              <textarea
                id="task"
                rows={3}
                value={task}
                onChange={(e) => onTaskChange(e.target.value)}
                placeholder="Enter a task for the agent team..."
                className="w-full rounded-tile border border-line bg-panel2 px-3 py-2.5 text-[13px] text-ink
                           placeholder:text-ink3 focus:border-neon/50 focus:outline-none resize-none transition-colors"
                style={{ background: "rgba(8,12,21,.6)" }}
              />
            </div>

            <div className="flex items-center gap-3">
              <Button type="submit" size="lg" disabled={!canRun}>
                {busy ? "Starting…" : "Run Workflow"}
              </Button>
              {task.trim().length === 0 && (
                <span className="text-[11.5px] text-ink3">Enter a task to begin.</span>
              )}
            </div>

            {error && (
              <p className="text-[12px] text-danger rounded-tile border border-danger/20 bg-danger/10 px-3 py-2">
                {error}
              </p>
            )}
          </form>
        </div>

        {/* Feature pills */}
        <div className="flex flex-wrap justify-center gap-2 mt-6">
          {["Zero-Trust", "Multi-Agent", "Real-time Shield", "Artifact Scanner", "Cedar Policy"].map((f) => (
            <span
              key={f}
              className="text-[10.5px] font-mono rounded-full border border-line px-3 py-1 text-ink3"
              style={{ background: "rgba(14,20,34,.8)" }}
            >
              {f}
            </span>
          ))}
        </div>
      </div>
    </div>
  );
}
