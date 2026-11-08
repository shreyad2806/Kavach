import {
  Activity, ArrowRight, ArrowUpRight, Clock3, Command, Fingerprint,
  LockKeyhole, Network, Plus, Radio, Shield, ShieldCheck, ShieldAlert,
  TerminalSquare, Zap,
} from "lucide-react";
import { Panel } from "../ui/Panel.jsx";
import { Button } from "../ui/Button.jsx";
import { Badge } from "../ui/index.jsx";
import { relativeTime, stateTone, decisionTone, riskColor } from "../lib/format.js";

const SECTIONS = [
  { key: "identity", label: "Identity" },
  { key: "agent_state", label: "Agent state" },
  { key: "capability", label: "Capabilities" },
  { key: "provenance", label: "Provenance" },
  { key: "cedar", label: "Cedar policy" },
  { key: "deterministic_rules", label: "Runtime rules" },
];

function Stat({ label, value, detail, tone = "default", icon: Icon }) {
  const t = {
    default: "text-slate-100",
    green: "text-emerald-300",
    red: "text-rose-300",
    amber: "text-amber-200",
  }[tone];
  return (
    <Panel className="p-4 min-h-[116px] flex flex-col justify-between">
      <div className="flex items-center justify-between gap-2">
        <span className="text-[11px] font-semibold tracking-[.13em] uppercase text-slate-500">{label}</span>
        {Icon && <Icon size={15} className="text-slate-500" />}
      </div>
      <div className="flex items-end justify-between gap-2">
        <span className={`text-[30px] leading-none font-semibold tracking-tight ${t}`}>{value}</span>
        {detail && <span className="text-[11px] text-slate-500 text-right">{detail}</span>}
      </div>
    </Panel>
  );
}

function EmptyState({ title, description }) {
  return (
    <div className="flex flex-col items-center justify-center text-center py-10 px-5">
      <div className="w-11 h-11 rounded-2xl border border-cyan-400/20 bg-cyan-400/[.06] flex items-center justify-center mb-3">
        <Activity size={18} className="text-cyan-300" />
      </div>
      <div className="text-sm font-semibold text-slate-200">{title}</div>
      <p className="text-xs text-slate-500 mt-1 max-w-sm">{description}</p>
    </div>
  );
}

function DecisionRow({ event, selected, onClick }) {
  const denied = event.policy_decision === "DENY";
  const score = event.risk_score;
  return (
    <button
      onClick={onClick}
      className={`w-full grid grid-cols-[minmax(0,1.5fr)_minmax(0,1fr)_92px_72px] gap-3 items-center px-3 py-3 text-left border-b border-white/[.045] transition-colors ${selected ? "bg-cyan-400/[.075]" : "hover:bg-white/[.025]"}`}
    >
      <div className="min-w-0">
        <div className="flex items-center gap-2 min-w-0">
          <span className={`w-1.5 h-1.5 rounded-full flex-shrink-0 ${denied ? "bg-rose-400" : "bg-emerald-400"}`} />
          <span className="font-mono text-[12px] text-slate-200 truncate">{event.source_agent}</span>
        </div>
        <div className="font-mono text-[11px] text-slate-500 mt-1 truncate">{event.action} <span className="text-slate-700">/</span> {event.resource}</div>
      </div>
      <div className="min-w-0">
        <div className="text-[11px] text-slate-400 truncate">{event.reason_codes?.[0]?.replaceAll("_", " ") || "Policy evaluation complete"}</div>
        <div className="text-[10px] text-ink3 mt-1">{relativeTime(event.timestamp)}</div>
      </div>
      <Badge label={event.policy_decision} tone={decisionTone(event.policy_decision)} />
      <div className="text-right">
        <span className="font-mono text-sm font-semibold" style={{ color: score == null ? "#64748b" : riskColor(score) }}>{score ?? "—"}</span>
        <div className="text-[9px] tracking-wider text-ink3 uppercase">risk</div>
      </div>
    </button>
  );
}

function PipelineCard({ event }) {
  const checks = event?.checks ?? {};
  return (
    <Panel className="p-4">
      <div className="flex items-center justify-between mb-4">
        <div>
          <div className="text-sm font-semibold text-slate-100">Authorization trace</div>
          <div className="text-[11px] text-slate-500 mt-1">Per-request zero-trust evaluation</div>
        </div>
        {event && <Badge label={event.policy_decision} tone={decisionTone(event.policy_decision)} />}
      </div>
      {!event ? (
        <EmptyState title="No request selected" description="Choose a decision from the activity stream to inspect every authorization gate." />
      ) : (
        <>
          <div className="flex flex-wrap gap-2">
            {SECTIONS.map((step, i) => {
              const status = checks[step.key] || "NOT_EVALUATED";
              const pass = status === "PASS" || status === "ALLOW";
              const fail = status === "FAIL" || status === "DENY" || status === "BLOCK";
              return (
                <div key={step.key} className="flex items-center gap-2">
                  <div className={`min-w-[102px] rounded-xl border px-2.5 py-2 ${pass ? "border-emerald-400/20 bg-emerald-400/[.06]" : fail ? "border-rose-400/25 bg-rose-400/[.06]" : "border-white/[.07] bg-white/[.02]"}`}>
                    <div className={`text-[10px] font-semibold ${pass ? "text-emerald-300" : fail ? "text-rose-300" : "text-slate-500"}`}>{step.label}</div>
                    <div className="text-[9px] font-mono mt-1 text-slate-500">{status.replaceAll("_", " ")}</div>
                  </div>
                  {i !== SECTIONS.length - 1 && <ArrowRight size={12} className="text-slate-700 hidden lg:block" />}
                </div>
              );
            })}
          </div>
          <div className="mt-4 pt-3 border-t border-white/[.06] grid grid-cols-2 gap-3 text-[11px]">
            <div><span className="text-ink3">Request ID</span><div className="font-mono text-slate-400 mt-1 truncate">{event.request_id}</div></div>
            <div><span className="text-ink3">Task ID</span><div className="font-mono text-slate-400 mt-1 truncate">{event.task_id}</div></div>
          </div>
          {event.reason_codes?.length > 0 && (
            <div className="flex flex-wrap gap-1.5 mt-3">
              {event.reason_codes.map(code => <span key={code} className="rounded-md border border-rose-400/15 bg-rose-400/[.06] px-2 py-1 text-[9px] font-mono text-rose-200/80">{code}</span>)}
            </div>
          )}
        </>
      )}
    </Panel>
  );
}

function FleetCard({ agents, onAgentSelect, selectedAgent }) {
  return (
    <Panel className="p-4">
      <div className="flex items-center justify-between mb-3">
        <div><div className="text-sm font-semibold text-slate-100">Agent fleet</div><div className="text-[11px] text-slate-500 mt-1">Registered identities and current state</div></div>
        <span className="text-[10px] font-mono text-slate-500">{agents.length} registered</span>
      </div>
      {agents.length === 0 ? <EmptyState title="Fleet data unavailable" description="The dashboard will populate when the API returns registered agent identities." /> : (
        <div className="space-y-1">
          {agents.map(agent => (
            <button key={agent.agent_id} onClick={() => onAgentSelect?.(agent.agent_id)} className={`w-full flex items-center gap-3 rounded-xl px-3 py-2.5 text-left border transition-colors ${selectedAgent === agent.agent_id ? "bg-cyan-400/[.06] border-cyan-400/20" : "border-transparent hover:bg-white/[.025]"}`}>
              <span className={`w-2 h-2 rounded-full ${agent.state === "ACTIVE" ? "bg-emerald-400" : agent.state === "QUARANTINED" ? "bg-rose-400" : "bg-amber-300"}`} />
              <span className="min-w-0 flex-1">
                <span className="block text-[12px] font-mono text-slate-200">{agent.agent_id}</span>
                <span className="block text-[10px] text-slate-500 capitalize">{agent.role || "autonomous agent"}</span>
              </span>
              <Badge label={agent.state} tone={stateTone(agent.state)} />
            </button>
          ))}
        </div>
      )}
    </Panel>
  );
}

export function LandingPanel({
  task, onTaskChange, onRun, busy = false, error = "",
  agents = [], events = [], connected = true, selectedRequestId = null, onInspectEvent, onAgentSelect,
  onOpenRunWorkflow,
}) {
  const allowCount = events.filter(e => e.policy_decision === "ALLOW").length;
  const denyCount = events.filter(e => e.policy_decision === "DENY").length;
  const quarantined = agents.filter(a => a.state === "QUARANTINED").length;
  const latest = events.slice(0, 5);

  const submit = (e) => {
    e.preventDefault();
    if (task.trim() && !busy) onRun();
  };

  return (
    <div className="max-w-[1440px] mx-auto space-y-5 pb-8">
      <div className="flex flex-col md:flex-row md:items-end justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 text-[10px] font-bold uppercase tracking-[.2em] text-cyan-300/80 mb-2">
            <span className="w-1.5 h-1.5 rounded-full bg-cyan-300 animate-pulse" />
            Runtime protection / operator console
          </div>
          <h1 className="text-[26px] sm:text-[32px] font-semibold tracking-tight text-slate-100">Shield overview</h1>
          <p className="text-[13px] text-slate-400 mt-1 max-w-xl">Observe agent behaviour, inspect authorization decisions, and contain compromised identities before their next action executes.</p>
        </div>
        <Button size="lg" onClick={onOpenRunWorkflow} disabled={busy}>
          <Plus size={15} /> Run workflow <ArrowUpRight size={14} />
        </Button>
      </div>

      <div className="grid grid-cols-2 xl:grid-cols-4 gap-3">
        <Stat label="Registered agents" value={agents.length || "—"} detail="Identity registry" icon={Fingerprint} />
        <Stat label="Allowed requests" value={allowCount} detail="Current session" tone="green" icon={ShieldCheck} />
        <Stat label="Denied requests" value={denyCount} detail="Enforcement decisions" tone={denyCount ? "red" : "default"} icon={ShieldAlert} />
        <Stat label="Quarantined" value={quarantined} detail="Isolated identities" tone={quarantined ? "red" : "default"} icon={LockKeyhole} />
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-[minmax(0,1.65fr)_minmax(320px,.9fr)] gap-3">
        <Panel className="overflow-hidden">
          <div className="flex items-center justify-between px-4 py-4 border-b border-white/[.06]">
            <div><div className="text-sm font-semibold text-slate-100">Runtime decisions</div><div className="text-[11px] text-slate-500 mt-1">Latest authorization events · select a row to inspect</div></div>
            <div className="flex items-center gap-1.5 text-[10px] text-slate-500"><Radio size={12} className="text-cyan-300" /> Live session</div>
          </div>
          {latest.length === 0 ? (
            <EmptyState title="Shield is standing by" description="No authorization events are recorded in this session yet. Run a workflow or the adversarial scenario to watch real decisions arrive here." />
          ) : (
            <>
              <div className="hidden sm:grid grid-cols-[minmax(0,1.5fr)_minmax(0,1fr)_92px_72px] gap-3 px-3 py-2 text-[9px] font-bold tracking-[.14em] text-ink3 uppercase border-b border-white/[.04]"><span>Agent / operation</span><span>Finding / time</span><span>Decision</span><span className="text-right">Risk</span></div>
              {latest.map(event => <DecisionRow key={event.request_id} event={event} selected={event.request_id === selectedRequestId} onClick={() => onInspectEvent?.(event)} />)}
            </>
          )}
        </Panel>

        <Panel className="p-4 flex flex-col">
          <div className="flex items-center justify-between">
            <div><div className="text-sm font-semibold text-slate-100">Protection posture</div><div className="text-[11px] text-slate-500 mt-1">Control plane connectivity</div></div>
            <div className={`flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-[10px] ${connected ? "border-emerald-400/20 bg-emerald-400/[.06] text-emerald-300" : "border-rose-400/20 bg-rose-400/[.06] text-rose-300"}`}><span className={`w-1.5 h-1.5 rounded-full ${connected ? "bg-emerald-400" : "bg-rose-400"}`} />{connected ? "API connected" : "API unavailable"}</div>
          </div>
          <div className="mt-5 space-y-3">
            {[
              [ShieldCheck, "Zero-trust authorization", "Every protected action checked before execution"],
              [Network, "Identity & provenance", "Agent state and delegation chain validated"],
              [LockKeyhole, "Capability enforcement", "Actions limited to registered capability grants"],
              [Command, "Cedar policy", "Declarative authorization evaluated in the control plane"],
              [Activity, "Audit telemetry", "Decisions correlated by request and workflow"],
            ].map(([Icon, title, detail]) => (
              <div key={title} className="flex gap-3">
                <div className="w-8 h-8 rounded-lg border border-white/[.06] bg-white/[.025] flex items-center justify-center flex-shrink-0"><Icon size={14} className="text-cyan-300/80" /></div>
                <div><div className="text-[12px] font-medium text-slate-200">{title}</div><div className="text-[10px] text-slate-500 mt-0.5">{detail}</div></div>
              </div>
            ))}
          </div>
          <div className="mt-auto pt-4">
            <div className="flex items-center gap-2 text-[10px] text-ink3 border-t border-white/[.06] pt-3"><Clock3 size={12} /> Status reflects backend availability, not inferred agent health.</div>
          </div>
        </Panel>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-[minmax(0,1fr)_minmax(0,1fr)] gap-3">
        <FleetCard agents={agents} onAgentSelect={onAgentSelect} />
        <PipelineCard event={events[0] ?? null} />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-[1.2fr_.8fr] gap-3">
        <Panel className="p-4">
          <div className="flex items-center gap-2"><TerminalSquare size={15} className="text-cyan-300" /><div className="text-sm font-semibold text-slate-100">Adversarial validation</div></div>
          <p className="text-[11px] text-slate-500 mt-1.5">Exercise the actual enforcement boundary using a controlled capability-escalation attempt. No simulated dashboard-only verdicts.</p>
          <div className="mt-3 flex flex-wrap gap-2">
            <span className="rounded-lg border border-white/[.07] px-2.5 py-1.5 text-[10px] font-mono text-slate-400">research-01</span>
            <ArrowRight size={13} className="text-ink3 self-center" />
            <span className="rounded-lg border border-rose-400/20 bg-rose-400/[.05] px-2.5 py-1.5 text-[10px] font-mono text-rose-300">deployment.deploy</span>
            <ArrowRight size={13} className="text-ink3 self-center" />
            <span className="rounded-lg border border-white/[.07] px-2.5 py-1.5 text-[10px] font-mono text-slate-400">production</span>
          </div>
        </Panel>
        <Panel className="p-4 flex items-center justify-between gap-3">
          <div><div className="text-sm font-semibold text-slate-100">Need to execute a task?</div><p className="text-[11px] text-slate-500 mt-1">Start a supervised agent workflow under Shield protection.</p></div>
          <Button size="md" onClick={onOpenRunWorkflow} disabled={busy}>Create <ArrowUpRight size={13} /></Button>
        </Panel>
      </div>

      {error && <div role="alert" className="rounded-xl border border-rose-400/20 bg-rose-400/[.06] px-3 py-2.5 text-xs text-rose-300">{error}</div>}
    </div>
  );
}

export function RunWorkflowPanel({ task, onTaskChange, onRun, busy = false, error = "", onBack }) {
  const submit = (e) => { e.preventDefault(); if (task.trim() && !busy) onRun(); };
  return (
    <div className="max-w-3xl mx-auto py-8">
      <button onClick={onBack} className="text-[11px] text-slate-500 hover:text-cyan-300 mb-5 inline-flex items-center gap-2"><ArrowRight size={12} className="rotate-180" /> Back to Shield</button>
      <div className="flex items-center gap-3 mb-6">
        <div className="w-10 h-10 rounded-xl flex items-center justify-center border border-cyan-400/20 bg-cyan-400/[.06]"><Zap size={18} className="text-cyan-300" /></div>
        <div><div className="text-xl font-semibold text-slate-100">Run a protected workflow</div><div className="text-xs text-slate-500 mt-1">All tool operations pass through the Shield authorization boundary.</div></div>
      </div>
      <Panel className="p-5 sm:p-6">
        <form onSubmit={submit} className="space-y-4">
          <label htmlFor="task" className="block text-[10px] font-bold tracking-[.15em] uppercase text-slate-500">Workflow objective</label>
          <textarea id="task" rows={5} value={task} onChange={e => onTaskChange(e.target.value)} placeholder="Describe the work for your autonomous agent team…" className="w-full rounded-xl border border-line bg-panel2 px-4 py-3 text-sm text-slate-100 placeholder:text-ink3 focus:outline-none focus:border-cyan-400/40 resize-y" />
          {error && <div role="alert" className="text-xs text-rose-300">{error}</div>}
          <div className="flex items-center justify-between gap-3 flex-wrap">
            <span className="text-[10px] text-ink3">Workflow starts only when you submit.</span>
            <Button type="submit" size="lg" disabled={!task.trim() || busy}>{busy ? "Starting…" : "Start protected workflow"} <ArrowUpRight size={14} /></Button>
          </div>
        </form>
      </Panel>
    </div>
  );
}
