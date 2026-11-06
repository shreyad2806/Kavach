/**
 * DashboardPage — workflow execution detail and active Shield enforcement controls.
 */
import { useCallback, useEffect, useRef, useState } from "react";
import { AgentControlCard } from "../components/AgentControlCard.jsx";
import { AgentActivityPanel } from "../components/AgentActivityPanel.jsx";
import { CriticalIncidentPanel } from "../components/CriticalIncidentPanel.jsx";
import { AuthPipeline } from "../components/AuthPipeline.jsx";
import { FleetList } from "../components/FleetList.jsx";
import { WorkflowPanel } from "../components/WorkflowPanel.jsx";
import { MetricCard } from "../components/MetricCard.jsx";
import { api } from "../api.js";
import { normalizeIncidents } from "../lib/shape.js";

const TERMINAL = new Set(["COMPLETED", "FAILED", "STOPPED"]);

export function DashboardPage({
  snapshot = null, events = [], agents = [], starting = false,
  selectedRequestId = null, onEventSelect, manualAgentId = null,
  onAgentSelect, onMutate, children,
}) {
  const activityRef = useRef(null);
  const pipelineRef = useRef(null);
  const fleetRef = useRef(null);
  const status = snapshot?.status ?? null;

  const quarantinedCount = agents.filter(a => a.state === "QUARANTINED").length;
  const activeCount = agents.filter(a => a.state === "ACTIVE").length;
  const allowCount = events.filter(e => e.policy_decision === "ALLOW").length;
  const denyCount = events.filter(e => e.policy_decision === "DENY").length;
  const selectedEvent = selectedRequestId ? events.find(e => e.request_id === selectedRequestId) ?? null : null;
  const selectedAgentId = manualAgentId ?? selectedEvent?.source_agent ?? null;

  const [incidents, setIncidents] = useState([]);
  useEffect(() => {
    if (!status || !TERMINAL.has(status)) return undefined;
    let cancelled = false;
    api.getIncidents()
      .then(value => { if (!cancelled) setIncidents(normalizeIncidents(value)); })
      .catch(() => {});
    return () => { cancelled = true; };
  }, [status]);
  const openIncidents = incidents.filter(i => i.status === "OPEN");

  const handleEventSelect = useCallback(ev => {
    onEventSelect?.(ev.request_id);
    pipelineRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
  }, [onEventSelect]);

  return (
    <div className="max-w-[1440px] mx-auto flex flex-col gap-4 pb-8">
      <div className="flex items-end justify-between gap-3 flex-wrap">
        <div><div className="text-[10px] font-bold uppercase tracking-[.18em] text-cyan-300/80 mb-1">Shield / workflow execution</div><h1 className="text-[24px] font-semibold text-slate-100">Runtime activity</h1><p className="text-[12px] text-slate-500 mt-1">Inspect individual authorization decisions and agent containment controls.</p></div>
        <button onClick={onMutate} className="text-[11px] text-slate-400 hover:text-cyan-300 border border-white/[.08] rounded-lg px-3 py-2">Refresh telemetry</button>
      </div>

      <div className="grid grid-cols-2 xl:grid-cols-4 gap-3">
        <MetricCard label="Active agents" value={agents.length ? activeCount : "—"} tone={activeCount > 0 ? "neon" : "dim"} />
        <MetricCard label="Requests allowed" value={allowCount} tone="neon" />
        <MetricCard label="Requests denied" value={denyCount} tone={denyCount > 0 ? "danger" : "neutral"} />
        <MetricCard label="Quarantined" value={quarantinedCount} tone={quarantinedCount > 0 ? "danger" : "dim"} />
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-[minmax(300px,.8fr)_minmax(0,1.6fr)] gap-3">
        <div className="flex flex-col gap-3">
          <AgentControlCard agents={agents} selectedId={selectedAgentId} onSelect={onAgentSelect} deniedCount={denyCount} onMutate={onMutate} />
          <FleetList agents={agents} selectedId={selectedAgentId} onSelect={onAgentSelect} />
        </div>
        <div ref={activityRef}>
          <AgentActivityPanel events={events} onEventSelect={handleEventSelect} selectedRequestId={selectedRequestId} quarantinedCount={quarantinedCount} onReviewQuarantine={() => fleetRef.current?.scrollIntoView({ behavior: "smooth", block: "start" })} />
        </div>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-[minmax(0,1.25fr)_minmax(320px,.75fr)] gap-3">
        <div ref={pipelineRef}><AuthPipeline event={selectedEvent} checks={selectedEvent?.checks ?? {}} /></div>
        <div className="flex flex-col gap-3"><WorkflowPanel snapshot={snapshot} starting={starting} /><CriticalIncidentPanel incident={openIncidents[0] ?? null} onResolve={() => {}} onHistory={() => activityRef.current?.scrollIntoView({ behavior: "smooth", block: "start" })} /></div>
      </div>
      {children}
    </div>
  );
}
