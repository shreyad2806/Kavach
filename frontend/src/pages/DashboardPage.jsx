/**
 * DashboardPage — the runtime security overview, rendered only after Run
 * Workflow has been pressed.  It lives inside the persistent app shell, so the
 * sidebar and top bar stay mounted around it.
 *
 * Every value here is a projection of real backend state:
 *
 *   counters   <- the current workflow session's authorization events + live
 *                 Shield agent states (never the permanent audit log)
 *   activity   <- the same events
 *   pipeline   <- event.checks for the ONE selected request id
 *   agent ctrl <- the selected event's source_agent
 *   fleet      <- the live Shield identity registry
 *
 * There is no client-side inference of check outcomes and no hardcoded
 * selected agent: the selection follows the event the operator is inspecting.
 */
import { useCallback, useEffect, useRef, useState } from "react";
import { AgentControlCard }      from "../components/AgentControlCard.jsx";
import { AgentActivityPanel }    from "../components/AgentActivityPanel.jsx";
import { CriticalIncidentPanel } from "../components/CriticalIncidentPanel.jsx";
import { AuthPipeline }          from "../components/AuthPipeline.jsx";
import { FleetList }             from "../components/FleetList.jsx";
import { WorkflowPanel }         from "../components/WorkflowPanel.jsx";
import { MetricCard }            from "../components/MetricCard.jsx";
import { api }                   from "../api.js";
import { normalizeIncidents }    from "../lib/shape.js";

const TERMINAL = new Set(["COMPLETED", "FAILED", "STOPPED"]);

export function DashboardPage({
  snapshot = null,
  events = [],
  agents = [],
  starting = false,
  selectedRequestId = null,
  onEventSelect,
  manualAgentId = null,
  onAgentSelect,
  onMutate,
  children,
}) {
  const activityRef = useRef(null);
  const pipelineRef = useRef(null);
  const fleetRef    = useRef(null);

  const status = snapshot?.status ?? null;

  const quarantinedCount = agents.filter((a) => a.state === "QUARANTINED").length;
  const activeCount      = agents.filter((a) => a.state === "ACTIVE").length;
  const allowCount       = events.filter((e) => e.policy_decision === "ALLOW").length;
  const denyCount        = events.filter((e) => e.policy_decision === "DENY").length;

  // The ONE selected request, and the event behind it.
  const selectedEvent = selectedRequestId
    ? events.find((e) => e.request_id === selectedRequestId) ?? null
    : null;

  // Agent Control follows the selected event.  An explicit Fleet/Agent Control
  // click overrides it until the next event is selected.  There is no default
  // agent: with nothing selected, nothing is selected.
  const selectedAgentId = manualAgentId ?? selectedEvent?.source_agent ?? null;

  // Real per-stage check outcomes, exactly as returned by Shield.  Stages that
  // never ran stay missing and render as NOT EVALUATED.
  const checks = selectedEvent?.checks ?? {};

  // Incidents are fetched ONCE when the run settles — never polled.
  const [incidents, setIncidents] = useState([]);
  useEffect(() => {
    if (!status || !TERMINAL.has(status)) return undefined;
    let cancelled = false;
    api
      .getIncidents()
      .then((value) => { if (!cancelled) setIncidents(normalizeIncidents(value)); })
      .catch(() => { /* non-fatal: the panel simply shows no incident */ });
    return () => { cancelled = true; };
  }, [status]);

  const openIncidents = incidents.filter((i) => i.status === "OPEN");

  const handleEventSelect = useCallback((ev) => {
    onEventSelect?.(ev.request_id);
    setTimeout(() => pipelineRef.current?.scrollIntoView({ behavior: "smooth", block: "start" }), 80);
  }, [onEventSelect]);

  const handleReviewQuarantine = useCallback(() => {
    fleetRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
  }, []);

  return (
    <div className="flex flex-col gap-3">

      {/* Metric row — all counts come from the current workflow session. */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <MetricCard label="Active agents"    value={agents.length ? activeCount : "—"} tone={activeCount > 0 ? "neon" : "dim"} />
        <MetricCard label="Requests allowed" value={allowCount}                        tone="neon" />
        <MetricCard label="Requests denied"  value={denyCount}                         tone={denyCount > 0 ? "danger" : "neutral"} />
        <MetricCard label="Quarantined"      value={quarantinedCount}                  tone={quarantinedCount > 0 ? "danger" : "dim"} />
      </div>

      {/* Main row */}
      <div className="analysis-grid grid gap-3">
        <AgentControlCard
          agents={agents}
          selectedId={selectedAgentId}
          onSelect={onAgentSelect}
          deniedCount={denyCount}
          onMutate={onMutate}
        />
        <div ref={activityRef}>
          <AgentActivityPanel
            events={events}
            onEventSelect={handleEventSelect}
            selectedRequestId={selectedRequestId}
            quarantinedCount={quarantinedCount}
            onReviewQuarantine={handleReviewQuarantine}
          />
        </div>
        <CriticalIncidentPanel
          incident={openIncidents[0] ?? null}
          onResolve={() => {}}
          onHistory={() => activityRef.current?.scrollIntoView({ behavior: "smooth", block: "start" })}
        />
      </div>

      {/* Pipeline + fleet + workflow row */}
      <div className="pipeline-ext-grid grid gap-3">
        <div ref={pipelineRef}>
          <AuthPipeline event={selectedEvent} checks={checks} />
        </div>
        <div ref={fleetRef}>
          <FleetList agents={agents} selectedId={selectedAgentId} onSelect={onAgentSelect} />
        </div>
        <WorkflowPanel snapshot={snapshot} starting={starting} />
      </div>

      {/* Security test / run again */}
      {children}
    </div>
  );
}
