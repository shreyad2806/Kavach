/**
 * DashboardPage — the main security overview page.
 * Receives all live data as props from the root App shell.
 */
import { useState, useCallback, useRef } from "react";
import { AgentControlCard }      from "../components/AgentControlCard.jsx";
import { AgentActivityPanel }    from "../components/AgentActivityPanel.jsx";
import { CriticalIncidentPanel } from "../components/CriticalIncidentPanel.jsx";
import { AuthPipeline }          from "../components/AuthPipeline.jsx";
import { FleetList }             from "../components/FleetList.jsx";
import { WorkflowPanel }         from "../components/WorkflowPanel.jsx";
import { MetricCard }            from "../components/MetricCard.jsx";

function checksForEvent(event) {
  if (!event) return {};
  if (event.policy_decision === "ALLOW") {
    return {
      identity: "PASS", agent_state: "PASS", capability: "PASS",
      provenance: "PASS", cedar: "ALLOW", deterministic_rules: "PASS",
    };
  }
  const codes = event.reason_codes ?? [];
  if (codes.includes("IDENTITY_FAILURE"))
    return { identity: "FAIL", agent_state: "NOT_EVALUATED", capability: "NOT_EVALUATED", provenance: "NOT_EVALUATED", cedar: "NOT_EVALUATED", deterministic_rules: "NOT_EVALUATED" };
  if (codes.includes("AGENT_QUARANTINED"))
    return { identity: "PASS", agent_state: "BLOCK", capability: "NOT_EVALUATED", provenance: "NOT_EVALUATED", cedar: "NOT_EVALUATED", deterministic_rules: "NOT_EVALUATED" };
  if (codes.includes("CAPABILITY_MISMATCH"))
    return { identity: "PASS", agent_state: "PASS", capability: "FAIL", provenance: "NOT_EVALUATED", cedar: "NOT_EVALUATED", deterministic_rules: "NOT_EVALUATED" };
  if (codes.includes("PROVENANCE_ANOMALY") || codes.includes("AUTHORITY_MISMATCH"))
    return { identity: "PASS", agent_state: "PASS", capability: "PASS", provenance: "FAIL", cedar: "NOT_EVALUATED", deterministic_rules: "NOT_EVALUATED" };
  if (codes.includes("POLICY_DENIED"))
    return { identity: "PASS", agent_state: "PASS", capability: "PASS", provenance: "PASS", cedar: "DENY", deterministic_rules: "NOT_EVALUATED" };
  return { identity: "PASS", agent_state: "PASS", capability: "PASS", provenance: "PASS", cedar: "DENY", deterministic_rules: "NOT_EVALUATED" };
}

export function DashboardPage({ agents, events, incidents, loading, refresh }) {
  const [selectedAgentId, setSelectedAgentId] = useState("orchestrator-01");
  const [selectedEvent,   setSelectedEvent]   = useState(null);

  const activityRef = useRef(null);
  const pipelineRef = useRef(null);
  const fleetRef    = useRef(null);

  const quarantinedCount = agents.filter(a => a.state === "QUARANTINED").length;
  const activeCount      = agents.filter(a => a.state === "ACTIVE").length;
  const allowCount       = events.filter(e => e.policy_decision === "ALLOW").length;
  const denyCount        = events.filter(e => e.policy_decision === "DENY").length;
  const openIncidents    = incidents.filter(i => i.status === "OPEN");
  const checks           = checksForEvent(selectedEvent);

  const handleEventSelect = useCallback(ev => {
    setSelectedEvent(ev);
    setTimeout(() => pipelineRef.current?.scrollIntoView({ behavior: "smooth", block: "start" }), 80);
  }, []);

  const handleReviewQuarantine = useCallback(() => {
    fleetRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
  }, []);

  return (
    <div className="flex flex-col gap-3">

      {/* Metric row */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <MetricCard label="Active agents"     value={loading ? "—" : activeCount}      tone={activeCount > 0 ? "neon" : "dim"} />
        <MetricCard label="Requests allowed"  value={loading ? "—" : allowCount}       tone="neon" />
        <MetricCard label="Requests denied"   value={loading ? "—" : denyCount}        tone={denyCount > 0 ? "danger" : "neutral"} />
        <MetricCard label="Quarantined"       value={loading ? "—" : quarantinedCount} tone={quarantinedCount > 0 ? "danger" : "dim"} />
      </div>

      {/* Main row */}
      <div className="analysis-grid grid gap-3">
        <AgentControlCard
          agents={agents}
          selectedId={selectedAgentId}
          onSelect={setSelectedAgentId}
          deniedCount={denyCount}
          onMutate={refresh}
        />
        <div ref={activityRef}>
          <AgentActivityPanel
            events={events}
            onEventSelect={handleEventSelect}
            selectedEventId={selectedEvent?.event_id}
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
          <FleetList agents={agents} selectedId={selectedAgentId} onSelect={setSelectedAgentId} />
        </div>
        <WorkflowPanel onWorkflowComplete={refresh} />
      </div>
    </div>
  );
}
