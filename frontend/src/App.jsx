/**
 * App — Kavach Runtime Security Console
 *
 * All data comes from the real backend (Node BFF → Python → Shield/P1).
 * No sample/mock constants anywhere in this file.
 *
 * Layout (one viewport):
 *   TopBar          — branding + live/offline indicator + refresh
 *   MetricRow       — 4 real counters from /dashboard + /events
 *   MainRow         — AgentControlCard | AgentActivityPanel | CriticalIncidentPanel
 *   BottomRow       — AuthPipeline | FleetList | WorkflowPanel
 *   Footer
 *
 * Real-time: useKavach() polls /agents, /events, /incidents, /dashboard every 2 s.
 */

import { useState, useCallback, useRef } from "react";

import { TopBar }             from "./components/TopBar.jsx";
import { AgentControlCard }   from "./components/AgentControlCard.jsx";
import { AgentActivityPanel } from "./components/AgentActivityPanel.jsx";
import { CriticalIncidentPanel } from "./components/CriticalIncidentPanel.jsx";
import { AuthPipeline }       from "./components/AuthPipeline.jsx";
import { FleetList }          from "./components/FleetList.jsx";
import { WorkflowPanel }      from "./components/WorkflowPanel.jsx";
import { MetricCard }         from "./components/MetricCard.jsx";

import { useKavach }          from "./hooks/useKavach.js";

// ─── Authorization pipeline check derivation ─────────────────────────────────
// Converts a real Shield event's reason_codes into pipeline check statuses.
// This is DERIVED from real event data, not hardcoded.
function checksForEvent(event) {
  if (!event) return {};
  if (event.policy_decision === "ALLOW") {
    return {
      identity:           "PASS",
      agent_state:        "PASS",
      capability:         "PASS",
      provenance:         "PASS",
      cedar:              "ALLOW",
      deterministic_rules:"PASS",
    };
  }
  const codes = event.reason_codes ?? [];
  if (codes.includes("IDENTITY_FAILURE"))
    return {
      identity:           "FAIL",
      agent_state:        "NOT_EVALUATED",
      capability:         "NOT_EVALUATED",
      provenance:         "NOT_EVALUATED",
      cedar:              "NOT_EVALUATED",
      deterministic_rules:"NOT_EVALUATED",
    };
  if (codes.includes("AGENT_QUARANTINED"))
    return {
      identity:           "PASS",
      agent_state:        "BLOCK",
      capability:         "NOT_EVALUATED",
      provenance:         "NOT_EVALUATED",
      cedar:              "NOT_EVALUATED",
      deterministic_rules:"NOT_EVALUATED",
    };
  if (codes.includes("CAPABILITY_MISMATCH"))
    return {
      identity:           "PASS",
      agent_state:        "PASS",
      capability:         "FAIL",
      provenance:         "NOT_EVALUATED",
      cedar:              "NOT_EVALUATED",
      deterministic_rules:"NOT_EVALUATED",
    };
  if (codes.includes("PROVENANCE_ANOMALY") || codes.includes("AUTHORITY_MISMATCH"))
    return {
      identity:           "PASS",
      agent_state:        "PASS",
      capability:         "PASS",
      provenance:         "FAIL",
      cedar:              "NOT_EVALUATED",
      deterministic_rules:"NOT_EVALUATED",
    };
  if (codes.includes("POLICY_DENIED"))
    return {
      identity:           "PASS",
      agent_state:        "PASS",
      capability:         "PASS",
      provenance:         "PASS",
      cedar:              "DENY",
      deterministic_rules:"NOT_EVALUATED",
    };
  if (codes.includes("PRIVILEGE_ESCALATION") || codes.includes("SUSPICIOUS_BEHAVIOR"))
    return {
      identity:           "PASS",
      agent_state:        "PASS",
      capability:         "PASS",
      provenance:         "PASS",
      cedar:              "PASS",
      deterministic_rules:"DENY",
    };
  // Fallback: some other DENY reason
  return {
    identity:           "PASS",
    agent_state:        "PASS",
    capability:         "PASS",
    provenance:         "PASS",
    cedar:              "DENY",
    deterministic_rules:"NOT_EVALUATED",
  };
}

// ─── App ──────────────────────────────────────────────────────────────────────
export default function App() {
  // ── Real backend state ──────────────────────────────────────────────────
  const { agents, events, incidents, dashboard, connected, offline, loading, refresh } =
    useKavach();

  // ── UI selection state ──────────────────────────────────────────────────
  const [selectedAgentId,  setSelectedAgentId]  = useState("orchestrator-01");
  const [selectedEvent,    setSelectedEvent]     = useState(null);

  // Scroll refs
  const activityRef = useRef(null);
  const pipelineRef = useRef(null);
  const fleetRef    = useRef(null);
  const incidentRef = useRef(null);

  // ── Derived real metrics ────────────────────────────────────────────────
  const quarantinedCount = agents.filter((a) => a.state === "QUARANTINED").length;
  const activeCount      = agents.filter((a) => a.state === "ACTIVE").length;
  const allowCount       = events.filter((e) => e.policy_decision === "ALLOW").length;
  const denyCount        = events.filter((e) => e.policy_decision === "DENY").length;

  // Real open incidents
  const openIncidents = incidents.filter((i) => i.status === "OPEN");

  // Authorization pipeline checks for the selected event
  const checks = checksForEvent(selectedEvent);

  // ── Event selection ─────────────────────────────────────────────────────
  const handleEventSelect = useCallback((event) => {
    setSelectedEvent(event);
    setTimeout(() => {
      pipelineRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
    }, 80);
  }, []);

  // ── Agent selection ─────────────────────────────────────────────────────
  const handleAgentSelect = useCallback((id) => {
    setSelectedAgentId(id);
  }, []);

  // ── After isolate/restore: immediate refresh ────────────────────────────
  const handleAgentMutate = useCallback(() => {
    refresh();
  }, [refresh]);

  // ── After workflow completes: refresh events/incidents ──────────────────
  const handleWorkflowComplete = useCallback(() => {
    refresh();
  }, [refresh]);

  // ── Review quarantine — scroll to fleet ────────────────────────────────
  const handleReviewQuarantine = useCallback(() => {
    fleetRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
  }, []);

  return (
    <div className="min-h-screen w-full overflow-x-hidden">
      <div className="mx-auto max-w-[1460px] px-3 py-3 flex flex-col gap-3">

        {/* ── Band 1: Top bar ──────────────────────────────────────────── */}
        <TopBar
          connected={connected}
          offline={offline}
          loading={loading}
          onRefresh={refresh}
        />

        {/* ── Band 2: Real metric summary ──────────────────────────────── */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          <MetricCard
            label="Active agents"
            value={loading ? "—" : activeCount}
            tone={activeCount > 0 ? "neon" : "dim"}
          />
          <MetricCard
            label="Requests allowed"
            value={loading ? "—" : allowCount}
            tone="neon"
          />
          <MetricCard
            label="Requests denied"
            value={loading ? "—" : denyCount}
            tone={denyCount > 0 ? "danger" : "neutral"}
          />
          <MetricCard
            label="Quarantined"
            value={loading ? "—" : quarantinedCount}
            tone={quarantinedCount > 0 ? "danger" : "dim"}
          />
        </div>

        {/* ── Band 3: Main row ─────────────────────────────────────────── */}
        <div className="analysis-grid grid gap-3">
          {/* Agent Control */}
          <AgentControlCard
            agents={agents}
            selectedId={selectedAgentId}
            onSelect={handleAgentSelect}
            deniedCount={denyCount}
            onMutate={handleAgentMutate}
          />

          {/* Live security event stream */}
          <div ref={activityRef}>
            <AgentActivityPanel
              events={events}
              onEventSelect={handleEventSelect}
              selectedEventId={selectedEvent?.event_id}
              quarantinedCount={quarantinedCount}
              onReviewQuarantine={handleReviewQuarantine}
            />
          </div>

          {/* Incidents */}
          <div ref={incidentRef}>
            <CriticalIncidentPanel
              incident={openIncidents[0] ?? null}
              onResolve={() => {/* read-only — incidents resolved via backend */}}
              onHistory={() => {
                activityRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
              }}
            />
          </div>
        </div>

        {/* ── Band 4: Pipeline + fleet + workflow ──────────────────────── */}
        <div className="pipeline-ext-grid grid gap-3">
          {/* Authorization pipeline inspector */}
          <div ref={pipelineRef}>
            <AuthPipeline event={selectedEvent} checks={checks} />
          </div>

          {/* Fleet list */}
          <div ref={fleetRef}>
            <FleetList
              agents={agents}
              selectedId={selectedAgentId}
              onSelect={handleAgentSelect}
            />
          </div>

          {/* Workflow control */}
          <WorkflowPanel onWorkflowComplete={handleWorkflowComplete} />
        </div>

        {/* ── Footer ───────────────────────────────────────────────────── */}
        <div className="text-center text-[11px] text-ink3 py-2 font-mono">
          kavach · zero-trust runtime security · {connected ? "backend connected" : offline ? "backend offline" : "connecting…"}
        </div>

      </div>
    </div>
  );
}
