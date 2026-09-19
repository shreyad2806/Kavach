import { useState, useCallback, useRef } from "react";
import { TopBar }                from "./components/TopBar.jsx";
import { HeroStrip }             from "./components/HeroStrip.jsx";
import { VerticalRail }          from "./components/VerticalRail.jsx";
import { AgentControlCard }      from "./components/AgentControlCard.jsx";
import { MetricCard }            from "./components/MetricCard.jsx";
import { SystemLockTile, ContainmentDonut } from "./components/SystemLockTile.jsx";
import { UptimeCard }            from "./components/UptimeCard.jsx";
import { ArtifactsBlockedCard }  from "./components/ArtifactsBlockedCard.jsx";
import { FleetRiskCard }         from "./components/FleetRiskCard.jsx";
import { SeverityRings }         from "./components/SeverityRings.jsx";
import { AgentActivityPanel }    from "./components/AgentActivityPanel.jsx";
import { CriticalIncidentPanel } from "./components/CriticalIncidentPanel.jsx";
import { AuthPipeline }          from "./components/AuthPipeline.jsx";
import { FleetList }             from "./components/FleetList.jsx";
import { ScanModal }             from "./components/ScanModal.jsx";
import { IncidentHistoryModal }  from "./components/IncidentHistoryModal.jsx";
import { ToastStack }            from "./components/ToastStack.jsx";

// ─── Sample data ──────────────────────────────────────────────────────────────
const SAMPLE_AGENTS = [
  { agent_id: "orchestrator-01", role: "orchestrator", state: "ACTIVE",      risk_score: 12 },
  { agent_id: "research-01",     role: "research",     state: "QUARANTINED", risk_score: 87 },
  { agent_id: "coding-01",       role: "coding",       state: "ACTIVE",      risk_score: 24 },
  { agent_id: "deployment-01",   role: "deployment",   state: "ACTIVE",      risk_score: 8  },
  { agent_id: "verification-01", role: "verification", state: "SUSPICIOUS",  risk_score: 55 },
];

const SAMPLE_EVENTS = [
  { event_id: "evt-001", timestamp: new Date(Date.now() - 45000).toISOString(),   source_agent: "research-01",     action: "deployment.deploy",     resource: "production-environment", policy_decision: "DENY",  risk_score: 87, reason_codes: ["CAPABILITY_MISMATCH", "PRIVILEGE_ESCALATION"] },
  { event_id: "evt-002", timestamp: new Date(Date.now() - 120000).toISOString(),  source_agent: "coding-01",       action: "coding.write",          resource: "workspace",              policy_decision: "ALLOW", risk_score: 18, reason_codes: [] },
  { event_id: "evt-003", timestamp: new Date(Date.now() - 200000).toISOString(),  source_agent: "verification-01", action: "verification.test",     resource: "test-environment",       policy_decision: "ALLOW", risk_score: 22, reason_codes: [] },
  { event_id: "evt-004", timestamp: new Date(Date.now() - 310000).toISOString(),  source_agent: "research-01",     action: "research.search",       resource: "research-data",          policy_decision: "DENY",  risk_score: 72, reason_codes: ["AGENT_QUARANTINED"] },
  { event_id: "evt-005", timestamp: new Date(Date.now() - 420000).toISOString(),  source_agent: "orchestrator-01", action: "orchestrator.delegate", resource: "workspace",              policy_decision: "ALLOW", risk_score: 10, reason_codes: [] },
  { event_id: "evt-006", timestamp: new Date(Date.now() - 600000).toISOString(),  source_agent: "coding-01",       action: "coding.test",           resource: "test-environment",       policy_decision: "ALLOW", risk_score: 15, reason_codes: [] },
  { event_id: "evt-007", timestamp: new Date(Date.now() - 750000).toISOString(),  source_agent: "verification-01", action: "deployment.deploy",     resource: "staging-environment",    policy_decision: "DENY",  risk_score: 61, reason_codes: ["PRIVILEGE_ESCALATION", "POLICY_DENIED"] },
];

const SAMPLE_INCIDENT = {
  incident_id:  "inc-a3f9c1",
  agent_id:     "research-01",
  severity:     "HIGH",
  status:       "OPEN",
  reason_codes: ["CAPABILITY_MISMATCH", "PRIVILEGE_ESCALATION"],
  description:  "Agent attempted to invoke deployment.deploy on production-environment without the required capability token.",
  timestamp:    new Date(Date.now() - 45000).toISOString(),
};

// ─── Auth pipeline check derivation ──────────────────────────────────────────
function checksForEvent(event) {
  if (!event) return {};
  if (event.policy_decision === "ALLOW") {
    return { identity: "PASS", agent_state: "PASS", capability: "PASS", provenance: "PASS", cedar: "ALLOW", deterministic_rules: "PASS" };
  }
  const codes = event.reason_codes || [];
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
  if (codes.includes("PRIVILEGE_ESCALATION") || codes.includes("SUSPICIOUS_BEHAVIOR"))
    return { identity: "PASS", agent_state: "PASS", capability: "PASS", provenance: "PASS", cedar: "PASS", deterministic_rules: "DENY" };
  return { identity: "PASS", agent_state: "PASS", capability: "PASS", provenance: "PASS", cedar: "DENY", deterministic_rules: "NOT_EVALUATED" };
}

// ─── Toast helpers ────────────────────────────────────────────────────────────
let _toastId = 0;
function makeToast(message, type = "info", duration = 3000) {
  return { id: ++_toastId, message, type, duration };
}

// ─── App ──────────────────────────────────────────────────────────────────────
export default function App() {
  const [agents, setAgents]               = useState(SAMPLE_AGENTS);
  const [selectedAgentId, setSelectedAgentId] = useState("orchestrator-01");
  const [systemLocked, setSystemLocked]   = useState(false);
  const [selectedEvent, setSelectedEvent] = useState(null);
  const [incident, setIncident]           = useState(SAMPLE_INCIDENT);
  const [toasts, setToasts]               = useState([]);
  const [showScanModal, setShowScanModal] = useState(false);
  const [showHistoryModal, setShowHistoryModal] = useState(false);

  // Scroll refs
  const activityRef  = useRef(null);
  const incidentRef  = useRef(null);
  const pipelineRef  = useRef(null);
  const fleetRef     = useRef(null);

  // ── Toast ──
  const addToast = useCallback((message, type = "info") => {
    setToasts((prev) => [...prev, makeToast(message, type)]);
  }, []);
  const dismissToast = useCallback((id) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  }, []);

  // ── Derived counts ──
  const activeCount      = agents.filter((a) => a.state === "ACTIVE").length;
  const quarantinedCount = agents.filter((a) => a.state === "QUARANTINED").length;
  const containPct       = Math.round((activeCount / agents.length) * 100);
  const openIncidents    = incident ? 1 : 0;
  const denyCount        = SAMPLE_EVENTS.filter((e) => e.policy_decision === "DENY").length;
  const allowCount       = SAMPLE_EVENTS.filter((e) => e.policy_decision === "ALLOW").length;
  const checks           = checksForEvent(selectedEvent);

  // ── Isolate (optimistic) ──
  const handleIsolate = useCallback((id) => {
    const prev = agents.find((a) => a.agent_id === id);
    if (!prev || prev.state === "QUARANTINED") return;
    setAgents((list) => list.map((a) => a.agent_id === id ? { ...a, state: "QUARANTINED" } : a));
    addToast(`${id} isolated.`, "warning");
    // In production: call API, rollback on failure
    // api.isolateAgent(id).catch(() => { setAgents(original); addToast("Isolate failed.", "error"); });
  }, [agents, addToast]);

  // ── Restore (optimistic) ──
  const handleRestore = useCallback((id) => {
    if (systemLocked) {
      addToast("System lock is enabled — restore is blocked.", "error");
      return;
    }
    const prev = agents.find((a) => a.agent_id === id);
    if (!prev || prev.state === "ACTIVE") return;
    setAgents((list) => list.map((a) => a.agent_id === id ? { ...a, state: "ACTIVE" } : a));
    addToast(`${id} restored.`, "success");
  }, [agents, systemLocked, addToast]);

  // ── Resolve incident ──
  const handleResolveIncident = useCallback((id) => {
    setIncident(null);
    addToast("Incident resolved.", "success");
  }, [addToast]);

  // ── Refresh ──
  const handleRefresh = useCallback(() => {
    addToast("Data refreshed.", "info");
  }, [addToast]);

  // ── System lock toggle ──
  const handleSystemLockToggle = useCallback(() => {
    setSystemLocked((v) => {
      const next = !v;
      addToast(next ? "System lock enabled." : "System lock disabled.", next ? "warning" : "info");
      return next;
    });
  }, [addToast]);

  // ── Scroll helpers ──
  const scrollTo = useCallback((ref) => {
    ref.current?.scrollIntoView({ behavior: "smooth", block: "start" });
  }, []);

  // ── Event select: also scroll to pipeline ──
  const handleEventSelect = useCallback((event) => {
    setSelectedEvent(event);
    setTimeout(() => scrollTo(pipelineRef), 80);
  }, [scrollTo]);

  // ── Agent select: sync FleetList ↔ AgentControlCard ──
  const handleAgentSelect = useCallback((id) => {
    setSelectedAgentId(id);
  }, []);

  // ── Review quarantine: scroll to fleet ──
  const handleReviewQuarantine = useCallback(() => {
    scrollTo(fleetRef);
    addToast("Showing quarantined agents in fleet list.", "info");
  }, [scrollTo, addToast]);

  // ── View log: scroll to activity ──
  const handleViewLog = useCallback(() => {
    scrollTo(activityRef);
  }, [scrollTo]);

  // ── Hero CTA ──
  const handleHeroCTA = useCallback(() => {
    if (openIncidents > 0) scrollTo(incidentRef);
    else scrollTo(activityRef);
  }, [openIncidents, scrollTo]);

  return (
    <div className="min-h-screen w-full overflow-x-hidden">
      <div className="mx-auto max-w-[1460px] px-3 py-3 flex flex-col gap-3">

        {/* ── Band 1: Top bar ── */}
        <TopBar
          onNewScan={() => setShowScanModal(true)}
          onRefresh={handleRefresh}
          reconnecting={false}
        />

        {/* ── Band 2: Hero strip ── */}
        <HeroStrip
          openIncidents={openIncidents}
          onCTA={handleHeroCTA}
          onViewActivity={() => scrollTo(activityRef)}
        />

        {/* ── Band 3: Metrics row ── */}
        <div className="metrics-grid grid gap-3">
          <VerticalRail
            onNew={() => setShowScanModal(true)}
            onSwap={() => scrollTo(fleetRef)}
          />

          <AgentControlCard
            agents={agents}
            selectedId={selectedAgentId}
            onSelect={handleAgentSelect}
            onIsolate={handleIsolate}
            onRestore={handleRestore}
            deniedToday={denyCount}
            systemLocked={systemLocked}
          />

          <div className="flex flex-col gap-3">
            <MetricCard
              label="Requests denied"
              value={denyCount}
              tone="danger"
              action={
                <select
                  aria-label="Time period for denied requests"
                  className="bg-panel2 border border-line rounded-btn text-[11px] text-ink3 px-2 py-1 outline-none hover:border-line2 transition-colors cursor-pointer"
                >
                  <option>Today</option>
                  <option>This week</option>
                </select>
              }
            />
            <MetricCard
              label="Requests reviewed"
              value={2}
              tone="amber"
              action={
                <button
                  onClick={handleViewLog}
                  className="text-[11.5px] text-neon hover:underline"
                >
                  View log
                </button>
              }
            />
          </div>

          <div className="flex flex-col gap-3">
            <SystemLockTile
              locked={systemLocked}
              onToggle={handleSystemLockToggle}
            />
            <ContainmentDonut percent={containPct} />
          </div>

          <div className="flex flex-col gap-3">
            <UptimeCard days={13} />
            <ArtifactsBlockedCard />
          </div>

          <FleetRiskCard
            score={24}
            delta={+3}
            drivingAgent="research-01"
            sparkline={[12, 18, 15, 22, 19, 28, 24, 31, 27, 24]}
          />
        </div>

        {/* ── Band 4: Analysis row ── */}
        <div className="analysis-grid grid gap-3">
          <SeverityRings low={3} medium={2} critical={1} />

          <div ref={activityRef}>
            <AgentActivityPanel
              events={SAMPLE_EVENTS}
              onEventSelect={handleEventSelect}
              selectedEventId={selectedEvent?.event_id}
              quarantinedCount={quarantinedCount}
              onReviewQuarantine={handleReviewQuarantine}
            />
          </div>

          <div ref={incidentRef}>
            <CriticalIncidentPanel
              incident={incident}
              onResolve={handleResolveIncident}
              onHistory={() => setShowHistoryModal(true)}
            />
          </div>
        </div>

        {/* ── Band 5: Pipeline + fleet row ── */}
        <div className="pipeline-grid grid gap-3">
          <div ref={pipelineRef}>
            <AuthPipeline event={selectedEvent} checks={checks} />
          </div>

          <div ref={fleetRef}>
            <FleetList
              agents={agents}
              selectedId={selectedAgentId}
              onSelect={handleAgentSelect}
            />
          </div>
        </div>

        {/* ── Band 6: Footer ── */}
        <div className="text-center text-[11px] text-ink3 py-2 font-mono">
          kavach · runtime security · all systems live
        </div>

      </div>

      {/* ── Modals ── */}
      {showScanModal && (
        <ScanModal onClose={() => setShowScanModal(false)} />
      )}
      {showHistoryModal && incident && (
        <IncidentHistoryModal
          incident={incident}
          events={SAMPLE_EVENTS}
          onClose={() => setShowHistoryModal(false)}
        />
      )}

      {/* ── Toast stack ── */}
      <ToastStack toasts={toasts} onDismiss={dismissToast} />
    </div>
  );
}
