import React, { useMemo, useState, useCallback, useEffect } from "react";
import { api } from "./api.js";
import {
  Menu, Plus, Search, Mic, Calendar, Lock, ArrowRight, ArrowUpRight,
  Maximize2, X, Bell, ChevronDown, Check, RotateCcw, RefreshCw
} from "lucide-react";

const COLORS = {
  page: "#e9eaec", canvas: "#f3f4f6", card: "#ffffff", ink: "#15161a",
  inkDim: "#8b8d95", inkFaint: "#b7b9c1", accent: "#ff5a3c",
  accentSoft: "#ffe4dc", line: "#ececee", green: "#16865b"
};

const STATE_COLOR = {
  ACTIVE: COLORS.green, QUARANTINED: COLORS.accent,
  TERMINATED: "#6b7280", SUSPICIOUS: "#d97706"
};
const DECISION_COLOR = {
  APPROVED: COLORS.green, BLOCKED: COLORS.accent, REVIEW_REQUIRED: "#d97706"
};
const SEV_COLOR = {
  Critical: COLORS.accent, HIGH: COLORS.accent,
  Medium: "#d97706", MEDIUM: "#d97706",
  Low: COLORS.inkDim, LOW: COLORS.inkDim
};

function Card({ children, className = "", dark = false, style = {} }) {
  return (
    <div className={`rounded-2xl p-4 ${className}`} style={{
      backgroundColor: dark ? COLORS.ink : COLORS.card,
      color: dark ? "#fff" : COLORS.ink,
      boxShadow: "0 8px 30px rgba(35,38,48,.035)", ...style
    }}>{children}</div>
  );
}
function Pill({ children, onClick, active = false }) {
  return (
    <button onClick={onClick}
      className="text-[11px] font-semibold rounded-full px-3 py-1.5 whitespace-nowrap"
      style={{ background: active ? COLORS.ink : COLORS.canvas, color: active ? "#fff" : COLORS.ink }}>
      {children}
    </button>
  );
}
function Donut({ percent = 0 }) {
  const r = 34, c = 2 * Math.PI * r;
  return (
    <div className="relative w-[78px] h-[78px]">
      <svg width="78" height="78" viewBox="0 0 84 84" style={{ transform: "rotate(-90deg)" }}>
        <circle cx="42" cy="42" r={r} fill="none" stroke="#2a2c33" strokeWidth="8" />
        <circle cx="42" cy="42" r={r} fill="none" stroke={COLORS.accent} strokeWidth="8"
          strokeDasharray={c} strokeDashoffset={c - percent / 100 * c} strokeLinecap="round" />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center text-white">
        <b className="text-[15px]">{percent}%</b>
        <span className="text-[7px] text-gray-400">Contained</span>
      </div>
    </div>
  );
}
function Wave() {
  return (
    <svg className="w-full flex-1" viewBox="0 0 300 56" preserveAspectRatio="none" style={{ minHeight: 40 }}>
      <polyline fill="none" stroke={COLORS.accent} strokeWidth="2.4"
        points="0,34 15,30 30,38 45,24 60,32 75,20 90,30 105,18 120,26 135,14 150,24 165,16 180,28 195,20 210,30 225,18 240,26 255,14 270,22 285,10 300,18" />
    </svg>
  );
}

function ScanArtifactPanel({ form, setForm, result, setResult, loading, setLoading, error, setError, notify }) {
  const poll = useCallback(async (artifact_id) => {
    for (let i = 0; i < 30; i++) {
      await new Promise(r => setTimeout(r, 3000));
      try {
        const data = await api.getArtifact(artifact_id);
        if (["APPROVED", "BLOCKED", "REVIEW_REQUIRED", "FAILED"].includes(data.status)) {
          setResult(data); setLoading(false); return;
        }
      } catch { }
    }
    setError("Scan timed out."); setLoading(false);
  }, [setResult, setLoading, setError]);

  const submit = async () => {
    if (!form.source_url.trim()) { setError("Source URL is required."); return; }
    setLoading(true); setResult(null); setError("");
    try {
      const { artifact_id } = await api.scanArtifact(form);
      notify(`Scan queued: ${artifact_id}`);
      poll(artifact_id);
    } catch (e) {
      setError(e.message || "Scan submission failed."); setLoading(false);
    }
  };

  return (
    <div className="space-y-3">
      <p className="text-xs" style={{ color: COLORS.inkDim }}>Submit an artifact URL to the scanner pipeline.</p>
      <select value={form.artifact_type} onChange={e => setForm(f => ({ ...f, artifact_type: e.target.value }))}
        className="w-full rounded-xl px-3 py-2 text-sm outline-none" style={{ background: COLORS.canvas }}>
        <option value="python_package">Python Package</option>
        <option value="github_repo">GitHub Repo</option>
        <option value="generic_file">Generic File</option>
      </select>
      <input value={form.source_url} onChange={e => setForm(f => ({ ...f, source_url: e.target.value }))}
        placeholder="https://files.pythonhosted.org/..." className="w-full rounded-xl px-3 py-2 text-sm outline-none"
        style={{ background: COLORS.canvas }} />
      <input value={form.requested_by} onChange={e => setForm(f => ({ ...f, requested_by: e.target.value }))}
        placeholder="Requested by (agent ID)" className="w-full rounded-xl px-3 py-2 text-sm outline-none"
        style={{ background: COLORS.canvas }} />
      {error && <p className="text-xs font-semibold" style={{ color: COLORS.accent }}>{error}</p>}
      <button onClick={submit} disabled={loading}
        className="w-full rounded-full py-2.5 text-sm font-bold text-white disabled:opacity-50"
        style={{ background: COLORS.ink }}>{loading ? "Scanning…" : "Submit Scan"}</button>
      {result && (
        <div className="rounded-xl p-3 text-sm" style={{ background: COLORS.canvas }}>
          <div className="flex justify-between items-center mb-1">
            <b>{result.artifact_id}</b>
            <span className="font-bold text-xs" style={{ color: DECISION_COLOR[result.verdict?.decision] || COLORS.inkDim }}>
              {result.verdict?.decision || result.status}
            </span>
          </div>
          {result.verdict && <>
            <div className="text-xs" style={{ color: COLORS.inkDim }}>
              Risk score: <b style={{ color: COLORS.ink }}>{result.verdict.risk_score}</b> · {result.verdict.risk_level}
            </div>
            {result.verdict.blocked_reasons?.length > 0 && (
              <ul className="mt-1 text-xs list-disc pl-4" style={{ color: COLORS.accent }}>
                {result.verdict.blocked_reasons.map((r, i) => <li key={i}>{r}</li>)}
              </ul>
            )}
          </>}
          {result.agent_report && <p className="mt-2 text-xs" style={{ color: COLORS.inkDim }}>{result.agent_report}</p>}
        </div>
      )}
    </div>
  );
}

function useApiData(fetcher, interval = 0) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const load = useCallback(async () => {
    try { setData(await fetcher()); } catch { } finally { setLoading(false); }
  }, []);
  useEffect(() => {
    load();
    if (interval > 0) {
      const t = setInterval(load, interval);
      return () => clearInterval(t);
    }
  }, [load, interval]);
  return { data, loading, reload: load };
}

export default function KavachDashboard() {
  const { data: agentsData, reload: reloadAgents } = useApiData(api.getAgents, 15000);
  const { data: dashData, reload: reloadDash } = useApiData(api.getDashboard, 15000);
  const { data: eventsData, reload: reloadEvents } = useApiData(api.getEvents, 10000);
  const { data: incidentsData, reload: reloadIncidents } = useApiData(api.getIncidents, 15000);

  const agents = useMemo(() => {
    if (!agentsData) return [];
    return agentsData.map(a => ({
      id: a.agent_id,
      name: a.agent_id.replace(/-/g, " ").replace(/\b\w/g, c => c.toUpperCase()),
      status: a.state === "ACTIVE" ? "Active" : a.state === "QUARANTINED" ? "Isolated" : a.state,
      role: a.role,
      state: a.state,
    }));
  }, [agentsData]);

  const events = useMemo(() => {
    if (!eventsData) return [];
    return eventsData.slice(0, 50).map((e, i) => ({
      id: e.event_id || i,
      time: new Date(e.timestamp).toLocaleTimeString(),
      agent: e.source_agent,
      event: `${e.action} on ${e.resource}`,
      severity: e.risk_score >= 80 ? "Critical" : e.risk_score >= 50 ? "Medium" : "Low",
      decision: e.policy_decision === "ALLOW" ? "Allow" : "Deny",
    }));
  }, [eventsData]);

  const incidents = useMemo(() => incidentsData || [], [incidentsData]);
  const topIncident = incidents.find(i => i.status === "OPEN" && i.severity === "HIGH") || incidents[0];

  const [query, setQuery] = useState("");
  const [activityQuery, setActivityQuery] = useState("");
  const [severity, setSeverity] = useState("All");
  const [policyFilter, setPolicyFilter] = useState(false);
  const [systemLocked, setSystemLocked] = useState(false);
  const [showLockConfirm, setShowLockConfirm] = useState(false);
  const [modal, setModal] = useState("");
  const [selectedAgentId, setSelectedAgentId] = useState("");
  const [notice, setNotice] = useState("");
  const [navOpen, setNavOpen] = useState(false);
  const [scanForm, setScanForm] = useState({ artifact_type: "python_package", source_url: "", requested_by: "operator" });
  const [scanResult, setScanResult] = useState(null);
  const [scanLoading, setScanLoading] = useState(false);
  const [scanError, setScanError] = useState("");

  useEffect(() => {
    if (agents.length > 0 && !selectedAgentId) setSelectedAgentId(agents[0].id);
  }, [agents, selectedAgentId]);

  const notify = (msg) => { setNotice(msg); setTimeout(() => setNotice(""), 2800); };

  const selected = agents.find(a => a.id === selectedAgentId) || agents[0];

  const filteredEvents = useMemo(() => events.filter(e => {
    const q = activityQuery.toLowerCase();
    const matchQ = !q || `${e.agent} ${e.event} ${e.severity} ${e.decision}`.toLowerCase().includes(q);
    const matchS = severity === "All" || e.severity === severity;
    const matchP = !policyFilter || e.event.toLowerCase().includes("policy");
    return matchQ && matchS && matchP;
  }), [events, activityQuery, severity, policyFilter]);

  const filteredAgents = useMemo(() =>
    agents.filter(a => !query || a.id.toLowerCase().includes(query.toLowerCase()) || a.name.toLowerCase().includes(query.toLowerCase())),
    [agents, query]);

  const isolateAgent = async (id) => {
    try {
      await api.isolateAgent(id);
      notify(`${id} isolated.`);
      reloadAgents(); reloadDash();
    } catch (e) { notify(`Failed: ${e.message}`); }
  };

  const restoreAgent = async (id) => {
    if (systemLocked) { notify("System lock is enabled."); return; }
    try {
      await api.restoreAgent(id);
      notify(`${id} restored.`);
      reloadAgents(); reloadDash();
    } catch (e) { notify(`Failed: ${e.message}`); }
  };

  const resolveIncident = async (id) => {
    try {
      await fetch(`/api/incidents/${id}/resolve`, { method: "PATCH", headers: { "x-api-key": import.meta.env.VITE_API_KEY || "" } });
      notify("Incident resolved.");
      reloadIncidents();
    } catch { notify("Failed to resolve incident."); }
  };

  const reloadAll = () => { reloadAgents(); reloadDash(); reloadEvents(); reloadIncidents(); notify("Refreshed."); };

  const activeCount = agents.filter(a => a.state === "ACTIVE").length;
  const quarantinedCount = agents.filter(a => a.state === "QUARANTINED").length;
  const denyCount = dashData?.recent_events?.deny || 0;
  const allowCount = dashData?.recent_events?.allow || 0;
  const openIncidents = dashData?.incidents?.open || 0;
  const containPct = agents.length > 0 ? Math.round((activeCount / agents.length) * 100) : 0;

  return (
    <div className="min-h-screen w-full overflow-auto p-3 md:p-4" style={{
      background: "radial-gradient(ellipse 90% 70% at 10% 10%, rgba(255,214,170,.5), transparent 60%), radial-gradient(ellipse 90% 70% at 90% 5%, rgba(178,205,255,.5), transparent 60%), linear-gradient(135deg,#eef0f4,#e9ecf2 50%,#eceef4)",
      fontFamily: "Manrope, ui-sans-serif, system-ui, sans-serif"
    }}>
      <div className="mx-auto max-w-[1440px] rounded-[28px] p-3 md:p-4 flex flex-col gap-3"
        style={{ background: "rgba(243,244,246,.65)", backdropFilter: "blur(26px)" }}>

        {/* Header */}
        <header className="flex items-center justify-between gap-3 flex-wrap">
          <div className="flex items-center gap-3">
            <button onClick={() => setNavOpen(v => !v)} className="w-10 h-10 rounded-full bg-white flex items-center justify-center"><Menu size={16} /></button>
            <div className="w-10 h-10 rounded-full flex items-center justify-center font-extrabold text-white" style={{ background: COLORS.ink }}>KV</div>
            <div className="leading-tight"><b className="text-sm">Kavach</b><div className="text-sm font-semibold" style={{ color: COLORS.inkDim }}>Zero-Trust Runtime Security</div></div>
            {navOpen && (
              <div className="flex gap-2 ml-2">
                <Pill onClick={() => { setModal("agents"); setNavOpen(false); }}>Agents</Pill>
                <Pill onClick={() => { setModal("activity"); setNavOpen(false); }}>Activity</Pill>
                <Pill onClick={() => { setModal("incidents"); setNavOpen(false); }}>Incidents</Pill>
                <Pill onClick={() => { setModal("scan"); setScanResult(null); setScanError(""); setNavOpen(false); }}>Scan Artifact</Pill>
              </div>
            )}
          </div>
          <div className="flex items-center gap-3">
            <button onClick={reloadAll} title="Refresh" className="w-10 h-10 rounded-full bg-white flex items-center justify-center"><RefreshCw size={15} /></button>
            <button onClick={() => setModal("incidents")} title="Incidents" className="w-10 h-10 rounded-full bg-white flex items-center justify-center relative">
              <Bell size={16} />
              {openIncidents > 0 && <span className="absolute top-1 right-1 w-4 h-4 rounded-full text-[9px] font-bold text-white flex items-center justify-center" style={{ background: COLORS.accent }}>{openIncidents}</span>}
            </button>
            <div className="flex items-center gap-2">
              <div className="w-9 h-9 rounded-full flex items-center justify-center text-white font-bold text-xs" style={{ background: "linear-gradient(135deg,#2b2e36,#54586a)" }}>SL</div>
              <div className="text-xs"><b>Security Lead</b><div style={{ color: COLORS.inkDim }}>On shift</div></div>
            </div>
            <div className="hidden sm:flex items-center gap-2 bg-white rounded-full px-3 py-2">
              <Search size={13} color={COLORS.inkDim} />
              <input value={query} onChange={e => setQuery(e.target.value)} placeholder="Search agents..." className="bg-transparent outline-none text-xs w-32" />
            </div>
          </div>
        </header>

        {/* Banner */}
        <section className="bg-white rounded-[22px] px-5 py-4 flex items-center justify-between gap-4 flex-wrap">
          <div className="flex items-center gap-3">
            <div className="w-12 h-12 rounded-full border flex items-center justify-center text-lg font-extrabold" style={{ borderColor: COLORS.line }}>
              {new Date().getDate()}
            </div>
            <div className="hidden sm:block text-xs" style={{ color: COLORS.inkDim }}>
              <b className="block" style={{ color: COLORS.ink }}>{new Date().toLocaleDateString("en", { weekday: "short" })},</b>
              {new Date().toLocaleDateString("en", { month: "long" })}
            </div>
            <button onClick={() => setModal("incidents")} className="flex items-center gap-2 rounded-full px-4 py-2.5 text-xs font-bold text-white" style={{ background: COLORS.accent }}>
              Review incidents <ArrowRight size={13} />
            </button>
          </div>
          <div className="flex-1 min-w-[220px]">
            <h1 className="text-lg font-extrabold">Fleet security overview 🛡️</h1>
            <p className="text-xs font-semibold" style={{ color: COLORS.inkFaint }}>
              {systemLocked ? "System lock is ENABLED." : `${activeCount} active · ${quarantinedCount} quarantined · ${openIncidents} open incidents`}
            </p>
          </div>
        </section>

        {/* Main grid */}
        <div className="grid gap-3 xl:grid-cols-[64px_1.35fr_1fr_.75fr_1fr_1fr]">
          <Card className="hidden xl:flex flex-col items-center justify-between">
            <button onClick={() => setModal("agents")} className="w-9 h-9 rounded-full border flex items-center justify-center">⇄</button>
            <button onClick={reloadAll} className="w-9 h-9 rounded-full border flex items-center justify-center"><RefreshCw size={13} /></button>
          </Card>

          {/* Agent control */}
          <Card className="flex flex-col">
            <div className="flex justify-between items-center mb-3">
              <b className="text-xs uppercase tracking-wide flex items-center gap-2">
                <span className="w-2 h-2 rounded-full" style={{ background: COLORS.accent }} />Agent control
              </b>
              {selected && <span className="text-[11px] font-semibold rounded-full px-2 py-1" style={{ background: selected.state === "ACTIVE" ? "#dcfce7" : COLORS.accentSoft, color: selected.state === "ACTIVE" ? COLORS.green : COLORS.accent }}>{selected.status}</span>}
            </div>
            <label className="text-[11px] mb-1" style={{ color: COLORS.inkDim }}>Select agent</label>
            <select value={selectedAgentId} onChange={e => setSelectedAgentId(e.target.value)} className="w-full rounded-xl bg-gray-100 px-3 py-2 text-sm mb-2 outline-none">
              {agents.map(a => <option key={a.id} value={a.id}>{a.name} · {a.id}</option>)}
            </select>
            {selected && <>
              <div className="text-[11px]" style={{ color: COLORS.inkDim }}>{selected.role}</div>
              <div className="text-sm font-bold tracking-wide mb-3">{selected.id}</div>
              <div className="flex gap-2">
                <button disabled={selected.state === "QUARANTINED"} onClick={() => isolateAgent(selected.id)}
                  className="flex-1 rounded-full py-2 text-xs font-bold text-white disabled:opacity-40" style={{ background: COLORS.ink }}>Isolate</button>
                <button disabled={selected.state === "ACTIVE" || systemLocked} onClick={() => restoreAgent(selected.id)}
                  className="flex-1 rounded-full py-2 text-xs font-bold disabled:opacity-40" style={{ background: COLORS.canvas }}>Resume</button>
              </div>
            </>}
          </Card>

          {/* Stats */}
          <div className="grid grid-rows-2 gap-3">
            <Card className="flex flex-col justify-center">
              <div className="text-[11px]" style={{ color: COLORS.inkDim }}>Denied requests <Pill onClick={() => setModal("activity")}>Recent ▾</Pill></div>
              <b className="text-2xl">{denyCount}</b>
            </Card>
            <Card className="flex flex-col justify-center">
              <div className="text-[11px]" style={{ color: COLORS.inkDim }}>Allowed requests <button onClick={() => setModal("activity")} className="float-right font-bold" style={{ color: COLORS.accent }}>View log</button></div>
              <b className="text-2xl">{allowCount}</b>
            </Card>
          </div>

          {/* System lock */}
          <Card className="flex flex-col items-center justify-center text-center gap-2">
            <button onClick={() => setShowLockConfirm(true)} className="w-11 h-11 rounded-full flex items-center justify-center text-white" style={{ background: systemLocked ? COLORS.accent : COLORS.ink }}>
              <Lock size={15} />
            </button>
            <b className="text-xs">System Lock</b>
            <span className="text-[10px]" style={{ color: systemLocked ? COLORS.accent : COLORS.inkDim }}>{systemLocked ? "Enabled" : "Disabled"}</span>
          </Card>

          {/* Agents summary */}
          <Card className="flex flex-col">
            <b className="text-xl">{agents.length} Agents</b>
            <span className="text-[11px] mb-3" style={{ color: COLORS.inkDim }}>{activeCount} active · {quarantinedCount} quarantined</span>
            <div className="flex gap-1 mt-auto">
              {agents.map((a, i) => (
                <span key={a.id} className="w-2 h-2 rounded-full" style={{ background: a.state === "ACTIVE" ? COLORS.green : COLORS.accent }} title={a.id} />
              ))}
            </div>
          </Card>

          {/* Risk */}
          <Card className="flex flex-col">
            <div className="flex justify-between">
              <b className="text-lg">Risk {selected?.state === "QUARANTINED" ? "HIGH" : "LOW"}</b>
              <span className="text-[10px] rounded-full px-2 py-1" style={{ background: COLORS.accentSoft, color: COLORS.accent }}>Live</span>
            </div>
            <b className="text-xs mt-2">{selected?.id || "—"}</b>
            <span className="text-[10px]" style={{ color: COLORS.inkDim }}>State: {selected?.state || "—"}</span>
            <Wave />
          </Card>

          <Card dark className="flex items-center justify-center"><Donut percent={containPct} /></Card>

          {/* Open incidents count */}
          <Card className="flex flex-col">
            <div className="flex justify-between text-[10px] font-bold mb-2" style={{ color: COLORS.inkFaint }}>
              Open incidents <Pill active>Live</Pill>
            </div>
            <b className="text-2xl">{openIncidents}</b>
            <div className="text-[10px] mt-2" style={{ color: COLORS.inkDim }}>Total: {dashData?.incidents?.total || 0}</div>
          </Card>
        </div>

        {/* Bottom grid */}
        <div className="grid gap-3 lg:grid-cols-[.85fr_1.9fr_.9fr]">
          {/* Severity breakdown */}
          <Card className="flex flex-col min-h-[250px]">
            <div className="flex justify-between mb-3"><b className="text-sm">Events by decision</b></div>
            <div className="flex-1 flex flex-col justify-center gap-3 px-2">
              {[["Allow", allowCount, COLORS.green], ["Deny", denyCount, COLORS.accent]].map(([label, count, color]) => (
                <div key={label}>
                  <div className="flex justify-between text-xs mb-1"><span>{label}</span><b>{count}</b></div>
                  <div className="w-full rounded-full h-2" style={{ background: COLORS.canvas }}>
                    <div className="h-2 rounded-full" style={{ width: `${(allowCount + denyCount) > 0 ? Math.round(count / (allowCount + denyCount) * 100) : 0}%`, background: color }} />
                  </div>
                </div>
              ))}
            </div>
          </Card>

          {/* Activity log */}
          <Card className="flex flex-col min-h-[300px]">
            <div className="flex justify-between items-center flex-wrap gap-2 mb-3">
              <b className="text-sm">Agent activity</b>
              <div className="flex gap-2">
                <button onClick={() => setModal("activity")} className="w-7 h-7 rounded-full flex items-center justify-center" style={{ background: COLORS.canvas }}><Maximize2 size={12} /></button>
                <button onClick={() => { setSeverity("All"); setPolicyFilter(false); setActivityQuery(""); }} className="w-7 h-7 rounded-full flex items-center justify-center" style={{ background: COLORS.canvas }}><RotateCcw size={12} /></button>
              </div>
            </div>
            <div className="flex flex-wrap gap-2 mb-3">
              <div className="flex-1 min-w-[140px] flex items-center gap-2 rounded-full px-3 py-2" style={{ background: COLORS.canvas }}>
                <Search size={12} />
                <input value={activityQuery} onChange={e => setActivityQuery(e.target.value)} placeholder="Search activity..." className="bg-transparent outline-none text-xs w-full" />
              </div>
              <select value={severity} onChange={e => setSeverity(e.target.value)} className="rounded-full px-3 py-2 text-xs" style={{ background: COLORS.canvas }}>
                <option>All</option><option>Critical</option><option>Medium</option><option>Low</option>
              </select>
              <Pill active={policyFilter} onClick={() => setPolicyFilter(v => !v)}>Policies {policyFilter && <X size={10} className="inline" />}</Pill>
            </div>
            <div className="overflow-auto">
              {filteredEvents.length === 0
                ? <p className="text-xs py-6 text-center" style={{ color: COLORS.inkDim }}>No matching activity.</p>
                : filteredEvents.slice(0, 8).map(e => (
                  <div key={e.id} className="flex items-center gap-3 py-3 border-t" style={{ borderColor: COLORS.line }}>
                    <span className="text-[10px] w-14 shrink-0" style={{ color: COLORS.inkDim }}>{e.time}</span>
                    <div className="flex-1 min-w-0"><b className="block text-xs truncate">{e.event}</b><span className="text-[10px]" style={{ color: COLORS.inkDim }}>{e.agent}</span></div>
                    <span className="text-[10px] font-bold" style={{ color: SEV_COLOR[e.severity] || COLORS.inkDim }}>{e.severity}</span>
                    <span className="text-[10px] font-bold" style={{ color: e.decision === "Deny" ? COLORS.accent : COLORS.green }}>{e.decision}</span>
                  </div>
                ))}
            </div>
          </Card>

          {/* Top incident */}
          <Card dark className="flex flex-col min-h-[250px]">
            {topIncident ? <>
              <div className="flex items-center gap-2 mb-3 text-[10px] font-extrabold" style={{ color: COLORS.accent }}>
                <span className="w-2 h-2 rounded-full" style={{ background: COLORS.accent }} />{topIncident.severity} INCIDENT
              </div>
              <div className="text-[11px] text-gray-400">{topIncident.agent_id}</div>
              <h3 className="text-base font-extrabold my-2">{topIncident.reason_codes?.[0] || "Security violation"}</h3>
              <div className="text-[11px] text-gray-400">Status: <b className="text-white">{topIncident.status}</b></div>
              <div className="text-[11px] text-gray-400 mt-1">ID: <b className="text-white">{topIncident.incident_id}</b></div>
              <button onClick={() => setModal("incidents")} className="mt-auto rounded-full py-2.5 text-xs font-bold text-white" style={{ background: "#343640" }}>
                View incidents <ArrowRight size={12} className="inline" />
              </button>
            </> : (
              <div className="flex flex-col items-center justify-center flex-1 text-gray-400 text-sm">No open incidents</div>
            )}
          </Card>
        </div>
      </div>

      {/* Toast */}
      {notice && (
        <div className="fixed bottom-5 right-5 z-50 rounded-xl px-4 py-3 text-sm font-semibold text-white shadow-xl" style={{ background: COLORS.ink }}>
          <Check size={15} className="inline mr-2" />{notice}
        </div>
      )}

      {/* Modals */}
      {(showLockConfirm || modal) && (
        <div className="fixed inset-0 z-40 bg-black/30 backdrop-blur-sm flex items-center justify-center p-4" onClick={() => { setShowLockConfirm(false); setModal(""); }}>
          <div className="w-full max-w-lg rounded-3xl bg-white p-5 shadow-2xl" onClick={e => e.stopPropagation()}>
            <div className="flex items-center justify-between mb-4">
              <h2 className="font-extrabold text-lg">
                {showLockConfirm ? "System lock" : modal === "agents" ? "Agent inventory" : modal === "activity" ? "Activity log" : modal === "incidents" ? "Incidents" : modal === "scan" ? "Scan artifact" : "Kavach"}
              </h2>
              <button onClick={() => { setShowLockConfirm(false); setModal(""); }} className="w-8 h-8 rounded-full flex items-center justify-center" style={{ background: COLORS.canvas }}><X size={16} /></button>
            </div>

            {showLockConfirm && (
              <>
                <p className="text-sm mb-4">{systemLocked ? "Disable the system lock?" : "Enable system lock? This prevents resuming isolated agents."}</p>
                <div className="flex justify-end gap-2">
                  <button onClick={() => setShowLockConfirm(false)} className="rounded-full px-4 py-2 text-sm" style={{ background: COLORS.canvas }}>Cancel</button>
                  <button onClick={() => { setSystemLocked(v => !v); setShowLockConfirm(false); notify(`System lock ${systemLocked ? "disabled" : "enabled"}.`); }}
                    className="rounded-full px-4 py-2 text-sm text-white" style={{ background: COLORS.ink }}>
                    {systemLocked ? "Disable lock" : "Enable lock"}
                  </button>
                </div>
              </>
            )}

            {modal === "agents" && (
              <div className="space-y-2 max-h-96 overflow-auto">
                {filteredAgents.map(a => (
                  <div key={a.id} className="rounded-xl p-3 flex justify-between items-center" style={{ background: COLORS.canvas }}>
                    <div>
                      <b className="text-sm">{a.name}</b>
                      <span className="block text-xs text-gray-500">{a.id} · {a.role}</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <span className="text-xs font-bold" style={{ color: STATE_COLOR[a.state] || COLORS.inkDim }}>{a.status}</span>
                      {a.state === "ACTIVE"
                        ? <button onClick={() => { isolateAgent(a.id); }} className="text-[10px] rounded-full px-2 py-1 text-white" style={{ background: COLORS.accent }}>Isolate</button>
                        : <button onClick={() => { restoreAgent(a.id); }} className="text-[10px] rounded-full px-2 py-1 text-white" style={{ background: COLORS.green }}>Restore</button>
                      }
                    </div>
                  </div>
                ))}
              </div>
            )}

            {modal === "activity" && (
              <div className="space-y-2 max-h-96 overflow-auto">
                {events.map(e => (
                  <div key={e.id} className="rounded-xl p-3" style={{ background: COLORS.canvas }}>
                    <div className="text-xs text-gray-500">{e.time} · {e.agent}</div>
                    <b className="text-sm">{e.event}</b>
                    <div className="text-xs mt-1" style={{ color: e.decision === "Deny" ? COLORS.accent : COLORS.green }}>{e.severity} · {e.decision}</div>
                  </div>
                ))}
                {events.length === 0 && <p className="text-sm text-gray-500 text-center py-4">No events yet.</p>}
              </div>
            )}

            {modal === "incidents" && (
              <div className="space-y-2 max-h-96 overflow-auto">
                {incidents.map(i => (
                  <div key={i.incident_id} className="rounded-xl p-3" style={{ background: COLORS.canvas }}>
                    <div className="flex justify-between items-start">
                      <div>
                        <b className="text-sm">{i.incident_id}</b>
                        <div className="text-xs text-gray-500">{i.agent_id} · {new Date(i.timestamp).toLocaleString()}</div>
                        <div className="text-xs mt-1">{i.reason_codes?.join(", ")}</div>
                      </div>
                      <div className="flex flex-col items-end gap-1">
                        <span className="text-xs font-bold" style={{ color: i.severity === "HIGH" ? COLORS.accent : COLORS.inkDim }}>{i.severity}</span>
                        {i.status === "OPEN" && (
                          <button onClick={() => resolveIncident(i.incident_id)} className="text-[10px] rounded-full px-2 py-1 text-white" style={{ background: COLORS.green }}>Resolve</button>
                        )}
                        {i.status !== "OPEN" && <span className="text-[10px] text-gray-400">{i.status}</span>}
                      </div>
                    </div>
                  </div>
                ))}
                {incidents.length === 0 && <p className="text-sm text-gray-500 text-center py-4">No incidents.</p>}
              </div>
            )}

            {modal === "scan" && (
              <ScanArtifactPanel
                form={scanForm} setForm={setScanForm}
                result={scanResult} setResult={setScanResult}
                loading={scanLoading} setLoading={setScanLoading}
                error={scanError} setError={setScanError}
                notify={notify}
              />
            )}
          </div>
        </div>
      )}

      <div className="max-w-[1440px] mx-auto mt-2 text-[10px] text-center text-gray-500">
        Kavach · scanner · shield · agents · all live
      </div>
    </div>
  );
}
