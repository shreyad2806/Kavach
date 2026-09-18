import React, { useMemo, useState, useCallback } from "react";
import { api } from "./api.js";
import {
  Menu, Plus, Search, Mic, Calendar, Lock, ArrowRight, ArrowUpRight,
  MoreVertical, Maximize2, SlidersHorizontal, X, Scale, ListChecks,
  ShieldCheck, Bell, Activity, ChevronDown, Check, AlertTriangle, RotateCcw
} from "lucide-react";

const COLORS = {
  page: "#e9eaec", canvas: "#f3f4f6", card: "#ffffff", ink: "#15161a",
  inkDim: "#8b8d95", inkFaint: "#b7b9c1", accent: "#ff5a3c",
  accentSoft: "#ffe4dc", line: "#ececee", green: "#16865b"
};

const initialAgents = [
  { id: "rsch-2719", name: "Research Agent", status: "Active", blocked: 4, scope: "Sandbox environment", risk: 24 },
  { id: "agent-03", name: "Agent-03", status: "Isolated", blocked: 7, scope: "Credential access", risk: 96 },
  { id: "agent-07", name: "Data Analyst", status: "Active", blocked: 2, scope: "Read-only dataset", risk: 18 },
];

const initialEvents = [
  { id: 1, time: "15:42:08", agent: "Agent-03", event: "Credential access attempt", severity: "Critical", decision: "Deny" },
  { id: 2, time: "15:39:21", agent: "Research Agent", event: "Outbound call blocked", severity: "Medium", decision: "Deny" },
  { id: 3, time: "15:31:54", agent: "Data Analyst", event: "Policy check passed", severity: "Low", decision: "Allow" },
  { id: 4, time: "15:18:03", agent: "Research Agent", event: "Sandbox scope verified", severity: "Low", decision: "Allow" },
];

function Card({ children, className = "", dark = false, style = {} }) {
  return <div className={`rounded-2xl p-4 ${className}`} style={{
    backgroundColor: dark ? COLORS.ink : COLORS.card, color: dark ? "#fff" : COLORS.ink,
    boxShadow: "0 8px 30px rgba(35,38,48,.035)", ...style
  }}>{children}</div>;
}
function Pill({ children, onClick, active = false }) {
  return <button onClick={onClick} className="text-[11px] font-semibold rounded-full px-3 py-1.5 whitespace-nowrap"
    style={{ background: active ? COLORS.ink : COLORS.canvas, color: active ? "#fff" : COLORS.ink }}>{children}</button>;
}
function Donut({ percent = 86 }) {
  const r = 34, c = 2 * Math.PI * r;
  return <div className="relative w-[78px] h-[78px]">
    <svg width="78" height="78" viewBox="0 0 84 84" style={{ transform: "rotate(-90deg)" }}>
      <circle cx="42" cy="42" r={r} fill="none" stroke="#2a2c33" strokeWidth="8"/>
      <circle cx="42" cy="42" r={r} fill="none" stroke={COLORS.accent} strokeWidth="8"
        strokeDasharray={c} strokeDashoffset={c - percent / 100 * c} strokeLinecap="round"/>
    </svg>
    <div className="absolute inset-0 flex flex-col items-center justify-center text-white">
      <b className="text-[15px]">{percent}%</b><span className="text-[7px] text-gray-400">Containment</span>
    </div>
  </div>;
}
function MiniBars() {
  return <div className="flex items-end gap-1.5 flex-1 min-h-9">{[30,45,38,60,50,70,48].map((h,i)=>
    <div key={i} className="flex-1 rounded-t" style={{height:`${h}%`,background:i===5?COLORS.accent:COLORS.line}}/>)}</div>;
}
function Wave() {
  return <svg className="w-full flex-1" viewBox="0 0 300 56" preserveAspectRatio="none" style={{minHeight:40}}>
    <polyline fill="none" stroke={COLORS.accent} strokeWidth="2.4"
      points="0,34 15,30 30,38 45,24 60,32 75,20 90,30 105,18 120,26 135,14 150,24 165,16 180,28 195,20 210,30 225,18 240,26 255,14 270,22 285,10 300,18"/>
  </svg>;
}

const DECISION_COLOR = { APPROVED: "#16865b", BLOCKED: "#ff5a3c", REVIEW_REQUIRED: "#d97706" };

function ScanArtifactPanel({ form, setForm, result, setResult, loading, setLoading, error, setError, notify }) {
  const poll = useCallback(async (artifact_id) => {
    for (let i = 0; i < 30; i++) {
      await new Promise(r => setTimeout(r, 3000));
      try {
        const data = await api.getArtifact(artifact_id);
        if (["APPROVED","BLOCKED","REVIEW_REQUIRED","FAILED"].includes(data.status)) {
          setResult(data); setLoading(false); return;
        }
      } catch {}
    }
    setError("Scan timed out. Check back later."); setLoading(false);
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

  return <div className="space-y-3">
    <p className="text-xs" style={{color:COLORS.inkDim}}>Submit an artifact URL to the scanner pipeline.</p>
    <select value={form.artifact_type} onChange={e=>setForm(f=>({...f,artifact_type:e.target.value}))}
      className="w-full rounded-xl px-3 py-2 text-sm outline-none" style={{background:COLORS.canvas}}>
      <option value="python_package">Python Package</option>
      <option value="github_repo">GitHub Repo</option>
      <option value="generic_file">Generic File</option>
    </select>
    <input value={form.source_url} onChange={e=>setForm(f=>({...f,source_url:e.target.value}))}
      placeholder="https://files.pythonhosted.org/..." className="w-full rounded-xl px-3 py-2 text-sm outline-none"
      style={{background:COLORS.canvas}} />
    <input value={form.requested_by} onChange={e=>setForm(f=>({...f,requested_by:e.target.value}))}
      placeholder="Requested by (agent ID)" className="w-full rounded-xl px-3 py-2 text-sm outline-none"
      style={{background:COLORS.canvas}} />
    {error && <p className="text-xs font-semibold" style={{color:COLORS.accent}}>{error}</p>}
    <button onClick={submit} disabled={loading}
      className="w-full rounded-full py-2.5 text-sm font-bold text-white disabled:opacity-50"
      style={{background:COLORS.ink}}>{loading ? "Scanning…" : "Submit Scan"}</button>
    {result && <div className="rounded-xl p-3 text-sm" style={{background:COLORS.canvas}}>
      <div className="flex justify-between items-center mb-1">
        <b>{result.artifact_id}</b>
        <span className="font-bold text-xs" style={{color:DECISION_COLOR[result.verdict?.decision] || COLORS.inkDim}}>
          {result.verdict?.decision || result.status}
        </span>
      </div>
      {result.verdict && <>
        <div className="text-xs" style={{color:COLORS.inkDim}}>Risk score: <b style={{color:COLORS.ink}}>{result.verdict.risk_score}</b> · {result.verdict.risk_level}</div>
        {result.verdict.blocked_reasons?.length > 0 && <ul className="mt-1 text-xs list-disc pl-4" style={{color:COLORS.accent}}>
          {result.verdict.blocked_reasons.map((r,i)=><li key={i}>{r}</li>)}
        </ul>}
      </>}
      {result.agent_report && <p className="mt-2 text-xs" style={{color:COLORS.inkDim}}>{result.agent_report}</p>}
    </div>}
  </div>;
}

export default function KavachDashboard() {
  const [agents, setAgents] = useState(initialAgents);
  const [events, setEvents] = useState(initialEvents);
  const [query, setQuery] = useState("");
  const [activityQuery, setActivityQuery] = useState("");
  const [severity, setSeverity] = useState("All");
  const [policyFilter, setPolicyFilter] = useState(false);
  const [todayFilter, setTodayFilter] = useState(true);
  const [systemLocked, setSystemLocked] = useState(false);
  const [showLockConfirm, setShowLockConfirm] = useState(false);
  const [modal, setModal] = useState("");
  const [selectedAgent, setSelectedAgent] = useState("rsch-2719");
  const [notice, setNotice] = useState("");
  const [reviewed, setReviewed] = useState([]);
  const [navOpen, setNavOpen] = useState(false);
  const [scanForm, setScanForm] = useState({ artifact_type: "python_package", source_url: "", requested_by: "operator" });
  const [scanResult, setScanResult] = useState(null);
  const [scanLoading, setScanLoading] = useState(false);
  const [scanError, setScanError] = useState("");

  const notify = (message) => { setNotice(message); window.setTimeout(() => setNotice(""), 2800); };
  const selected = agents.find(a => a.id === selectedAgent) || agents[0];
  const filteredEvents = useMemo(() => events.filter(e => {
    const q = activityQuery.toLowerCase();
    const matchesQuery = !q || `${e.agent} ${e.event} ${e.severity} ${e.decision}`.toLowerCase().includes(q);
    const matchesSeverity = severity === "All" || e.severity === severity;
    const matchesPolicy = !policyFilter || e.event.toLowerCase().includes("policy") || e.event.toLowerCase().includes("scope");
    return matchesQuery && matchesSeverity && matchesPolicy;
  }), [events, activityQuery, severity, policyFilter]);

  const updateAgent = (id, status) => {
    setAgents(prev => prev.map(a => a.id === id ? {...a, status} : a));
    const agent = agents.find(a => a.id === id);
    setEvents(prev => [{id:Date.now(),time:new Date().toLocaleTimeString(),agent:agent?.name || id,
      event:`Agent ${status.toLowerCase()}`,severity:status==="Isolated"?"Medium":"Low",
      decision:status==="Isolated"?"Deny":"Allow"}, ...prev]);
    notify(`${agent?.name || id} ${status.toLowerCase()}.`);
  };
  const addAgent = () => {
    const id = `agent-${String(agents.length + 8).padStart(2,"0")}`;
    setAgents(prev => [...prev,{id,name:"New Sandbox Agent",status:"Active",blocked:0,scope:"New sandbox",risk:12}]);
    setSelectedAgent(id); notify("New demo agent added.");
  };

  return <div className="min-h-screen w-full overflow-auto p-3 md:p-4" style={{
    background:"radial-gradient(ellipse 90% 70% at 10% 10%, rgba(255,214,170,.5), transparent 60%), radial-gradient(ellipse 90% 70% at 90% 5%, rgba(178,205,255,.5), transparent 60%), radial-gradient(ellipse 80% 70% at 50% 55%, rgba(230,210,255,.35), transparent 65%), linear-gradient(135deg,#eef0f4,#e9ecf2 50%,#eceef4)",
    fontFamily:"Manrope, ui-sans-serif, system-ui, sans-serif"
  }}>
    <div className="mx-auto max-w-[1440px] rounded-[28px] p-3 md:p-4 flex flex-col gap-3"
      style={{background:"rgba(243,244,246,.65)",backdropFilter:"blur(26px)"}}>
      <header className="flex items-center justify-between gap-3 flex-wrap">
        <div className="flex items-center gap-3">
          <button onClick={()=>setNavOpen(v=>!v)} aria-label="Open navigation" className="w-10 h-10 rounded-full bg-white flex items-center justify-center"><Menu size={16}/></button>
          <div className="w-10 h-10 rounded-full flex items-center justify-center font-extrabold text-white" style={{background:COLORS.ink}}>KV</div>
          <div className="leading-tight"><b className="text-sm">Kavach</b><div className="text-sm font-semibold" style={{color:COLORS.inkDim}}>Scanner</div></div>
          {navOpen && <div className="flex gap-2 ml-2"><Pill onClick={()=>{setModal("agents");setNavOpen(false)}}>Agents</Pill><Pill onClick={()=>{setModal("activity");setNavOpen(false)}}>Activity</Pill><Pill onClick={()=>{setModal("quarantine");setNavOpen(false)}}>Quarantine</Pill><Pill onClick={()=>{setModal("scan");setScanResult(null);setScanError("");setNavOpen(false)}}>Scan Artifact</Pill></div>}
        </div>
        <div className="flex items-center gap-3">
          <button onClick={addAgent} title="Add demo agent" className="w-10 h-10 rounded-full bg-white flex items-center justify-center"><Plus size={17}/></button>
          <button onClick={()=>setModal("notifications")} title="Notifications" className="w-10 h-10 rounded-full bg-white flex items-center justify-center"><Bell size={16}/></button>
          <div className="flex items-center gap-2"><div className="w-9 h-9 rounded-full flex items-center justify-center text-white font-bold text-xs" style={{background:"linear-gradient(135deg,#2b2e36,#54586a)"}}>SL</div><div className="text-xs"><b>Security Lead</b><div style={{color:COLORS.inkDim}}>On shift</div></div></div>
          <div className="hidden sm:flex items-center gap-2 bg-white rounded-full px-3 py-2"><Search size={13} color={COLORS.inkDim}/><input value={query} onChange={e=>setQuery(e.target.value)} placeholder="Search agents..." className="bg-transparent outline-none text-xs w-32"/></div>
        </div>
      </header>

      <section className="bg-white rounded-[22px] px-5 py-4 flex items-center justify-between gap-4 flex-wrap">
        <div className="flex items-center gap-3"><div className="w-12 h-12 rounded-full border flex items-center justify-center text-lg font-extrabold" style={{borderColor:COLORS.line}}>18</div>
          <div className="hidden sm:block text-xs" style={{color:COLORS.inkDim}}><b className="block" style={{color:COLORS.ink}}>Fri,</b>September</div>
          <button onClick={()=>setModal("quarantine")} className="flex items-center gap-2 rounded-full px-4 py-2.5 text-xs font-bold text-white" style={{background:COLORS.accent}}>Review blocks <ArrowRight size={13}/></button>
          <button onClick={()=>setModal("calendar")} className="w-10 h-10 rounded-2xl border flex items-center justify-center" style={{borderColor:COLORS.line}}><Calendar size={15}/></button>
        </div>
        <div className="flex-1 min-w-[220px]"><h1 className="text-lg font-extrabold">Fleet security overview 🛡️</h1><p className="text-xs font-semibold" style={{color:COLORS.inkFaint}}>{systemLocked?"System lock is ENABLED.":"Monitor agents, review events, and manage sandbox controls."}</p></div>
        <button onClick={()=>notify("Voice input is a demo control; connect a speech service to enable it.")} className="w-11 h-11 rounded-full flex items-center justify-center" style={{background:COLORS.canvas}}><Mic size={16}/></button>
      </section>

      <div className="grid gap-3 xl:grid-cols-[64px_1.35fr_1fr_.75fr_1fr_1fr]">
        <Card className="hidden xl:flex flex-col items-center justify-between"><button onClick={addAgent} className="w-9 h-9 rounded-full border flex items-center justify-center"><Plus size={15}/></button><button onClick={()=>setModal("agents")} className="w-9 h-9 rounded-full border">⇄</button></Card>
        <Card className="flex flex-col">
          <div className="flex justify-between items-center mb-3"><b className="text-xs uppercase tracking-wide flex items-center gap-2"><span className="w-2 h-2 rounded-full" style={{background:COLORS.accent}}/>Agent control</b><Pill>{selected.status} <ChevronDown size={11} className="inline"/></Pill></div>
          <label className="text-[11px] mb-1" style={{color:COLORS.inkDim}}>Select agent</label>
          <select value={selectedAgent} onChange={e=>setSelectedAgent(e.target.value)} className="w-full rounded-xl bg-gray-100 px-3 py-2 text-sm mb-2 outline-none">
            {agents.map(a=><option key={a.id} value={a.id}>{a.name} · {a.id}</option>)}
          </select>
          <div className="text-[11px]" style={{color:COLORS.inkDim}}>{selected.scope}</div><div className="text-sm font-bold tracking-wide mb-3">{selected.id}</div>
          <div className="flex gap-2">
            <button disabled={selected.status==="Isolated"} onClick={()=>updateAgent(selected.id,"Isolated")} className="flex-1 rounded-full py-2 text-xs font-bold text-white disabled:opacity-40" style={{background:COLORS.ink}}>Isolate</button>
            <button disabled={selected.status==="Active"||systemLocked} onClick={()=>updateAgent(selected.id,"Active")} className="flex-1 rounded-full py-2 text-xs font-bold disabled:opacity-40" style={{background:COLORS.canvas}}>Resume</button>
          </div>
          <div className="mt-auto pt-4 flex justify-between items-end"><div><div className="text-[11px]" style={{color:COLORS.inkDim}}>Blocked calls</div><b>{selected.blocked}</b></div><button onClick={()=>setModal("scope")} className="text-[11px] font-bold flex items-center gap-1" style={{color:COLORS.accent}}>Edit scope <ArrowUpRight size={12}/></button></div>
        </Card>
        <div className="grid grid-rows-2 gap-3"><Card className="flex flex-col justify-center"><div className="text-[11px]" style={{color:COLORS.inkDim}}>Threats blocked <Pill onClick={()=>setModal("activity")}>Weekly ▾</Pill></div><b className="text-2xl">128</b></Card><Card className="flex flex-col justify-center"><div className="text-[11px]" style={{color:COLORS.inkDim}}>Actions reviewed <button onClick={()=>setModal("activity")} className="float-right font-bold" style={{color:COLORS.accent}}>View log</button></div><b className="text-2xl">{1940+reviewed.length}</b></Card></div>
        <Card className="flex flex-col items-center justify-center text-center gap-2"><button onClick={()=>setShowLockConfirm(true)} className="w-11 h-11 rounded-full flex items-center justify-center text-white" style={{background:systemLocked?COLORS.accent:COLORS.ink}}><Lock size={15}/></button><b className="text-xs">System Lock</b><span className="text-[10px]" style={{color:systemLocked?COLORS.accent:COLORS.inkDim}}>{systemLocked?"Enabled":"Disabled"}</span></Card>
        <Card className="flex flex-col"><b className="text-xl">13 Days</b><span className="text-[11px] mb-3" style={{color:COLORS.inkDim}}>clean uptime</span><div className="flex gap-1 mt-auto">{Array.from({length:18},(_,i)=><span key={i} className="w-2 h-2 rounded-full" style={{background:i<10?COLORS.accent:COLORS.line}}/>)}</div></Card>
        <Card className="flex flex-col"><div className="flex justify-between"><b className="text-lg">Risk {selected.risk}</b><span className="text-[10px] rounded-full px-2 py-1" style={{background:COLORS.accentSoft,color:COLORS.accent}}>Live</span></div><b className="text-xs mt-2">Selected agent risk</b><span className="text-[10px]" style={{color:COLORS.inkDim}}>Demo score · not a live feed</span><Wave/></Card>
        <Card dark className="flex items-center justify-center"><Donut/></Card>
        <Card className="flex flex-col"><div className="flex justify-between text-[10px] font-bold mb-2" style={{color:COLORS.inkFaint}}>Last week <Pill active>This week</Pill></div><MiniBars/><div className="text-[10px] mt-2" style={{color:COLORS.inkDim}}>Blocked artifacts</div></Card>
      </div>

      <div className="grid gap-3 lg:grid-cols-[.85fr_1.9fr_.9fr]">
        <Card className="flex flex-col min-h-[250px]"><div className="flex justify-between mb-3"><b className="text-sm">Blocked by severity</b><Pill>2026 ▾</Pill></div>
          <div className="flex-1 flex items-center justify-center"><div className="relative w-44 h-44 rounded-full flex justify-center pt-4 font-bold text-xs" style={{background:"#ffe1d8",color:"#c8431f"}}>Low · 14<div className="absolute rounded-full flex justify-center pt-5" style={{inset:"17%",background:"#ffb79f",color:"#8f2c0f"}}>Med · 9<div className="absolute rounded-full flex justify-center pt-5 text-white" style={{inset:"35%",background:COLORS.accent}}>Crit · 3</div></div></div></div>
        </Card>
        <Card className="flex flex-col min-h-[300px]"><div className="flex justify-between items-center flex-wrap gap-2 mb-3"><b className="text-sm">Agent activity</b><div className="flex gap-2"><button onClick={()=>setModal("activity")} className="w-7 h-7 rounded-full flex items-center justify-center" style={{background:COLORS.canvas}}><Maximize2 size={12}/></button><button onClick={()=>{setSeverity("All");setPolicyFilter(false);setTodayFilter(false);setActivityQuery("");}} className="w-7 h-7 rounded-full flex items-center justify-center" style={{background:COLORS.canvas}}><RotateCcw size={12}/></button></div></div>
          <div className="flex flex-wrap gap-2 mb-3"><div className="flex-1 min-w-[140px] flex items-center gap-2 rounded-full px-3 py-2" style={{background:COLORS.canvas}}><Search size={12}/><input value={activityQuery} onChange={e=>setActivityQuery(e.target.value)} placeholder="Search activity..." className="bg-transparent outline-none text-xs w-full"/></div>
            <select value={severity} onChange={e=>setSeverity(e.target.value)} className="rounded-full px-3 py-2 text-xs" style={{background:COLORS.canvas}}><option>All</option><option>Critical</option><option>Medium</option><option>Low</option></select>
            <Pill active={policyFilter} onClick={()=>setPolicyFilter(v=>!v)}>Policies {policyFilter&&<X size={10} className="inline"/>}</Pill><Pill active={todayFilter} onClick={()=>setTodayFilter(v=>!v)}>Today {todayFilter&&<X size={10} className="inline"/>}</Pill>
          </div>
          <div className="overflow-auto">
            {filteredEvents.length===0?<p className="text-xs py-6 text-center" style={{color:COLORS.inkDim}}>No matching activity.</p>:filteredEvents.slice(0,5).map(e=><div key={e.id} className="flex items-center gap-3 py-3 border-t" style={{borderColor:COLORS.line}}><span className="text-[10px] w-14 shrink-0" style={{color:COLORS.inkDim}}>{e.time}</span><div className="flex-1 min-w-0"><b className="block text-xs truncate">{e.event}</b><span className="text-[10px]" style={{color:COLORS.inkDim}}>{e.agent}</span></div><span className="text-[10px] font-bold" style={{color:e.severity==="Critical"?COLORS.accent:COLORS.inkDim}}>{e.severity}</span><span className="text-[10px] font-bold">{e.decision}</span></div>)}
          </div>
        </Card>
        <Card dark className="flex flex-col min-h-[250px]"><div className="flex items-center gap-2 mb-3 text-[10px] font-extrabold" style={{color:COLORS.accent}}><span className="w-2 h-2 rounded-full" style={{background:COLORS.accent}}/>CRITICAL INCIDENT</div><div className="text-[11px] text-gray-400">Agent-03 · Credential access attempt</div><h3 className="text-base font-extrabold my-2">Risk score 96</h3><div className="text-[11px] text-gray-400">Cedar decision: <b className="text-white">DENY</b></div><div className="text-[11px] text-gray-400 mt-2">Enforcement: <b className="text-white">Agent isolated</b></div><button onClick={()=>setModal("incident")} className="mt-auto rounded-full py-2.5 text-xs font-bold text-white" style={{background:"#343640"}}>Inspect incident <ArrowRight size={12} className="inline"/></button></Card>
      </div>
    </div>

    {notice && <div className="fixed bottom-5 right-5 z-50 rounded-xl px-4 py-3 text-sm font-semibold text-white shadow-xl" style={{background:COLORS.ink}}><Check size={15} className="inline mr-2"/>{notice}</div>}

    {(showLockConfirm || modal) && <div className="fixed inset-0 z-40 bg-black/30 backdrop-blur-sm flex items-center justify-center p-4" onClick={()=>{setShowLockConfirm(false);setModal("")}}>
      <div className="w-full max-w-lg rounded-3xl bg-white p-5 shadow-2xl" onClick={e=>e.stopPropagation()}>
        <div className="flex items-center justify-between mb-4"><h2 className="font-extrabold text-lg">{showLockConfirm?"System lock":modal==="quarantine"?"Quarantine review":modal==="scope"?"Agent scope":modal==="scan"?"Scan artifact":modal==="incident"?"Incident details":modal==="agents"?"Agent inventory":modal==="activity"?"Activity log":modal==="calendar"?"Review calendar":modal==="notifications"?"Notifications":"Kavach"}</h2><button onClick={()=>{setShowLockConfirm(false);setModal("")}} className="w-8 h-8 rounded-full flex items-center justify-center" style={{background:COLORS.canvas}}><X size={16}/></button></div>
        {showLockConfirm ? <><p className="text-sm mb-4">{systemLocked?"Disable the system lock?":"Enable system lock? This demo action prevents resuming isolated agents."}</p><div className="flex justify-end gap-2"><button onClick={()=>setShowLockConfirm(false)} className="rounded-full px-4 py-2 text-sm" style={{background:COLORS.canvas}}>Cancel</button><button onClick={()=>{setSystemLocked(v=>!v);setShowLockConfirm(false);notify(`System lock ${systemLocked?"disabled":"enabled"}.`)}} className="rounded-full px-4 py-2 text-sm text-white" style={{background:COLORS.ink}}>{systemLocked?"Disable lock":"Enable lock"}</button></div></> :
        modal==="quarantine" ? <><p className="text-sm mb-3">Two agents are awaiting re-verification in this demo queue.</p>{["Agent-03","Research Agent"].map((a,i)=><div key={a} className="flex items-center justify-between py-3 border-t" style={{borderColor:COLORS.line}}><div><b className="text-sm">{a}</b><div className="text-xs text-gray-500">Pending verification</div></div><button disabled={reviewed.includes(a)} onClick={()=>{setReviewed(v=>[...v,a]);notify(`${a} marked reviewed.`)}} className="rounded-full px-3 py-2 text-xs font-bold text-white disabled:opacity-40" style={{background:COLORS.ink}}>{reviewed.includes(a)?"Reviewed":"Mark reviewed"}</button></div>)}</> :
        modal==="scope" ? <><p className="text-sm mb-3">Demo scope controls for <b>{selected.name}</b>.</p><div className="rounded-xl p-3 mb-3 text-sm" style={{background:COLORS.canvas}}>{selected.scope}<div className="text-xs text-gray-500 mt-1">Sandbox · least-privilege profile</div></div><button onClick={()=>{setAgents(prev=>prev.map(a=>a.id===selected.id?{...a,scope:a.scope==="Sandbox environment"?"Read-only sandbox":"Sandbox environment"}:a));setModal("");notify("Demo scope updated.")}} className="rounded-full px-4 py-2 text-sm text-white" style={{background:COLORS.ink}}>Toggle demo scope</button></> :
        modal==="incident" ? <><div className="rounded-xl p-4 mb-3" style={{background:COLORS.canvas}}><div className="text-xs text-gray-500">Agent-03 · Critical · Risk 96</div><b className="block my-1">Credential access attempt</b><p className="text-sm">Policy decision: DENY. Enforcement status: isolated.</p></div><button onClick={()=>{setSelectedAgent("agent-03");setModal("");}} className="rounded-full px-4 py-2 text-sm text-white" style={{background:COLORS.ink}}>Open Agent-03 controls</button></> :
        modal==="agents" ? <div className="space-y-2">{agents.map(a=><button key={a.id} onClick={()=>{setSelectedAgent(a.id);setModal("")}} className="w-full text-left rounded-xl p-3 flex justify-between" style={{background:COLORS.canvas}}><span><b className="text-sm">{a.name}</b><span className="block text-xs text-gray-500">{a.id}</span></span><span className="text-xs font-bold">{a.status}</span></button>)}</div> :
        modal==="activity" ? <div className="space-y-2">{events.map(e=><div key={e.id} className="rounded-xl p-3" style={{background:COLORS.canvas}}><div className="text-xs text-gray-500">{e.time} · {e.agent}</div><b className="text-sm">{e.event}</b><div className="text-xs mt-1">{e.severity} · {e.decision}</div></div>)}</div> :
        modal==="calendar" ? <p className="text-sm">Review schedule: daily security review at 09:00. Calendar integration is not connected.</p> :
        modal==="notifications" ? <p className="text-sm">You have {events.filter(e=>e.severity==="Critical").length} critical demo event(s) and {agents.filter(a=>a.status==="Isolated").length} isolated agent(s).</p> :
        modal==="scan" ? <ScanArtifactPanel
          form={scanForm} setForm={setScanForm}
          result={scanResult} setResult={setScanResult}
          loading={scanLoading} setLoading={setScanLoading}
          error={scanError} setError={setScanError}
          notify={notify}
        /> :
        <p className="text-sm">This control is a frontend demo. Connect your Kavach API to load live data and enforce real security actions.</p>}
      </div>
    </div>}
    <div className="max-w-[1440px] mx-auto mt-2 text-[10px] text-center text-gray-500">Kavach · scanner integrated · shield and agents coming soon.</div>
  </div>;
}
