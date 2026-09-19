import { useState, useMemo } from "react";
import {
  Search, Shield, CheckCircle, XCircle, AlertCircle,
  ChevronDown, ChevronUp, RotateCcw, Package, Github,
  FileCode, Loader2, Lock, Unlock
} from "lucide-react";
import { Panel } from "../ui/Panel.jsx";
import { Button } from "../ui/Button.jsx";
import { Badge } from "../ui/index.jsx";
import { useScanner } from "../hooks/useScanner.js";

// ─── constants ────────────────────────────────────────────────────────────────

const ARTIFACT_TYPES = [
  { value: "python_package", label: "Python package",    Icon: Package  },
  { value: "github_repo",    label: "GitHub repository", Icon: Github   },
  { value: "generic_file",   label: "Generic file",      Icon: FileCode },
];

const PIPELINE_STAGES = [
  { key: "download",  label: "Download & hash",  desc: "Fetch artifact, SHA-256, upload to quarantine S3" },
  { key: "bandit",    label: "Bandit",            desc: "Python security issues: eval/exec, weak crypto, subprocess misuse" },
  { key: "semgrep",   label: "Semgrep",           desc: "Language-aware pattern matching — Python, JS, Go, Java, Shell" },
  { key: "pip_audit", label: "pip-audit",         desc: "CVE scanning via PyPI Advisory Database" },
  { key: "gitleaks",  label: "Gitleaks",          desc: "Secret & credential detection across full git history" },
  { key: "sandbox",   label: "Sandbox",           desc: "Fargate isolated execution — strace behavioural analysis" },
  { key: "verdict",   label: "Verdict engine",    desc: "Deterministic risk score 0–100, hard-block rules, final decision" },
];

const SEV_ORDER = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };

// ─── helpers ──────────────────────────────────────────────────────────────────

function sevTone(s) {
  if (s === "CRITICAL" || s === "HIGH") return "danger";
  if (s === "MEDIUM") return "amber";
  return "dim";
}

function verdictTone(v) {
  if (v === "BLOCKED")          return "danger";
  if (v === "REVIEW_REQUIRED")  return "amber";
  if (v === "APPROVED")         return "neon";
  return "neutral";
}

function riskColor(n) {
  if (n >= 80) return "#ff4d5e";
  if (n >= 51) return "#ffc046";
  if (n >= 21) return "#a7c9ba";
  return "#1fe98a";
}

// ─── small components ─────────────────────────────────────────────────────────

function RiskGauge({ score }) {
  const r = 38, c = 2 * Math.PI * r;
  const pct = Math.min(100, Math.max(0, score ?? 0));
  return (
    <div className="relative w-[96px] h-[96px] flex-shrink-0">
      <svg width="96" height="96" viewBox="0 0 96 96" style={{ transform: "rotate(-90deg)" }}>
        <circle cx="48" cy="48" r={r} fill="none" stroke="#12362a" strokeWidth="9" />
        <circle cx="48" cy="48" r={r} fill="none" stroke={riskColor(pct)} strokeWidth="9"
          strokeDasharray={c} strokeDashoffset={c - (pct / 100) * c}
          strokeLinecap="round" style={{ transition: "stroke-dashoffset .6s ease" }} />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="text-[22px] font-mono font-bold text-ink leading-none">{pct}</span>
        <span className="text-[10px] text-ink3">/100</span>
      </div>
    </div>
  );
}

function PipelineStages({ phase }) {
  return (
    <div className="flex flex-col gap-2">
      {PIPELINE_STAGES.map((s, i) => {
        const active = phase === "polling";
        const done   = phase === "done" || phase === "error";
        return (
          <div key={s.key} className="flex items-start gap-3">
            <div className="flex flex-col items-center gap-1 pt-1 flex-shrink-0">
              <span className={`w-2 h-2 rounded-full ${
                done   ? "bg-neon" :
                active ? "bg-amber pulse" :
                         "bg-line2"
              }`} />
              {i < PIPELINE_STAGES.length - 1 && <div className="w-px h-4 bg-line2" />}
            </div>
            <div className="pb-1 min-w-0">
              <div className={`text-[12.5px] font-semibold ${active || done ? "text-ink2" : "text-ink3"}`}>
                {s.label}
              </div>
              <div className="text-[11px] text-ink3 leading-relaxed">{s.desc}</div>
            </div>
          </div>
        );
      })}
    </div>
  );
}

function FindingRow({ f }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="rounded-tile border border-line overflow-hidden">
      <button
        onClick={() => setOpen(v => !v)}
        className="w-full flex items-center gap-3 px-3 py-2.5 text-left hover:bg-line/40 transition-colors"
      >
        <Badge label={f.severity} tone={sevTone(f.severity)} />
        <span className="flex-1 text-[12.5px] text-ink2 font-mono truncate">
          {f.title || f.check_id || "Finding"}
        </span>
        <span className="text-[11px] text-ink3 flex-shrink-0 capitalize">{f.scanner}</span>
        {open
          ? <ChevronUp size={13} className="text-ink3 flex-shrink-0" />
          : <ChevronDown size={13} className="text-ink3 flex-shrink-0" />}
      </button>
      {open && (
        <div className="px-3 pb-3 pt-1 border-t border-line bg-panel2 flex flex-col gap-1.5">
          {f.description && (
            <p className="text-[12px] text-ink3 leading-relaxed">{f.description}</p>
          )}
          {f.file_path && (
            <div className="text-[11.5px] font-mono text-ink3">
              <span className="text-ink2">File: </span>{f.file_path}
              {f.line_number ? `:${f.line_number}` : ""}
            </div>
          )}
          {f.cve_id && (
            <div className="text-[11.5px] font-mono">
              <span className="text-ink3">CVE: </span>
              <span className="text-amber">{f.cve_id}</span>
            </div>
          )}
          {f.package_name && (
            <div className="text-[11.5px] font-mono text-ink3">
              <span className="text-ink2">Package: </span>
              {f.package_name}{f.installed_version ? ` @ ${f.installed_version}` : ""}
            </div>
          )}
          {f.fix_versions?.length > 0 && (
            <div className="text-[11.5px] font-mono text-neon">
              Fix: {f.fix_versions.join(", ")}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function FindingsTable({ findings }) {
  const sorted = useMemo(() =>
    [...(findings ?? [])].sort((a, b) =>
      (SEV_ORDER[a.severity] ?? 9) - (SEV_ORDER[b.severity] ?? 9)
    ), [findings]);

  if (!sorted.length) {
    return (
      <div className="flex flex-col items-center justify-center py-8 gap-2">
        <CheckCircle size={22} className="text-neon" />
        <p className="text-[13px] text-ink3">No findings detected.</p>
      </div>
    );
  }
  return (
    <div className="flex flex-col gap-1.5">
      {sorted.map((f, i) => <FindingRow key={i} f={f} />)}
    </div>
  );
}

function VerdictCard({ result }) {
  const decision = result?.verdict?.decision || result?.status;
  const score    = result?.verdict?.risk_score;
  const level    = result?.verdict?.risk_level;
  const tone     = verdictTone(decision);
  const accent   = tone === "danger" ? "#ff4d5e" : tone === "amber" ? "#ffc046" : "#1fe98a";
  const Icon     = decision === "APPROVED" ? Unlock : decision === "BLOCKED" ? Lock : AlertCircle;

  return (
    <div className="rounded-tile border p-4 flex flex-col gap-4"
      style={{ borderColor: `${accent}30` }}>

      {/* Header row */}
      <div className="flex items-center justify-between gap-4 flex-wrap">
        <div className="flex items-center gap-3">
          <div className="w-11 h-11 rounded-full flex items-center justify-center flex-shrink-0"
            style={{ background: `${accent}18`, border: `1.5px solid ${accent}40` }}>
            <Icon size={18} style={{ color: accent }} />
          </div>
          <div>
            <div className="text-[11px] text-ink3 uppercase tracking-widest font-semibold mb-0.5">
              Final verdict
            </div>
            <div className="text-[20px] font-bold text-ink leading-tight">{decision}</div>
            {level && (
              <div className="text-[11.5px] font-mono" style={{ color: accent }}>
                {level} risk
              </div>
            )}
          </div>
        </div>
        {score != null && <RiskGauge score={score} />}
      </div>

      {/* Access decision banner */}
      <div className={`rounded-tile px-3 py-2.5 text-[12.5px] font-semibold flex items-center gap-2 ${
        decision === "APPROVED"
          ? "bg-neon/10 border border-neon/20 text-neon"
          : decision === "BLOCKED"
          ? "bg-danger/10 border border-danger/20 text-danger"
          : "bg-amber/10 border border-amber/20 text-amber"
      }`}>
        {decision === "APPROVED" && <><CheckCircle size={14} />Agents may access this artifact</>}
        {decision === "BLOCKED"  && <><XCircle size={14} />Agents are BLOCKED from this artifact</>}
        {decision === "REVIEW_REQUIRED" && <><AlertCircle size={14} />Operator review required before agent access</>}
      </div>

      {/* Blocked reasons */}
      {result?.verdict?.blocked_reasons?.length > 0 && (
        <div className="flex flex-col gap-1.5">
          <div className="text-[11.5px] font-semibold text-danger uppercase tracking-wide">
            Blocked because
          </div>
          <ul className="flex flex-col gap-1">
            {result.verdict.blocked_reasons.map((r, i) => (
              <li key={i} className="flex items-start gap-2 text-[12px] text-ink3">
                <span className="text-danger mt-0.5 flex-shrink-0">▸</span>{r}
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Per-scanner verdicts */}
      {result?.verdict?.scanner_verdicts && Object.keys(result.verdict.scanner_verdicts).length > 0 && (
        <div className="flex flex-wrap gap-2">
          {Object.entries(result.verdict.scanner_verdicts).map(([sc, v]) => (
            <div key={sc}
              className="flex items-center gap-2 bg-panel2 border border-line rounded-tile px-3 py-1.5">
              <span className="text-[11.5px] text-ink3 capitalize">{sc.replace(/_/g, "-")}</span>
              <Badge label={v} tone={sevTone(v)} />
            </div>
          ))}
        </div>
      )}

      {/* AI analysis */}
      {result?.agent_report && (
        <div className="rounded-tile bg-panel2 border border-line px-3 py-2.5">
          <div className="text-[11.5px] font-semibold text-ink2 mb-1.5 flex items-center gap-1.5">
            <Shield size={12} className="text-neon" />AI analysis
          </div>
          <p className="text-[12px] text-ink3 leading-relaxed">{result.agent_report}</p>
        </div>
      )}

      {/* Meta row */}
      <div className="flex flex-wrap gap-x-4 gap-y-1 text-[11.5px] font-mono text-ink3 border-t border-line pt-3">
        <span><span className="text-ink2">ID: </span>{result.artifact_id}</span>
        {result.sha256 && (
          <span><span className="text-ink2">SHA-256: </span>{result.sha256.slice(0, 16)}…</span>
        )}
        {result.scan_count > 1 && (
          <span><span className="text-ink2">Scan #: </span>{result.scan_count}</span>
        )}
        {result.total_findings != null && (
          <span><span className="text-ink2">Findings: </span>{result.total_findings}</span>
        )}
      </div>
    </div>
  );
}

// ─── main page ────────────────────────────────────────────────────────────────

export function ScannerPage() {
  const { phase, artifactId, result, error, submit, reset } = useScanner();

  const [form, setForm] = useState({
    artifact_type: "python_package",
    source_url: "",
    requested_by: "operator",
  });

  const [history, setHistory] = useState([]);

  // Push completed scans to history (deduplicated)
  if (
    phase === "done" &&
    result &&
    !history.find(h => h.artifact_id === result.artifact_id)
  ) {
    setHistory(h => [result, ...h].slice(0, 8));
  }

  const busy = phase === "submitting" || phase === "polling";
  const findingCounts = result?.finding_counts ?? {};
  const totalFindings = result?.total_findings ?? 0;

  return (
    <div className="flex flex-col gap-4">

      {/* Page header */}
      <div className="flex items-center justify-between gap-3 flex-wrap">
        <div>
          <h1 className="text-[18px] font-bold text-ink flex items-center gap-2">
            <Shield size={18} className="text-neon" />
            Artifact Scanner
          </h1>
          <p className="text-[12.5px] text-ink3 mt-0.5">
            Pre-execution security scanning — every artifact is verified before agents can access it.
          </p>
        </div>
        {(phase === "done" || phase === "error") && (
          <Button tone="outline" size="sm" onClick={reset}>
            <RotateCcw size={13} />New scan
          </Button>
        )}
      </div>

      {/* Two-column layout */}
      <div className="grid gap-4 lg:grid-cols-[320px_1fr]">

        {/* ── Left: form + pipeline + history ── */}
        <div className="flex flex-col gap-4">

          {/* Submit form */}
          <Panel className="p-4 flex flex-col gap-3">
            <div className="text-[13px] font-bold text-ink">Submit artifact</div>

            {/* Type selector */}
            <div>
              <label className="block text-[11.5px] text-ink3 mb-1.5">Artifact type</label>
              <div className="flex flex-col gap-1.5">
                {ARTIFACT_TYPES.map(({ value, label, Icon }) => (
                  <button
                    key={value}
                    onClick={() => setForm(f => ({ ...f, artifact_type: value }))}
                    disabled={busy}
                    className={`flex items-center gap-2.5 rounded-tile px-3 py-2 text-left border transition-colors disabled:opacity-50 ${
                      form.artifact_type === value
                        ? "border-neon/40 bg-neon/5 text-ink"
                        : "border-line text-ink3 hover:border-line2 hover:text-ink2"
                    }`}
                  >
                    <Icon size={14} className={form.artifact_type === value ? "text-neon" : "text-ink3"} />
                    <span className="text-[12.5px] font-semibold">{label}</span>
                  </button>
                ))}
              </div>
            </div>

            {/* URL */}
            <div>
              <label className="block text-[11.5px] text-ink3 mb-1.5">Source URL</label>
              <input
                type="url"
                value={form.source_url}
                onChange={e => setForm(f => ({ ...f, source_url: e.target.value }))}
                onKeyDown={e => e.key === "Enter" && !busy && submit(form)}
                placeholder="https://files.pythonhosted.org/packages/…"
                disabled={busy}
                className="w-full bg-panel2 border border-line rounded-tile px-3 py-2 text-[12.5px] text-ink placeholder:text-ink3 outline-none hover:border-line2 focus:border-neon/50 transition-colors font-mono disabled:opacity-50"
              />
            </div>

            {/* Requested by */}
            <div>
              <label className="block text-[11.5px] text-ink3 mb-1.5">Requested by</label>
              <input
                type="text"
                value={form.requested_by}
                onChange={e => setForm(f => ({ ...f, requested_by: e.target.value }))}
                placeholder="agent-id or operator"
                disabled={busy}
                className="w-full bg-panel2 border border-line rounded-tile px-3 py-2 text-[12.5px] text-ink placeholder:text-ink3 outline-none hover:border-line2 transition-colors font-mono disabled:opacity-50"
              />
            </div>

            {error && (
              <div className="flex items-center gap-2 rounded-tile bg-danger/10 border border-danger/20 px-3 py-2 text-[12px] text-danger">
                <XCircle size={13} className="flex-shrink-0" />{error}
              </div>
            )}

            <Button tone="neon" size="md" onClick={() => submit(form)} disabled={busy} className="w-full">
              {busy
                ? <><Loader2 size={14} className="animate-spin" />Scanning…</>
                : <><Search size={14} />Run scan</>}
            </Button>
          </Panel>

          {/* Pipeline stages */}
          <Panel className="p-4 flex flex-col gap-3">
            <div className="text-[13px] font-bold text-ink">Pipeline stages</div>
            <PipelineStages phase={phase} />
          </Panel>

          {/* Scan history */}
          {history.length > 0 && (
            <Panel className="p-4 flex flex-col gap-2">
              <div className="text-[13px] font-bold text-ink">Recent scans</div>
              {history.map(h => {
                const d = h?.verdict?.decision || h?.status;
                return (
                  <div key={h.artifact_id}
                    className="flex items-center gap-2 rounded-tile bg-panel2 border border-line px-3 py-2">
                    <Badge label={d} tone={verdictTone(d)} />
                    <span className="flex-1 text-[11px] font-mono text-ink3 truncate">
                      {h.artifact_id}
                    </span>
                    {h.verdict?.risk_score != null && (
                      <span className="text-[11px] font-mono flex-shrink-0"
                        style={{ color: riskColor(h.verdict.risk_score) }}>
                        {h.verdict.risk_score}
                      </span>
                    )}
                  </div>
                );
              })}
            </Panel>
          )}
        </div>

        {/* ── Right: results ── */}
        <div className="flex flex-col gap-4">

          {/* Idle */}
          {phase === "idle" && (
            <Panel className="p-10 flex flex-col items-center justify-center gap-4 text-center min-h-[340px]">
              <div className="w-14 h-14 rounded-full bg-neon/10 border border-neon/20 flex items-center justify-center">
                <Shield size={26} className="text-neon" />
              </div>
              <div>
                <div className="text-[15px] font-bold text-ink mb-1">Ready to scan</div>
                <p className="text-[12.5px] text-ink3 max-w-xs leading-relaxed">
                  Submit an artifact URL. Kavach runs Bandit, Semgrep, pip-audit,
                  Gitleaks, and a Fargate sandbox before issuing a deterministic verdict.
                </p>
              </div>
              <div className="flex flex-wrap justify-center gap-2 mt-1">
                {["Bandit", "Semgrep", "pip-audit", "Gitleaks", "Sandbox"].map(s => (
                  <span key={s}
                    className="text-[11px] font-mono rounded-full border border-line px-2.5 py-1 text-ink3">
                    {s}
                  </span>
                ))}
              </div>
            </Panel>
          )}

          {/* Submitting */}
          {phase === "submitting" && (
            <Panel className="p-10 flex flex-col items-center justify-center gap-3 min-h-[200px]">
              <Loader2 size={28} className="text-neon animate-spin" />
              <div className="text-[13px] text-ink2">Submitting to scanner pipeline…</div>
            </Panel>
          )}

          {/* Polling */}
          {phase === "polling" && (
            <Panel className="p-5 flex flex-col gap-4">
              <div className="flex items-center gap-3">
                <Loader2 size={20} className="text-neon animate-spin flex-shrink-0" />
                <div>
                  <div className="text-[13px] font-semibold text-ink">Scan in progress</div>
                  <div className="text-[11.5px] font-mono text-ink3 mt-0.5">{artifactId}</div>
                </div>
              </div>
              <div className="flex flex-col gap-1.5">
                {PIPELINE_STAGES.map(s => (
                  <div key={s.key}
                    className="flex items-center gap-3 rounded-tile bg-panel2 border border-line px-3 py-2">
                    <span className="w-2 h-2 rounded-full bg-amber pulse flex-shrink-0" />
                    <span className="text-[12px] font-semibold text-ink2">{s.label}</span>
                    <span className="text-[11px] text-ink3 ml-auto font-mono">running</span>
                  </div>
                ))}
              </div>
              <p className="text-[11.5px] text-ink3 text-center">
                Polling every 3 s · up to 2 minutes
              </p>
            </Panel>
          )}

          {/* Done */}
          {phase === "done" && result && (
            <div className="flex flex-col gap-4">

              {/* Verdict */}
              <Panel className="p-4">
                <VerdictCard result={result} />
              </Panel>

              {/* Findings summary */}
              {totalFindings > 0 && (
                <Panel className="p-4 flex flex-col gap-3">
                  <div className="text-[13px] font-bold text-ink">
                    Findings
                    <span className="ml-2 text-[12px] font-mono text-ink3">
                      ({totalFindings} total)
                    </span>
                  </div>

                  {/* Severity count pills */}
                  <div className="flex flex-wrap gap-2">
                    {Object.entries(findingCounts)
                      .sort(([a], [b]) => (SEV_ORDER[a] ?? 9) - (SEV_ORDER[b] ?? 9))
                      .map(([sev, count]) => (
                        <div key={sev}
                          className="flex items-center gap-2 rounded-tile bg-panel2 border border-line px-3 py-2">
                          <Badge label={sev} tone={sevTone(sev)} />
                          <span className="text-[16px] font-mono font-bold text-ink">{count}</span>
                        </div>
                      ))}
                  </div>

                  {/* Severity bar chart */}
                  <div className="flex flex-col gap-1.5">
                    {Object.entries(findingCounts)
                      .sort(([a], [b]) => (SEV_ORDER[a] ?? 9) - (SEV_ORDER[b] ?? 9))
                      .map(([sev, count]) => {
                        const pct = totalFindings > 0 ? (count / totalFindings) * 100 : 0;
                        const col = sev === "CRITICAL" || sev === "HIGH" ? "#ff4d5e"
                          : sev === "MEDIUM" ? "#ffc046" : "#4a6b5d";
                        return (
                          <div key={sev} className="flex items-center gap-3">
                            <span className="text-[11px] font-mono text-ink3 w-16 flex-shrink-0">
                              {sev}
                            </span>
                            <div className="flex-1 h-2 rounded-full bg-line overflow-hidden">
                              <div className="h-2 rounded-full transition-all duration-500"
                                style={{ width: `${pct}%`, background: col }} />
                            </div>
                            <span className="text-[11px] font-mono text-ink3 w-5 text-right">
                              {count}
                            </span>
                          </div>
                        );
                      })}
                  </div>

                  {/* Individual findings (if backend returns them) */}
                  {result.findings?.length > 0 && (
                    <div className="flex flex-col gap-1 mt-1">
                      <div className="text-[12px] font-semibold text-ink2 mb-1">
                        Finding details
                      </div>
                      <FindingsTable findings={result.findings} />
                    </div>
                  )}
                </Panel>
              )}

              {totalFindings === 0 && (
                <Panel className="p-4 flex items-center gap-3">
                  <CheckCircle size={18} className="text-neon flex-shrink-0" />
                  <span className="text-[13px] text-ink2">
                    No findings detected across all scanners.
                  </span>
                </Panel>
              )}
            </div>
          )}

          {/* Error */}
          {phase === "error" && (
            <Panel className="p-8 flex flex-col items-center gap-3 text-center">
              <XCircle size={28} className="text-danger" />
              <div className="text-[13px] font-semibold text-ink">Scan failed</div>
              <p className="text-[12px] text-ink3 max-w-sm">{error}</p>
              <Button tone="outline" size="sm" onClick={reset}>Try again</Button>
            </Panel>
          )}
        </div>
      </div>
    </div>
  );
}
