import { useState, useCallback, useEffect, useRef } from "react";
import { X, Loader2, CheckCircle, XCircle, AlertCircle } from "lucide-react";
import { Panel } from "../ui/Panel.jsx";
import { Button } from "../ui/Button.jsx";
import { Badge } from "../ui/index.jsx";
import { verdictTone } from "../lib/format.js";

const API_KEY = import.meta.env.VITE_API_KEY ?? "";

async function apiFetch(path, opts = {}) {
  const res = await fetch(`/api${path}`, {
    ...opts,
    headers: { "Content-Type": "application/json", "x-api-key": API_KEY, ...opts.headers },
  });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json();
}

const VERDICT_ICON = {
  APPROVED:        <CheckCircle size={16} className="text-neon" />,
  BLOCKED:         <XCircle size={16} className="text-danger" />,
  REVIEW_REQUIRED: <AlertCircle size={16} className="text-amber" />,
};

export function ScanModal({ onClose }) {
  const [form, setForm] = useState({
    artifact_type: "python_package",
    source_url: "",
    requested_by: "operator",
  });
  const [phase, setPhase] = useState("idle"); // idle | submitting | polling | done | error
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");
  const [artifactId, setArtifactId] = useState("");
  const pollRef = useRef(null);

  // Close on Escape
  useEffect(() => {
    const handler = (e) => { if (e.key === "Escape") onClose(); };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [onClose]);

  // Cleanup poll on unmount
  useEffect(() => () => clearTimeout(pollRef.current), []);

  const poll = useCallback(async (id) => {
    let attempts = 0;
    const tick = async () => {
      if (attempts >= 30) {
        setError("Scan timed out after 90 seconds.");
        setPhase("error");
        return;
      }
      attempts++;
      try {
        const data = await apiFetch(`/artifacts/${id}`);
        if (["APPROVED", "BLOCKED", "REVIEW_REQUIRED", "FAILED"].includes(data.status)) {
          setResult(data);
          setPhase("done");
          return;
        }
      } catch {
        // keep polling on transient errors
      }
      pollRef.current = setTimeout(tick, 3000);
    };
    pollRef.current = setTimeout(tick, 3000);
  }, []);

  const handleSubmit = async () => {
    if (!form.source_url.trim()) {
      setError("Source URL is required.");
      return;
    }
    setError("");
    setPhase("submitting");
    try {
      const { artifact_id } = await apiFetch("/artifacts/scan", {
        method: "POST",
        body: JSON.stringify(form),
      });
      setArtifactId(artifact_id);
      setPhase("polling");
      poll(artifact_id);
    } catch (e) {
      setError(e.message || "Scan submission failed.");
      setPhase("error");
    }
  };

  const verdict = result?.verdict?.decision || result?.status;
  const riskScore = result?.verdict?.risk_score;

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-4"
      style={{ background: "rgba(3,20,14,.85)", backdropFilter: "blur(6px)" }}
      onClick={onClose}
    >
      <Panel
        className="w-full max-w-lg flex flex-col gap-4 p-5"
        style={{ borderColor: "#17493a" }}
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <div className="text-[14px] font-bold text-ink">Scan artifact</div>
            <div className="text-[12px] text-ink3 mt-0.5">
              Submit a URL to the pre-execution scanner pipeline.
            </div>
          </div>
          <button
            onClick={onClose}
            aria-label="Close scan modal"
            className="w-8 h-8 rounded-btn flex items-center justify-center text-ink3 hover:text-ink hover:bg-line transition-colors"
          >
            <X size={15} />
          </button>
        </div>

        {/* Form */}
        {(phase === "idle" || phase === "error") && (
          <div className="flex flex-col gap-3">
            <div>
              <label className="block text-[11.5px] text-ink3 mb-1.5">Artifact type</label>
              <select
                value={form.artifact_type}
                onChange={(e) => setForm((f) => ({ ...f, artifact_type: e.target.value }))}
                className="w-full bg-panel2 border border-line rounded-tile px-3 py-2 text-[13px] text-ink outline-none hover:border-line2 transition-colors"
              >
                <option value="python_package">Python package</option>
                <option value="github_repo">GitHub repository</option>
                <option value="generic_file">Generic file</option>
              </select>
            </div>

            <div>
              <label className="block text-[11.5px] text-ink3 mb-1.5">Source URL</label>
              <input
                type="url"
                value={form.source_url}
                onChange={(e) => setForm((f) => ({ ...f, source_url: e.target.value }))}
                onKeyDown={(e) => e.key === "Enter" && handleSubmit()}
                placeholder="https://files.pythonhosted.org/packages/…"
                className="w-full bg-panel2 border border-line rounded-tile px-3 py-2 text-[13px] text-ink placeholder:text-ink3 outline-none hover:border-line2 focus:border-neon/50 transition-colors font-mono"
              />
            </div>

            <div>
              <label className="block text-[11.5px] text-ink3 mb-1.5">Requested by</label>
              <input
                type="text"
                value={form.requested_by}
                onChange={(e) => setForm((f) => ({ ...f, requested_by: e.target.value }))}
                placeholder="agent-id or operator"
                className="w-full bg-panel2 border border-line rounded-tile px-3 py-2 text-[13px] text-ink placeholder:text-ink3 outline-none hover:border-line2 transition-colors font-mono"
              />
            </div>

            {error && (
              <div className="flex items-center gap-2 rounded-tile bg-danger/10 border border-danger/20 px-3 py-2 text-[12px] text-danger">
                <XCircle size={13} />
                {error}
              </div>
            )}

            <Button tone="neon" size="md" onClick={handleSubmit} className="w-full mt-1">
              Submit scan
            </Button>
          </div>
        )}

        {/* Polling state */}
        {phase === "submitting" && (
          <div className="flex flex-col items-center gap-3 py-6">
            <Loader2 size={28} className="text-neon animate-spin" />
            <div className="text-[13px] text-ink2">Submitting to scanner pipeline…</div>
          </div>
        )}

        {phase === "polling" && (
          <div className="flex flex-col items-center gap-3 py-6">
            <Loader2 size={28} className="text-neon animate-spin" />
            <div className="text-[13px] text-ink2">Scanning in progress…</div>
            <div className="text-[11.5px] font-mono text-ink3">{artifactId}</div>
            <div className="text-[11.5px] text-ink3">
              Running Bandit · Semgrep · pip-audit · Gitleaks · Sandbox
            </div>
          </div>
        )}

        {/* Result */}
        {phase === "done" && result && (
          <div className="flex flex-col gap-3">
            {/* Verdict header */}
            <div className="flex items-center justify-between rounded-tile bg-panel2 border border-line px-4 py-3">
              <div>
                <div className="text-[11.5px] text-ink3 mb-1 font-mono">{result.artifact_id}</div>
                <div className="flex items-center gap-2">
                  {VERDICT_ICON[verdict]}
                  <span className="text-[15px] font-bold text-ink">{verdict}</span>
                </div>
              </div>
              {riskScore != null && (
                <div className="text-right">
                  <div className="text-[11px] text-ink3">Risk score</div>
                  <div className="text-[26px] font-mono font-semibold text-ink leading-none">
                    {riskScore}
                    <span className="text-[12px] text-ink3">/100</span>
                  </div>
                </div>
              )}
            </div>

            {/* Blocked reasons */}
            {result.verdict?.blocked_reasons?.length > 0 && (
              <div className="rounded-tile bg-danger/10 border border-danger/20 px-3 py-2.5">
                <div className="text-[11.5px] font-semibold text-danger mb-1.5">Blocked because</div>
                <ul className="flex flex-col gap-1">
                  {result.verdict.blocked_reasons.map((r, i) => (
                    <li key={i} className="text-[12px] text-ink3 flex items-start gap-1.5">
                      <span className="text-danger mt-0.5">·</span> {r}
                    </li>
                  ))}
                </ul>
              </div>
            )}

            {/* Scanner verdicts */}
            {result.verdict?.scanner_verdicts && (
              <div className="flex flex-wrap gap-2">
                {Object.entries(result.verdict.scanner_verdicts).map(([scanner, v]) => (
                  <div key={scanner} className="flex items-center gap-1.5 bg-panel2 border border-line rounded-tile px-2.5 py-1.5">
                    <span className="text-[11px] text-ink3">{scanner}</span>
                    <Badge label={v} tone={v === "CRITICAL" || v === "HIGH" ? "danger" : v === "MEDIUM" ? "amber" : "neon"} />
                  </div>
                ))}
              </div>
            )}

            {/* Agent report */}
            {result.agent_report && (
              <div className="rounded-tile bg-panel2 border border-line px-3 py-2.5">
                <div className="text-[11.5px] font-semibold text-ink2 mb-1.5">AI analysis</div>
                <p className="text-[12px] text-ink3 leading-relaxed">{result.agent_report}</p>
              </div>
            )}

            <div className="flex gap-2 mt-1">
              <Button tone="outline" size="sm" onClick={() => { setPhase("idle"); setResult(null); setForm({ artifact_type: "python_package", source_url: "", requested_by: "operator" }); }} className="flex-1">
                Scan another
              </Button>
              <Button tone="ghost" size="sm" onClick={onClose} className="flex-1">
                Close
              </Button>
            </div>
          </div>
        )}
      </Panel>
    </div>
  );
}
