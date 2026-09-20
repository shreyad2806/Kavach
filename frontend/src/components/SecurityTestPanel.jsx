import { ShieldAlert, Loader2, RotateCcw, AlertTriangle, Lock, Zap } from "lucide-react";
import { Panel } from "../ui/Panel.jsx";
import { Button } from "../ui/Button.jsx";
import { Badge } from "../ui/index.jsx";

function ReasonCodes({ codes = [] }) {
  if (!codes.length) return null;
  return (
    <div className="flex flex-wrap gap-1.5">
      {codes.map((code) => (
        <span
          key={code}
          className="text-[10.5px] font-mono rounded-md px-2 py-0.5 bg-danger/10 text-danger border border-danger/20"
        >
          {code}
        </span>
      ))}
    </div>
  );
}

export function SecurityTestPanel({
  status = null,
  attack = null,
  onAttack,
  attacking = false,
  error = "",
  onRunAgain,
  resetting = false,
}) {
  const attackAttempt = attack?.attack;
  const postAttempt = attack?.post_quarantine;
  const quarantined = attack?.quarantine;

  if (status !== "COMPLETED" && !attack) return null;

  return (
    <div className="flex flex-col gap-0 rounded-panel overflow-hidden border border-line">
      {/* Prominent header */}
      <div
        className="px-5 py-4 flex items-center justify-between gap-3 flex-wrap"
        style={{
          background: "linear-gradient(90deg, rgba(255,77,94,.08), rgba(255,77,94,.03), transparent)",
          borderBottom: "1px solid rgba(255,77,94,.2)",
        }}
      >
        <div className="flex items-center gap-3">
          <div
            className="w-9 h-9 rounded-lg flex items-center justify-center flex-shrink-0"
            style={{ background: "rgba(255,77,94,.12)", border: "1px solid rgba(255,77,94,.3)" }}
          >
            <ShieldAlert size={17} className="text-danger" />
          </div>
          <div>
            <div className="text-[13.5px] font-bold text-ink flex items-center gap-2">
              Attack Simulation
              <span className="text-[10px] font-mono rounded-full border border-danger/30 bg-danger/10 text-danger px-2 py-0.5 uppercase tracking-wide">
                Adversarial
              </span>
            </div>
            <div className="text-[11.5px] text-ink3 mt-0.5">
              Simulate a compromised agent attempting capability escalation
            </div>
          </div>
        </div>
        <div className="flex items-center gap-2">
          {!attack && (
            <Button tone="danger" size="sm" onClick={onAttack} disabled={attacking || resetting}>
              {attacking
                ? <><Loader2 size={12} className="animate-spin" />Attacking…</>
                : <><Zap size={12} />Simulate Attack</>}
            </Button>
          )}
          <Button tone="outline" size="sm" onClick={onRunAgain} disabled={resetting || attacking}>
            {resetting
              ? <><Loader2 size={12} className="animate-spin" />Resetting…</>
              : <><RotateCcw size={12} />Run Again</>}
          </Button>
        </div>
      </div>

      {/* Body */}
      <div className="p-5 bg-panel flex flex-col gap-4">
        <p className="text-[12.5px] text-ink3 leading-relaxed">
          The research agent asks for a production deployment it is not authorised to perform.
          Kavach evaluates the real request, denies it, quarantines the agent, and blocks every
          subsequent protected action from that agent.
        </p>

        {attacking && (
          <div className="flex items-center gap-2 rounded-tile border border-danger/20 bg-danger/10 px-3 py-2.5 text-[12px] text-danger">
            <Loader2 size={13} className="animate-spin flex-shrink-0" />
            ATTACK IN PROGRESS — evaluating the request through Shield…
          </div>
        )}

        {error && (
          <div className="flex items-center gap-2 rounded-tile bg-danger/10 border border-danger/20 px-3 py-2 text-[12px] text-danger">
            <AlertTriangle size={13} className="flex-shrink-0" />
            {error}
          </div>
        )}

        {attackAttempt && (
          <div className="grid gap-3 lg:grid-cols-3">
            {/* 1. Attack Request */}
            <div
              className="rounded-tile border p-4 flex flex-col gap-3"
              style={{ borderColor: "rgba(255,77,94,.2)", background: "rgba(255,77,94,.04)" }}
            >
              <div className="flex items-center justify-between gap-2">
                <div>
                  <div className="text-[10px] font-bold uppercase tracking-widest text-danger mb-0.5">
                    Attack Request
                  </div>
                  <div className="text-[12.5px] font-semibold text-ink">Unauthorised escalation</div>
                </div>
                <Badge label={attackAttempt.decision} tone={attackAttempt.decision === "DENY" ? "danger" : "neon"} />
              </div>
              <div className="text-[11px] font-mono text-ink3 leading-relaxed bg-panel2 rounded-tile px-3 py-2 border border-line">
                research-01 → deployment.deploy<br />
                resource: production-environment<br />
                capability: research.search<br />
                executed: {String(attackAttempt.executed)}
              </div>
              <ReasonCodes codes={attackAttempt.reason_codes} />
              {attackAttempt.risk_score != null && (
                <div className="text-[11px] font-mono text-ink3">
                  risk score: <span className="text-danger font-bold">{attackAttempt.risk_score}</span>
                </div>
              )}
              <div className="text-[10.5px] font-mono text-ink3 truncate">
                {attackAttempt.request_id}
              </div>
            </div>

            {/* 2. Decision Result */}
            <div
              className="rounded-tile border p-4 flex flex-col gap-3"
              style={{ borderColor: "rgba(255,77,94,.2)", background: "rgba(255,77,94,.04)" }}
            >
              <div className="flex items-center justify-between gap-2">
                <div>
                  <div className="text-[10px] font-bold uppercase tracking-widest text-danger mb-0.5">
                    Decision Result
                  </div>
                  <div className="text-[12.5px] font-semibold text-ink">Enforcement</div>
                </div>
                <Badge label={quarantined?.state ?? "—"} tone="danger" />
              </div>
              <div className="flex items-center gap-2 text-[12.5px] font-mono text-ink2 bg-panel2 rounded-tile px-3 py-2 border border-line">
                <Lock size={12} className="text-danger flex-shrink-0" />
                {quarantined?.agent_id}
              </div>
              <p className="text-[11.5px] text-ink3 leading-relaxed">
                Quarantine is a security state transition, not a request. The agent cannot
                release itself, and every other agent stays ACTIVE.
              </p>
            </div>

            {/* 3. Post-Quarantine */}
            <div
              className="rounded-tile border p-4 flex flex-col gap-3"
              style={{ borderColor: "rgba(255,77,94,.2)", background: "rgba(255,77,94,.04)" }}
            >
              <div className="flex items-center justify-between gap-2">
                <div>
                  <div className="text-[10px] font-bold uppercase tracking-widest text-danger mb-0.5">
                    Post-Quarantine
                  </div>
                  <div className="text-[12.5px] font-semibold text-ink">Blocked follow-up</div>
                </div>
                <Badge label={postAttempt?.decision ?? "—"} tone="danger" />
              </div>
              <div className="text-[11px] font-mono text-ink3 leading-relaxed bg-panel2 rounded-tile px-3 py-2 border border-line">
                research-01 → research.search<br />
                resource: research-data<br />
                executed: {String(postAttempt?.executed)}
              </div>
              <ReasonCodes codes={postAttempt?.reason_codes} />
              <div className="text-[10.5px] font-mono text-ink3 truncate">
                {postAttempt?.request_id}
              </div>
            </div>
          </div>
        )}

        {attackAttempt && (
          <p className="text-[11.5px] text-ink3 border-t border-line pt-3">
            Both decisions are preserved as separate events in Agent activity. Select either
            row to inspect that exact request&apos;s authorization pipeline.
          </p>
        )}
      </div>
    </div>
  );
}
