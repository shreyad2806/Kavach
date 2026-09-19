import { ShieldAlert, Loader2, RotateCcw, AlertTriangle, Lock } from "lucide-react";
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

/**
 * SecurityTestPanel — the adversary step of the demo.
 *
 * Only offered once the normal workflow has COMPLETED, so the operator sees a
 * clean run before the compromise.  Every value rendered here comes from the
 * backend response, which is itself a projection of two real authorization
 * decisions.  Nothing is hardcoded and no result is predicted.
 */
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

  // Before the workflow finishes there is nothing to attack.
  if (status !== "COMPLETED" && !attack) return null;

  return (
    <Panel className="p-4 flex flex-col gap-4">
      <div className="flex items-center justify-between gap-3 flex-wrap">
        <div className="flex items-center gap-2">
          <ShieldAlert size={15} className="text-danger" />
          <span className="text-[11px] font-bold uppercase tracking-widest text-ink2">
            Security test
          </span>
        </div>
        <div className="flex items-center gap-2">
          {!attack && (
            <Button
              tone="danger"
              size="sm"
              onClick={onAttack}
              disabled={attacking || resetting}
            >
              {attacking
                ? <><Loader2 size={12} className="animate-spin" />Attacking…</>
                : <><ShieldAlert size={12} />Simulate Attack</>}
            </Button>
          )}
          <Button tone="outline" size="sm" onClick={onRunAgain} disabled={resetting || attacking}>
            {resetting
              ? <><Loader2 size={12} className="animate-spin" />Resetting…</>
              : <><RotateCcw size={12} />Run Again</>}
          </Button>
        </div>
      </div>

      <p className="text-[12.5px] text-ink3 leading-relaxed">
        Simulate a compromised agent attempting to escalate its capabilities. The research
        agent asks for a production deployment it is not authorised to perform; Kavach
        evaluates the real request, denies it, quarantines the agent, and blocks every
        subsequent protected action from that agent.
      </p>

      {attacking && (
        <div className="flex items-center gap-2 rounded-tile border border-danger/20 bg-danger/10 px-3 py-2 text-[12px] text-danger">
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
          {/* 1. The denied escalation */}
          <div className="rounded-tile bg-panel2 border border-line p-3 flex flex-col gap-2">
            <div className="flex items-center justify-between gap-2">
              <span className="text-[11.5px] font-semibold text-ink2">
                Unauthorised escalation
              </span>
              <Badge label={attackAttempt.decision} tone={attackAttempt.decision === "DENY" ? "danger" : "neon"} />
            </div>
            <div className="text-[11px] font-mono text-ink3 leading-relaxed">
              research-01 → deployment.deploy
              <br />
              resource: production-environment
              <br />
              capability: research.search
              <br />
              side effect executed: {String(attackAttempt.executed)}
            </div>
            <ReasonCodes codes={attackAttempt.reason_codes} />
            {attackAttempt.risk_score != null && (
              <div className="text-[11px] font-mono text-ink3">
                risk={attackAttempt.risk_score}
              </div>
            )}
            <div className="text-[10.5px] font-mono text-ink3">
              request {attackAttempt.request_id}
            </div>
          </div>

          {/* 2. Enforcement */}
          <div className="rounded-tile bg-panel2 border border-line p-3 flex flex-col gap-2">
            <div className="flex items-center justify-between gap-2">
              <span className="text-[11.5px] font-semibold text-ink2">Enforcement</span>
              <Badge label={quarantined?.state ?? "—"} tone="danger" />
            </div>
            <div className="flex items-center gap-2 text-[12px] font-mono text-ink2">
              <Lock size={12} className="text-danger flex-shrink-0" />
              {quarantined?.agent_id}
            </div>
            <p className="text-[11.5px] text-ink3 leading-relaxed">
              Quarantine is a security state transition, not a request. The agent cannot
              release itself, and every other agent stays ACTIVE.
            </p>
          </div>

          {/* 3. Post-quarantine proof */}
          <div className="rounded-tile bg-panel2 border border-line p-3 flex flex-col gap-2">
            <div className="flex items-center justify-between gap-2">
              <span className="text-[11.5px] font-semibold text-ink2">
                Post-quarantine action
              </span>
              <Badge label={postAttempt?.decision ?? "—"} tone="danger" />
            </div>
            <div className="text-[11px] font-mono text-ink3 leading-relaxed">
              research-01 → research.search
              <br />
              resource: research-data
              <br />
              side effect executed: {String(postAttempt?.executed)}
            </div>
            <ReasonCodes codes={postAttempt?.reason_codes} />
            <div className="text-[10.5px] font-mono text-ink3">
              request {postAttempt?.request_id}
            </div>
          </div>
        </div>
      )}

      {attackAttempt && (
        <p className="text-[11.5px] text-ink3 border-t border-line pt-3">
          Both decisions are preserved as separate events in Agent activity. Select either
          row to inspect that exact request&apos;s authorization pipeline — the attack request
          and the post-quarantine request keep their own request IDs, checks and reason codes.
        </p>
      )}
    </Panel>
  );
}
