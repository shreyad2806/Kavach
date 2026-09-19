import { useCallback, useEffect, useRef, useState } from "react";
import { api } from "../api";

/**
 * Tracks ONE workflow.
 *
 * While the workflow is live we poll `GET /workflows/:id` only — a single
 * request that returns status, events, agents and result together. We never
 * poll /events, /agents, /dashboard and /incidents concurrently.
 *
 * Polling stops as soon as the workflow reaches a terminal state, so a
 * finished demo cannot be throttled.
 */

const POLL_MS = 700;
const TERMINAL = new Set(["COMPLETED", "FAILED", "STOPPED"]);

// `status` values that mean "the workflow has no more work to do".
export function isTerminal(status) {
  return TERMINAL.has(status);
}

export function useKavach() {
  const [workflowId, setWorkflowId] = useState(null);
  const [snapshot, setSnapshot] = useState(null);
  const [error, setError] = useState(null);

  const timerRef = useRef(null);
  // Monotonic generation: bumping it invalidates every in-flight poll loop, so
  // untracking (or tracking a different workflow) can never leave a stale loop
  // writing into state.
  const genRef = useRef(0);

  const clearTimer = useCallback(() => {
    if (timerRef.current) {
      clearTimeout(timerRef.current);
      timerRef.current = null;
    }
  }, []);

  const untrack = useCallback(() => {
    genRef.current += 1;
    clearTimer();
    setWorkflowId(null);
    setSnapshot(null);
    setError(null);
  }, [clearTimer]);

  const track = useCallback(
    (id) => {
      genRef.current += 1;
      const gen = genRef.current;
      clearTimer();
      setWorkflowId(id);
      setSnapshot(null);
      setError(null);

      const loop = async () => {
        if (gen !== genRef.current) return;

        let data = null;
        try {
          data = await api.getWorkflow(id);
        } catch (err) {
          if (gen !== genRef.current) return;
          // The workflow no longer exists (the session was reset) — stop
          // quietly rather than surfacing a scary error.
          if (err.kind === "not_found") return;
          setError({ kind: err.kind, message: err.message });
        }

        if (gen !== genRef.current) return;
        if (data) {
          setSnapshot(data);
          setError(null);
        }

        // Keep polling through a transient error so a rate limit self-heals.
        if (!data || !TERMINAL.has(data.status)) {
          timerRef.current = setTimeout(loop, POLL_MS);
        }
      };

      loop();
    },
    [clearTimer],
  );

  // One immediate re-fetch (used after stop/attack to refresh state now).
  const refresh = useCallback(async () => {
    if (!workflowId) return null;
    try {
      const data = await api.getWorkflow(workflowId);
      setSnapshot(data);
      setError(null);
      return data;
    } catch (err) {
      if (err.kind !== "not_found") setError({ kind: err.kind, message: err.message });
      return null;
    }
  }, [workflowId]);

  useEffect(() => () => clearTimer(), [clearTimer]);

  return { workflowId, snapshot, error, track, untrack, refresh };
}
